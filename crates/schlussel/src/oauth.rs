use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use reqwest::blocking::{Client, Response};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

use crate::callback::{build_authorization_url, open_browser, CallbackServer};
use crate::error::{Result, SchlusselError};
use crate::formulas::Formula;
use crate::lock::RefreshLockManager;
use crate::pkce::PkcePair;
use crate::session::{MemoryStorage, SessionStorage, Token};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct OAuthConfig {
    pub client_id: String,
    #[serde(default)]
    pub client_secret: Option<String>,
    pub authorization_endpoint: String,
    pub token_endpoint: String,
    pub redirect_uri: String,
    #[serde(default)]
    pub scope: Option<String>,
    #[serde(default)]
    pub device_authorization_endpoint: Option<String>,
}

impl OAuthConfig {
    pub fn github(client_id: impl Into<String>, scope: Option<String>) -> Self {
        Self {
            client_id: client_id.into(),
            client_secret: None,
            authorization_endpoint: "https://github.com/login/oauth/authorize".to_string(),
            token_endpoint: "https://github.com/login/oauth/access_token".to_string(),
            redirect_uri: "http://127.0.0.1/callback".to_string(),
            scope,
            device_authorization_endpoint: Some("https://github.com/login/device/code".to_string()),
        }
    }

    pub fn google(client_id: impl Into<String>, scope: Option<String>) -> Self {
        Self {
            client_id: client_id.into(),
            client_secret: None,
            authorization_endpoint: "https://accounts.google.com/o/oauth2/v2/auth".to_string(),
            token_endpoint: "https://oauth2.googleapis.com/token".to_string(),
            redirect_uri: "http://127.0.0.1/callback".to_string(),
            scope,
            device_authorization_endpoint: Some(
                "https://oauth2.googleapis.com/device/code".to_string(),
            ),
        }
    }

    pub fn microsoft(
        client_id: impl Into<String>,
        tenant: impl Into<String>,
        scope: Option<String>,
    ) -> Self {
        let tenant = tenant.into();
        let tenant = match tenant.as_str() {
            "common" | "organizations" | "consumers" => tenant,
            _ => "common".to_string(),
        };
        let base = format!("https://login.microsoftonline.com/{tenant}/oauth2/v2.0");

        Self {
            client_id: client_id.into(),
            client_secret: None,
            authorization_endpoint: format!("{base}/authorize"),
            token_endpoint: format!("{base}/token"),
            redirect_uri: "http://127.0.0.1/callback".to_string(),
            scope,
            device_authorization_endpoint: Some(format!("{base}/devicecode")),
        }
    }

    pub fn gitlab(client_id: impl Into<String>, scope: Option<String>) -> Self {
        Self {
            client_id: client_id.into(),
            client_secret: None,
            authorization_endpoint: "https://gitlab.com/oauth/authorize".to_string(),
            token_endpoint: "https://gitlab.com/oauth/token".to_string(),
            redirect_uri: "http://127.0.0.1/callback".to_string(),
            scope,
            device_authorization_endpoint: None,
        }
    }

    pub fn tuist(client_id: impl Into<String>, scope: Option<String>) -> Self {
        Self {
            client_id: client_id.into(),
            client_secret: None,
            authorization_endpoint: "https://cloud.tuist.io/oauth/authorize".to_string(),
            token_endpoint: "https://cloud.tuist.io/oauth/token".to_string(),
            redirect_uri: "http://127.0.0.1/callback".to_string(),
            scope,
            device_authorization_endpoint: Some(
                "https://cloud.tuist.io/oauth/device/code".to_string(),
            ),
        }
    }

    pub fn validate(&self) -> Result<()> {
        validate_endpoint_security(&self.authorization_endpoint)?;
        validate_endpoint_security(&self.token_endpoint)?;
        if let Some(endpoint) = &self.device_authorization_endpoint {
            validate_endpoint_security(endpoint)?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DeviceAuthorizationResponse {
    pub device_code: String,
    pub user_code: String,
    pub verification_uri: String,
    #[serde(default)]
    pub verification_uri_complete: Option<String>,
    pub expires_in: u64,
    pub interval: u64,
}

pub fn config_from_formula(
    formula: &Formula,
    method_name: &str,
    client_id_override: Option<&str>,
    client_secret_override: Option<&str>,
    redirect_uri: &str,
    scope_override: Option<&str>,
) -> Result<OAuthConfig> {
    let method = formula
        .get_method(method_name)
        .ok_or_else(|| SchlusselError::MethodNotFound(method_name.to_string()))?;
    let endpoints = method
        .endpoints
        .as_ref()
        .ok_or_else(|| SchlusselError::MissingEndpoint(method_name.to_string()))?;

    let token_endpoint = endpoints
        .token
        .clone()
        .ok_or_else(|| SchlusselError::MissingEndpoint(format!("{method_name}.token")))?;
    let authorization_endpoint = endpoints
        .authorize
        .clone()
        .or_else(|| endpoints.device.clone())
        .ok_or_else(|| SchlusselError::MissingEndpoint(format!("{method_name}.authorize")))?;

    let mut client_secret = client_secret_override.map(ToString::to_string);
    let client_id = if let Some(client_id) = client_id_override {
        client_id.to_string()
    } else if let Some(client) = formula.get_default_client_for_method(method_name) {
        if client_secret.is_none() {
            client_secret = client.secret.clone();
        }
        client.id.clone()
    } else {
        return Err(SchlusselError::MissingClientId);
    };

    let config = OAuthConfig {
        client_id,
        client_secret,
        authorization_endpoint,
        token_endpoint,
        redirect_uri: redirect_uri.to_string(),
        scope: scope_override
            .map(ToString::to_string)
            .or_else(|| method.scope.clone()),
        device_authorization_endpoint: endpoints.device.clone(),
    };
    config.validate()?;
    Ok(config)
}

pub fn validate_endpoint_security(endpoint: &str) -> Result<()> {
    if endpoint.starts_with("https://")
        || endpoint.starts_with("http://localhost")
        || endpoint.starts_with("http://127.0.0.1")
        || endpoint.starts_with("http://[::1]")
    {
        Ok(())
    } else {
        Err(SchlusselError::InsecureEndpoint(endpoint.to_string()))
    }
}

#[derive(Debug, Clone)]
pub struct OAuthClient<S: SessionStorage> {
    config: OAuthConfig,
    storage: S,
    http: Client,
}

impl<S: SessionStorage> OAuthClient<S> {
    pub fn new(config: OAuthConfig, storage: S) -> Result<Self> {
        config.validate()?;
        let http = Client::builder().build()?;
        Ok(Self {
            config,
            storage,
            http,
        })
    }

    pub fn config(&self) -> &OAuthConfig {
        &self.config
    }

    pub fn authorize_device(&self, open_browser_after_prompt: bool) -> Result<Token> {
        let device = self.request_device_code()?;

        eprintln!();
        eprintln!("To authorize, visit: {}", device.verification_uri);
        eprintln!("And enter code: {}", device.user_code);
        eprintln!();

        if open_browser_after_prompt {
            if let Some(verification_uri_complete) = &device.verification_uri_complete {
                let _ = open_browser(verification_uri_complete);
            } else {
                let _ = open_browser(&device.verification_uri);
            }
        }

        self.poll_device_code(
            &device.device_code,
            device.interval,
            Some(device.expires_in),
        )
    }

    pub fn request_device_code(&self) -> Result<DeviceAuthorizationResponse> {
        let endpoint = self
            .config
            .device_authorization_endpoint
            .as_deref()
            .ok_or_else(|| {
                SchlusselError::UnsupportedOperation(
                    "device code flow is not supported by this configuration".to_string(),
                )
            })?;

        let mut form = vec![("client_id".to_string(), self.config.client_id.clone())];
        if let Some(scope) = &self.config.scope {
            form.push(("scope".to_string(), scope.clone()));
        }

        let response = self
            .http
            .post(endpoint)
            .header("Accept", "application/json")
            .form(&form)
            .send()?;

        parse_oauth_response(response)
    }

    pub fn poll_device_code(
        &self,
        device_code: &str,
        poll_interval: u64,
        expires_in: Option<u64>,
    ) -> Result<Token> {
        let ttl = expires_in.unwrap_or(900);
        let started_at = current_unix_timestamp();
        let mut interval = poll_interval.max(5);

        loop {
            if current_unix_timestamp().saturating_sub(started_at) >= ttl {
                return Err(SchlusselError::DeviceCodeExpired);
            }

            thread::sleep(Duration::from_secs(interval));

            let form = vec![
                (
                    "grant_type".to_string(),
                    "urn:ietf:params:oauth:grant-type:device_code".to_string(),
                ),
                ("device_code".to_string(), device_code.to_string()),
                ("client_id".to_string(), self.config.client_id.clone()),
            ];

            let response = self
                .http
                .post(&self.config.token_endpoint)
                .header("Accept", "application/json")
                .form(&form)
                .send()?;

            let status = response.status().as_u16();
            let body = response.text()?;

            if let Some(error_payload) = parse_body::<OAuthErrorPayload>(&body).ok() {
                match error_payload.error.as_str() {
                    "authorization_pending" => continue,
                    "slow_down" => {
                        interval += 5;
                        continue;
                    }
                    "access_denied" => return Err(SchlusselError::AuthorizationDenied),
                    "expired_token" => return Err(SchlusselError::DeviceCodeExpired),
                    _ if status >= 400 => {
                        return Err(SchlusselError::server(
                            Some(status),
                            Some(error_payload.error),
                            error_payload.error_description,
                        ));
                    }
                    _ => {}
                }
            }

            if status >= 400 {
                return Err(parse_server_error(status, &body));
            }

            let payload: RawTokenResponse = parse_body(&body)?;
            return Ok(payload.into_token());
        }
    }

    pub fn authorize(&self, open_browser_after_prompt: bool) -> Result<Token> {
        let pkce = PkcePair::generate();
        let state = random_state();
        let server = CallbackServer::new(0)?;
        let callback_url = server.callback_url();
        let authorize_url = build_authorization_url(
            &self.config.authorization_endpoint,
            &self.config.client_id,
            &callback_url,
            self.config.scope.as_deref(),
            &state,
            pkce.challenge(),
        )?;

        if open_browser_after_prompt {
            eprintln!();
            eprintln!("Opening browser for authorization...");
            eprintln!("If the browser does not open, visit:");
            eprintln!("{authorize_url}");
            eprintln!();
            let _ = open_browser(&authorize_url);
        } else {
            eprintln!();
            eprintln!("Visit the following URL to authorize:");
            eprintln!("{authorize_url}");
            eprintln!();
        }

        let callback = server.wait_for_callback(120)?;
        if callback.state.as_deref() != Some(state.as_str()) {
            return Err(SchlusselError::InvalidState);
        }
        if callback.error_code.is_some() {
            return Err(SchlusselError::AuthorizationDenied);
        }
        let code = callback.code.ok_or_else(|| {
            SchlusselError::server(None, None, Some("missing authorization code".to_string()))
        })?;

        self.exchange_code(&code, pkce.verifier(), &callback_url)
    }

    pub fn exchange_code(&self, code: &str, verifier: &str, redirect_uri: &str) -> Result<Token> {
        let mut form = vec![
            ("grant_type".to_string(), "authorization_code".to_string()),
            ("code".to_string(), code.to_string()),
            ("redirect_uri".to_string(), redirect_uri.to_string()),
            ("client_id".to_string(), self.config.client_id.clone()),
            ("code_verifier".to_string(), verifier.to_string()),
        ];
        if let Some(client_secret) = &self.config.client_secret {
            form.push(("client_secret".to_string(), client_secret.clone()));
        }

        let response = self
            .http
            .post(&self.config.token_endpoint)
            .header("Accept", "application/json")
            .form(&form)
            .send()?;

        parse_oauth_response::<RawTokenResponse>(response).map(RawTokenResponse::into_token)
    }

    pub fn refresh_token(&self, refresh_token: &str) -> Result<Token> {
        let mut form = vec![
            ("grant_type".to_string(), "refresh_token".to_string()),
            ("refresh_token".to_string(), refresh_token.to_string()),
            ("client_id".to_string(), self.config.client_id.clone()),
        ];
        if let Some(client_secret) = &self.config.client_secret {
            form.push(("client_secret".to_string(), client_secret.clone()));
        }

        let response = self
            .http
            .post(&self.config.token_endpoint)
            .header("Accept", "application/json")
            .form(&form)
            .send()?;

        parse_oauth_response::<RawTokenResponse>(response).map(RawTokenResponse::into_token)
    }

    pub fn save_token(&self, key: &str, token: &Token) -> Result<()> {
        self.storage.save(key, token)
    }

    pub fn get_token(&self, key: &str) -> Result<Option<Token>> {
        self.storage.load(key)
    }

    pub fn delete_token(&self, key: &str) -> Result<()> {
        self.storage.delete(key)
    }
}

#[derive(Debug, Clone)]
pub struct TokenRefresher<S: SessionStorage> {
    client: OAuthClient<S>,
    lock_manager: Option<RefreshLockManager>,
    refresh_threshold: f64,
}

impl<S: SessionStorage> TokenRefresher<S> {
    pub fn new(client: OAuthClient<S>) -> Self {
        Self {
            client,
            lock_manager: None,
            refresh_threshold: 0.1,
        }
    }

    pub fn with_file_locking(mut self, app_name: &str) -> Result<Self> {
        self.lock_manager = Some(RefreshLockManager::new(app_name)?);
        Ok(self)
    }

    pub fn with_refresh_threshold(mut self, threshold: f64) -> Self {
        self.refresh_threshold = threshold;
        self
    }

    pub fn get_valid_token(&self, key: &str) -> Result<Token> {
        self.get_valid_token_with_threshold(key, self.refresh_threshold)
    }

    pub fn get_valid_token_with_threshold(&self, key: &str, threshold: f64) -> Result<Token> {
        let mut token = self
            .client
            .get_token(key)?
            .ok_or_else(|| SchlusselError::TokenNotFound(key.to_string()))?;

        let needs_refresh = token.is_expired()
            || token
                .remaining_lifetime_fraction()
                .is_some_and(|fraction| fraction <= threshold);
        if !needs_refresh {
            return Ok(token);
        }

        let refresh_token = token
            .refresh_token
            .clone()
            .ok_or(SchlusselError::NoRefreshToken)?;

        let mut lock = if let Some(lock_manager) = &self.lock_manager {
            Some(lock_manager.acquire(key)?)
        } else {
            None
        };

        if lock.is_some() {
            token = self
                .client
                .get_token(key)?
                .ok_or_else(|| SchlusselError::TokenNotFound(key.to_string()))?;
            let still_needs_refresh = token.is_expired()
                || token
                    .remaining_lifetime_fraction()
                    .is_some_and(|fraction| fraction <= threshold);
            if !still_needs_refresh {
                return Ok(token);
            }
        }

        let mut new_token = self.client.refresh_token(&refresh_token)?;
        if new_token.refresh_token.is_none() {
            new_token.refresh_token = Some(refresh_token);
        }
        self.client.save_token(key, &new_token)?;
        if let Some(lock) = &mut lock {
            lock.release()?;
        }
        Ok(new_token)
    }
}

#[derive(Debug, Deserialize)]
struct OAuthErrorPayload {
    error: String,
    #[serde(default)]
    error_description: Option<String>,
}

#[derive(Debug, Deserialize)]
struct RawTokenResponse {
    access_token: String,
    token_type: String,
    #[serde(default)]
    refresh_token: Option<String>,
    #[serde(default)]
    expires_in: Option<u64>,
    #[serde(default)]
    expires_at: Option<u64>,
    #[serde(default)]
    scope: Option<String>,
    #[serde(default)]
    id_token: Option<String>,
}

impl RawTokenResponse {
    fn into_token(self) -> Token {
        let expires_at = self
            .expires_at
            .or_else(|| self.expires_in.map(|ttl| current_unix_timestamp() + ttl));
        Token {
            access_token: self.access_token,
            token_type: self.token_type,
            refresh_token: self.refresh_token,
            expires_in: self.expires_in,
            expires_at,
            scope: self.scope,
            id_token: self.id_token,
        }
    }
}

fn parse_oauth_response<T: DeserializeOwned>(response: Response) -> Result<T> {
    let status = response.status().as_u16();
    let body = response.text()?;
    if status >= 400 {
        return Err(parse_server_error(status, &body));
    }
    parse_body(&body)
}

fn parse_body<T: DeserializeOwned>(body: &str) -> Result<T> {
    serde_json::from_str(body).or_else(|_| {
        serde_urlencoded::from_str(body).map_err(|error| SchlusselError::Json(error.to_string()))
    })
}

fn parse_server_error(status: u16, body: &str) -> SchlusselError {
    if let Ok(payload) = parse_body::<OAuthErrorPayload>(body) {
        map_oauth_error(payload, Some(status))
    } else {
        SchlusselError::server(Some(status), None, Some(body.to_string()))
    }
}

fn map_oauth_error(payload: OAuthErrorPayload, status: Option<u16>) -> SchlusselError {
    match payload.error.as_str() {
        "authorization_pending" => SchlusselError::AuthorizationPending,
        "slow_down" => SchlusselError::SlowDown,
        "access_denied" => SchlusselError::AuthorizationDenied,
        "expired_token" => SchlusselError::DeviceCodeExpired,
        _ => SchlusselError::server(status, Some(payload.error), payload.error_description),
    }
}

fn current_unix_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn random_state() -> String {
    PkcePair::generate().verifier()[..22].to_string()
}

pub fn build_memory_oauth_client(config: OAuthConfig) -> Result<OAuthClient<MemoryStorage>> {
    OAuthClient::new(config, MemoryStorage::new())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::formulas::load_from_json_slice;

    #[test]
    fn config_from_formula_uses_public_client() {
        let formula = load_from_json_slice(
            br#"{
              "schema": "v2",
              "id": "github",
              "label": "GitHub",
              "clients": [{ "name": "gh", "id": "client-id", "methods": ["device_code"] }],
              "methods": {
                "device_code": {
                  "endpoints": {
                    "device": "https://github.com/login/device/code",
                    "token": "https://github.com/login/oauth/access_token"
                  }
                }
              }
            }"#,
        )
        .expect("formula");

        let config = config_from_formula(
            &formula,
            "device_code",
            None,
            None,
            "http://127.0.0.1/callback",
            None,
        )
        .expect("config");
        assert_eq!(config.client_id, "client-id");
    }

    #[test]
    fn config_from_formula_requires_client_id() {
        let formula = load_from_json_slice(
            br#"{
              "schema": "v2",
              "id": "example",
              "label": "Example",
              "methods": {
                "oauth": {
                  "endpoints": {
                    "authorize": "https://example.com/authorize",
                    "token": "https://example.com/token"
                  }
                }
              }
            }"#,
        )
        .expect("formula");

        let error = config_from_formula(
            &formula,
            "oauth",
            None,
            None,
            "http://127.0.0.1/callback",
            None,
        )
        .expect_err("client id");
        assert!(matches!(error, SchlusselError::MissingClientId));
    }
}
