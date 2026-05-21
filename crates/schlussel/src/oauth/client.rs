use std::borrow::Cow;
use std::thread;
use std::time::Duration;

use reqwest::blocking::{Client as HttpClient, Response};

use crate::callback::{build_authorization_url, open_browser, CallbackServer};
use crate::error::{Result, SchlusselError};
use crate::session::{MemoryStorage, SessionStorage, Token};

use super::config::{DeviceAuthorizationResponse, OAuthConfig};
use super::protocol::{
    parse_device_poll_response, parse_oauth_response, DevicePollState, RawTokenResponse,
};
use super::util::{current_unix_timestamp, random_state};

type FormField<'a> = (&'static str, Cow<'a, str>);

#[derive(Debug, Clone)]
pub struct OAuthClient<S: SessionStorage> {
    config: OAuthConfig,
    storage: S,
    http: HttpClient,
}

impl<S: SessionStorage> OAuthClient<S> {
    pub fn new(config: OAuthConfig, storage: S) -> Result<Self> {
        config.validate()?;
        let http = HttpClient::builder().build()?;
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
            let preferred = device
                .verification_uri_complete
                .as_deref()
                .unwrap_or(device.verification_uri.as_str());
            let _ = open_browser(preferred);
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

        let form = self.request_device_form();
        parse_oauth_response(self.send_form_request(endpoint, &form)?)
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

            let form = self.device_poll_form(device_code);
            let response = self.send_form_request(&self.config.token_endpoint, &form)?;
            let status = response.status().as_u16();
            let body = response.text()?;

            match parse_device_poll_response(status, &body)? {
                DevicePollState::Pending => continue,
                DevicePollState::SlowDown => {
                    interval += 5;
                    continue;
                }
                DevicePollState::Complete(token) => return Ok(token),
            }
        }
    }

    pub fn authorize(&self, open_browser_after_prompt: bool) -> Result<Token> {
        let pkce = crate::pkce::PkcePair::generate();
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

        eprintln!();
        if open_browser_after_prompt {
            eprintln!("Opening browser for authorization...");
            eprintln!("If the browser does not open, visit:");
            let _ = open_browser(&authorize_url);
        } else {
            eprintln!("Visit the following URL to authorize:");
        }
        eprintln!("{authorize_url}");
        eprintln!();

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
        self.token_response(self.authorization_code_form(code, verifier, redirect_uri))
    }

    pub fn refresh_token(&self, refresh_token: &str) -> Result<Token> {
        self.token_response(self.refresh_token_form(refresh_token))
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

    fn request_device_form(&self) -> Vec<FormField<'_>> {
        let mut form = vec![self.client_id_field()];
        form.extend(self.scope_field());
        form
    }

    fn device_poll_form<'a>(&'a self, device_code: &'a str) -> Vec<FormField<'a>> {
        vec![
            (
                "grant_type",
                Cow::Borrowed("urn:ietf:params:oauth:grant-type:device_code"),
            ),
            ("device_code", Cow::Borrowed(device_code)),
            self.client_id_field(),
        ]
    }

    fn authorization_code_form<'a>(
        &'a self,
        code: &'a str,
        verifier: &'a str,
        redirect_uri: &'a str,
    ) -> Vec<FormField<'a>> {
        let mut form = vec![
            ("grant_type", Cow::Borrowed("authorization_code")),
            ("code", Cow::Borrowed(code)),
            ("redirect_uri", Cow::Borrowed(redirect_uri)),
            self.client_id_field(),
            ("code_verifier", Cow::Borrowed(verifier)),
        ];
        form.extend(self.client_secret_field());
        form
    }

    fn refresh_token_form<'a>(&'a self, refresh_token: &'a str) -> Vec<FormField<'a>> {
        let mut form = vec![
            ("grant_type", Cow::Borrowed("refresh_token")),
            ("refresh_token", Cow::Borrowed(refresh_token)),
            self.client_id_field(),
        ];
        form.extend(self.client_secret_field());
        form
    }

    fn token_response(&self, form: Vec<FormField<'_>>) -> Result<Token> {
        parse_oauth_response::<RawTokenResponse>(
            self.send_form_request(&self.config.token_endpoint, &form)?,
        )
        .map(RawTokenResponse::into_token)
    }

    fn send_form_request(&self, endpoint: &str, form: &[FormField<'_>]) -> Result<Response> {
        self.http
            .post(endpoint)
            .header("Accept", "application/json")
            .form(form)
            .send()
            .map_err(Into::into)
    }

    fn client_id_field(&self) -> FormField<'_> {
        ("client_id", Cow::Borrowed(self.config.client_id.as_str()))
    }

    fn client_secret_field(&self) -> Option<FormField<'_>> {
        self.config
            .client_secret
            .as_deref()
            .map(|secret| ("client_secret", Cow::Borrowed(secret)))
    }

    fn scope_field(&self) -> Option<FormField<'_>> {
        self.config
            .scope
            .as_deref()
            .map(|scope| ("scope", Cow::Borrowed(scope)))
    }
}

pub fn build_memory_oauth_client(config: OAuthConfig) -> Result<OAuthClient<MemoryStorage>> {
    OAuthClient::new(config, MemoryStorage::new())
}

#[cfg(test)]
mod tests {
    use super::super::test_support::{oauth_config, OneShotServer};
    use super::*;

    #[test]
    fn request_device_code_requires_supported_endpoint() {
        let client =
            build_memory_oauth_client(oauth_config("https://example.com/token")).expect("client");
        let error = client
            .request_device_code()
            .expect_err("device flow should be unsupported");

        assert!(matches!(error, SchlusselError::UnsupportedOperation(_)));
    }

    #[test]
    fn request_device_code_parses_urlencoded_response() {
        let server = OneShotServer::respond(
            200,
            "application/x-www-form-urlencoded",
            "device_code=device-1&user_code=USER-1&verification_uri=https%3A%2F%2Fexample.com%2Fverify&verification_uri_complete=https%3A%2F%2Fexample.com%2Fverify%3Fcode%3DUSER-1&expires_in=600&interval=5",
        );
        let mut config = oauth_config(server.endpoint("/token"));
        config.device_authorization_endpoint = Some(server.endpoint("/device"));
        let client = build_memory_oauth_client(config).expect("client");

        let device = client.request_device_code().expect("device response");
        let request = server.next_request();

        assert_eq!(device.device_code, "device-1");
        assert_eq!(request.method, "POST");
        assert_eq!(request.path, "/device");
        assert!(request.body.contains("client_id=client-id"));
        assert!(
            request.body.contains("scope=repo+user") || request.body.contains("scope=repo%20user")
        );
    }

    #[test]
    fn refresh_token_includes_client_secret_and_returns_token() {
        let server = OneShotServer::respond(
            200,
            "application/json",
            r#"{
                "access_token": "access-2",
                "token_type": "Bearer",
                "refresh_token": "refresh-2",
                "expires_in": 3600
            }"#,
        );
        let client =
            build_memory_oauth_client(oauth_config(server.endpoint("/token"))).expect("client");

        let token = client.refresh_token("refresh-1").expect("refreshed token");
        let request = server.next_request();

        assert_eq!(token.access_token, "access-2");
        assert_eq!(request.path, "/token");
        assert!(request.body.contains("grant_type=refresh_token"));
        assert!(request.body.contains("refresh_token=refresh-1"));
        assert!(request.body.contains("client_secret=secret"));
    }

    #[test]
    fn storage_roundtrip_uses_underlying_session_storage() {
        let client =
            build_memory_oauth_client(oauth_config("https://example.com/token")).expect("client");
        let token = Token::new("access-1", "Bearer").with_expiration(Some(60));

        client
            .save_token("github:device_code", &token)
            .expect("save token");
        assert_eq!(
            client
                .get_token("github:device_code")
                .expect("load token")
                .expect("stored token"),
            token
        );

        client
            .delete_token("github:device_code")
            .expect("delete token");
        assert!(client
            .get_token("github:device_code")
            .expect("load deleted token")
            .is_none());
    }

    #[test]
    fn poll_device_code_expires_before_waiting_when_ttl_is_zero() {
        let client =
            build_memory_oauth_client(oauth_config("https://example.com/token")).expect("client");
        let error = client
            .poll_device_code("device-1", 1, Some(0))
            .expect_err("device code should expire immediately");

        assert!(matches!(error, SchlusselError::DeviceCodeExpired));
    }
}
