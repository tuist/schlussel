use serde::{Deserialize, Serialize};

use crate::error::{Result, SchlusselError};
use crate::formulas::{Endpoints, Formula, MethodDef};

const LOOPBACK_REDIRECT_URI: &str = "http://127.0.0.1/callback";

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
        Self::public_client(
            client_id,
            "https://github.com/login/oauth/authorize",
            "https://github.com/login/oauth/access_token",
            scope,
            Some("https://github.com/login/device/code".to_string()),
        )
    }

    pub fn google(client_id: impl Into<String>, scope: Option<String>) -> Self {
        Self::public_client(
            client_id,
            "https://accounts.google.com/o/oauth2/v2/auth",
            "https://oauth2.googleapis.com/token",
            scope,
            Some("https://oauth2.googleapis.com/device/code".to_string()),
        )
    }

    pub fn microsoft(
        client_id: impl Into<String>,
        tenant: impl Into<String>,
        scope: Option<String>,
    ) -> Self {
        let tenant = normalize_microsoft_tenant(tenant.into());
        let base = format!("https://login.microsoftonline.com/{tenant}/oauth2/v2.0");

        Self::public_client(
            client_id,
            format!("{base}/authorize"),
            format!("{base}/token"),
            scope,
            Some(format!("{base}/devicecode")),
        )
    }

    pub fn gitlab(client_id: impl Into<String>, scope: Option<String>) -> Self {
        Self::public_client(
            client_id,
            "https://gitlab.com/oauth/authorize",
            "https://gitlab.com/oauth/token",
            scope,
            None,
        )
    }

    pub fn tuist(client_id: impl Into<String>, scope: Option<String>) -> Self {
        Self::public_client(
            client_id,
            "https://tuist.dev/oauth2/authorize",
            "https://tuist.dev/oauth2/token",
            scope,
            None,
        )
    }

    pub fn validate(&self) -> Result<()> {
        for endpoint in [
            Some(self.authorization_endpoint.as_str()),
            Some(self.token_endpoint.as_str()),
            self.device_authorization_endpoint.as_deref(),
        ]
        .into_iter()
        .flatten()
        {
            validate_endpoint_security(endpoint)?;
        }
        Ok(())
    }

    fn public_client(
        client_id: impl Into<String>,
        authorization_endpoint: impl Into<String>,
        token_endpoint: impl Into<String>,
        scope: Option<String>,
        device_authorization_endpoint: Option<String>,
    ) -> Self {
        Self {
            client_id: client_id.into(),
            client_secret: None,
            authorization_endpoint: authorization_endpoint.into(),
            token_endpoint: token_endpoint.into(),
            redirect_uri: LOOPBACK_REDIRECT_URI.to_string(),
            scope,
            device_authorization_endpoint,
        }
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
    let method = resolve_method(formula, method_name)?;
    let endpoints = resolve_endpoints(method, method_name)?;
    let (client_id, client_secret) = resolve_client_credentials(
        formula,
        method_name,
        client_id_override,
        client_secret_override,
    )?;

    let config = OAuthConfig {
        client_id,
        client_secret,
        authorization_endpoint: resolve_authorization_endpoint(endpoints, method_name)?,
        token_endpoint: resolve_token_endpoint(endpoints, method_name)?,
        redirect_uri: redirect_uri.to_string(),
        scope: scope_override
            .map(str::to_owned)
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

fn normalize_microsoft_tenant(tenant: String) -> String {
    match tenant.as_str() {
        "common" | "organizations" | "consumers" => tenant,
        _ => "common".to_string(),
    }
}

fn resolve_method<'a>(formula: &'a Formula, method_name: &str) -> Result<&'a MethodDef> {
    formula
        .get_method(method_name)
        .ok_or_else(|| SchlusselError::MethodNotFound(method_name.to_string()))
}

fn resolve_endpoints<'a>(method: &'a MethodDef, method_name: &str) -> Result<&'a Endpoints> {
    method
        .endpoints
        .as_ref()
        .ok_or_else(|| SchlusselError::MissingEndpoint(method_name.to_string()))
}

fn resolve_authorization_endpoint(endpoints: &Endpoints, method_name: &str) -> Result<String> {
    endpoints
        .authorize
        .clone()
        .or_else(|| endpoints.device.clone())
        .ok_or_else(|| SchlusselError::MissingEndpoint(format!("{method_name}.authorize")))
}

fn resolve_token_endpoint(endpoints: &Endpoints, method_name: &str) -> Result<String> {
    endpoints
        .token
        .clone()
        .ok_or_else(|| SchlusselError::MissingEndpoint(format!("{method_name}.token")))
}

fn resolve_client_credentials(
    formula: &Formula,
    method_name: &str,
    client_id_override: Option<&str>,
    client_secret_override: Option<&str>,
) -> Result<(String, Option<String>)> {
    let mut client_secret = client_secret_override.map(str::to_owned);

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

    Ok((client_id, client_secret))
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;
    use crate::formulas::load_from_json_slice;

    fn parse_formula(value: serde_json::Value) -> Formula {
        load_from_json_slice(&serde_json::to_vec(&value).expect("formula JSON")).expect("formula")
    }

    #[test]
    fn github_preset_uses_expected_endpoints() {
        let config = OAuthConfig::github("client-id", Some("repo".to_string()));

        assert_eq!(
            config.authorization_endpoint,
            "https://github.com/login/oauth/authorize"
        );
        assert_eq!(
            config.device_authorization_endpoint.as_deref(),
            Some("https://github.com/login/device/code")
        );
        assert_eq!(config.redirect_uri, LOOPBACK_REDIRECT_URI);
    }

    #[test]
    fn microsoft_preset_normalizes_unknown_tenants() {
        let config = OAuthConfig::microsoft("client-id", "custom-tenant", None);

        assert!(config
            .authorization_endpoint
            .starts_with("https://login.microsoftonline.com/common/"));
    }

    #[test]
    fn tuist_preset_matches_current_tuist_oauth_surface() {
        let config = OAuthConfig::tuist("client-id", Some("projects:read".to_string()));

        assert_eq!(
            config.authorization_endpoint,
            "https://tuist.dev/oauth2/authorize"
        );
        assert_eq!(config.token_endpoint, "https://tuist.dev/oauth2/token");
        assert_eq!(config.device_authorization_endpoint, None);
    }

    #[test]
    fn validate_endpoint_security_accepts_https_and_loopback() {
        assert!(validate_endpoint_security("https://example.com").is_ok());
        assert!(validate_endpoint_security("http://localhost/callback").is_ok());
        assert!(validate_endpoint_security("http://127.0.0.1/callback").is_ok());
        assert!(validate_endpoint_security("http://[::1]/callback").is_ok());
    }

    #[test]
    fn validate_endpoint_security_rejects_insecure_remote_endpoint() {
        let error =
            validate_endpoint_security("http://example.com/token").expect_err("insecure endpoint");
        assert!(matches!(
            error,
            SchlusselError::InsecureEndpoint(endpoint) if endpoint == "http://example.com/token"
        ));
    }

    #[test]
    fn config_from_formula_uses_public_client() {
        let formula = parse_formula(json!({
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
        }));

        let config = config_from_formula(
            &formula,
            "device_code",
            None,
            None,
            LOOPBACK_REDIRECT_URI,
            None,
        )
        .expect("config");

        assert_eq!(config.client_id, "client-id");
        assert_eq!(
            config.authorization_endpoint,
            "https://github.com/login/device/code"
        );
    }

    #[test]
    fn config_from_formula_prefers_overrides() {
        let formula = parse_formula(json!({
            "schema": "v2",
            "id": "example",
            "label": "Example",
            "clients": [{ "name": "default", "id": "from-formula", "secret": "formula-secret" }],
            "methods": {
                "authorization_code": {
                    "scope": "from-formula-scope",
                    "endpoints": {
                        "authorize": "https://example.com/authorize",
                        "token": "https://example.com/token"
                    }
                }
            }
        }));

        let config = config_from_formula(
            &formula,
            "authorization_code",
            Some("override-client"),
            Some("override-secret"),
            "http://127.0.0.1:3000/callback",
            Some("override-scope"),
        )
        .expect("config");

        assert_eq!(config.client_id, "override-client");
        assert_eq!(config.client_secret.as_deref(), Some("override-secret"));
        assert_eq!(config.scope.as_deref(), Some("override-scope"));
        assert_eq!(config.redirect_uri, "http://127.0.0.1:3000/callback");
    }

    #[test]
    fn config_from_formula_requires_client_id() {
        let formula = parse_formula(json!({
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
        }));

        let error = config_from_formula(&formula, "oauth", None, None, LOOPBACK_REDIRECT_URI, None)
            .expect_err("client id");

        assert!(matches!(error, SchlusselError::MissingClientId));
    }
}
