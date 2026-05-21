use reqwest::blocking::Client;
use reqwest::Method;
use serde::{Deserialize, Serialize};

use crate::error::{Result, SchlusselError};
use crate::oauth::validate_endpoint_security;

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct ClientMetadata {
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub client_name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_uri: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub logo_uri: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub redirect_uris: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub grant_types: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub response_types: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub contacts: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tos_uri: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy_uri: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jwks_uri: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jwks: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token_endpoint_auth_method: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token_endpoint_auth_signing_alg: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id_token_signed_response_alg: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id_token_encrypted_response_alg: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id_token_encrypted_response_enc: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub userinfo_signed_response_alg: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub userinfo_encrypted_response_alg: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub userinfo_encrypted_response_enc: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request_object_signing_alg: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request_object_encryption_alg: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request_object_encryption_enc: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default_max_age: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub require_auth_time: Option<bool>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub default_acr_values: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub initiate_login_uri: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub request_uris: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub frontchannel_logout_uri: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub frontchannel_logout_session_required: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub backchannel_logout_uri: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub backchannel_logout_session_required: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ClientRegistrationResponse {
    pub client_id: String,
    #[serde(default)]
    pub client_secret: Option<String>,
    #[serde(default)]
    pub client_id_issued_at: Option<i64>,
    #[serde(default)]
    pub client_secret_expires_at: Option<i64>,
    #[serde(default)]
    pub registration_access_token: Option<String>,
    #[serde(default)]
    pub registration_client_uri: Option<String>,
}

#[derive(Debug, Clone)]
pub struct DynamicRegistrationClient {
    endpoint: String,
    http: Client,
}

impl DynamicRegistrationClient {
    pub fn new(endpoint: impl Into<String>) -> Result<Self> {
        let endpoint = endpoint.into();
        validate_endpoint_security(&endpoint)?;
        Ok(Self {
            endpoint,
            http: Client::builder().build()?,
        })
    }

    pub fn register(&self, metadata: &ClientMetadata) -> Result<ClientRegistrationResponse> {
        self.send(Method::POST, &self.endpoint, None, Some(metadata))
    }

    pub fn read(&self, registration_access_token: &str) -> Result<ClientRegistrationResponse> {
        self.send::<()>(
            Method::GET,
            &self.endpoint,
            Some(registration_access_token),
            None,
        )
    }

    pub fn update(
        &self,
        registration_access_token: &str,
        metadata: &ClientMetadata,
    ) -> Result<ClientRegistrationResponse> {
        self.send(
            Method::PUT,
            &self.endpoint,
            Some(registration_access_token),
            Some(metadata),
        )
    }

    pub fn delete(&self, registration_access_token: &str) -> Result<()> {
        let request = self
            .http
            .request(Method::DELETE, &self.endpoint)
            .header("Accept", "application/json")
            .bearer_auth(registration_access_token);
        let response = request.send()?;
        if response.status().is_success() {
            Ok(())
        } else {
            Err(parse_server_error(
                response.status().as_u16(),
                response.text().ok(),
            ))
        }
    }

    fn send<T: Serialize>(
        &self,
        method: Method,
        endpoint: &str,
        registration_access_token: Option<&str>,
        payload: Option<&T>,
    ) -> Result<ClientRegistrationResponse> {
        let mut request = self
            .http
            .request(method, endpoint)
            .header("Accept", "application/json");

        if let Some(token) = registration_access_token {
            request = request.bearer_auth(token);
        }

        if let Some(payload) = payload {
            request = request.json(payload);
        }

        let response = request.send()?;
        let status = response.status();
        let body = response.text()?;
        if !status.is_success() {
            return Err(parse_server_error(status.as_u16(), Some(body)));
        }
        serde_json::from_str(&body).map_err(Into::into)
    }
}

fn parse_server_error(status: u16, body: Option<String>) -> SchlusselError {
    body.as_deref()
        .and_then(|body| serde_json::from_str::<serde_json::Value>(body).ok())
        .map_or_else(
            || SchlusselError::server(Some(status), None, body),
            |value| {
                SchlusselError::server(
                    Some(status),
                    value
                        .get("error")
                        .and_then(serde_json::Value::as_str)
                        .map(ToString::to_string),
                    value
                        .get("error_description")
                        .or_else(|| value.get("message"))
                        .and_then(serde_json::Value::as_str)
                        .map(ToString::to_string),
                )
            },
        )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn metadata_serialization_omits_empty_optional_fields() {
        let metadata = ClientMetadata {
            client_name: "schlussel".to_string(),
            redirect_uris: vec!["http://127.0.0.1/callback".to_string()],
            ..ClientMetadata::default()
        };

        let json = serde_json::to_string(&metadata).expect("json");
        assert!(json.contains("redirect_uris"));
        assert!(!json.contains("logo_uri"));
    }

    #[test]
    fn registration_endpoint_requires_secure_transport() {
        let error = DynamicRegistrationClient::new("http://example.com/register")
            .expect_err("should reject insecure endpoint");
        assert!(matches!(error, SchlusselError::InsecureEndpoint(_)));
    }
}
