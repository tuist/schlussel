use reqwest::blocking::Response;
use serde::de::DeserializeOwned;
use serde::Deserialize;

use crate::error::{Result, SchlusselError};
use crate::session::Token;

use super::util::current_unix_timestamp;

#[derive(Debug, PartialEq, Eq)]
pub(super) enum DevicePollState {
    Pending,
    SlowDown,
    Complete(Token),
}

#[derive(Debug, Deserialize)]
struct OAuthErrorPayload {
    error: String,
    #[serde(default)]
    error_description: Option<String>,
}

#[derive(Debug, Deserialize)]
pub(super) struct RawTokenResponse {
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
    pub(super) fn into_token(self) -> Token {
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

pub(super) fn parse_oauth_response<T: DeserializeOwned>(response: Response) -> Result<T> {
    let status = response.status().as_u16();
    let body = response.text()?;
    if status >= 400 {
        return Err(parse_server_error(status, &body));
    }
    parse_body(&body)
}

pub(super) fn parse_body<T: DeserializeOwned>(body: &str) -> Result<T> {
    serde_json::from_str(body).or_else(|_| {
        serde_urlencoded::from_str(body).map_err(|error| SchlusselError::Json(error.to_string()))
    })
}

pub(super) fn parse_device_poll_response(status: u16, body: &str) -> Result<DevicePollState> {
    if let Ok(payload) = parse_body::<OAuthErrorPayload>(body) {
        return match payload.error.as_str() {
            "authorization_pending" => Ok(DevicePollState::Pending),
            "slow_down" => Ok(DevicePollState::SlowDown),
            _ if status >= 400 => Err(map_oauth_error(payload, Some(status))),
            _ => Ok(DevicePollState::Complete(
                parse_body::<RawTokenResponse>(body)?.into_token(),
            )),
        };
    }

    if status >= 400 {
        return Err(parse_server_error(status, body));
    }

    parse_body::<RawTokenResponse>(body)
        .map(RawTokenResponse::into_token)
        .map(DevicePollState::Complete)
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::oauth::DeviceAuthorizationResponse;

    #[test]
    fn parse_body_supports_json() {
        let payload: DeviceAuthorizationResponse = parse_body(
            r#"{
                "device_code": "device-1",
                "user_code": "USER-1",
                "verification_uri": "https://example.com/verify",
                "expires_in": 600,
                "interval": 5
            }"#,
        )
        .expect("JSON body");

        assert_eq!(payload.device_code, "device-1");
    }

    #[test]
    fn parse_body_supports_urlencoded_payloads() {
        let payload: DeviceAuthorizationResponse = parse_body(
            "device_code=device-1&user_code=USER-1&verification_uri=https%3A%2F%2Fexample.com%2Fverify&expires_in=600&interval=5",
        )
        .expect("urlencoded body");

        assert_eq!(payload.user_code, "USER-1");
    }

    #[test]
    fn parse_device_poll_response_maps_pending_states() {
        let pending = parse_device_poll_response(400, r#"{"error":"authorization_pending"}"#)
            .expect("pending");
        let slow_down =
            parse_device_poll_response(400, r#"{"error":"slow_down"}"#).expect("slow down");

        assert!(matches!(pending, DevicePollState::Pending));
        assert!(matches!(slow_down, DevicePollState::SlowDown));
    }

    #[test]
    fn parse_device_poll_response_returns_completed_token() {
        let result = parse_device_poll_response(
            200,
            r#"{
                "access_token": "access-1",
                "token_type": "Bearer",
                "refresh_token": "refresh-1",
                "expires_in": 60
            }"#,
        )
        .expect("completed token");

        match result {
            DevicePollState::Complete(token) => {
                assert_eq!(token.access_token, "access-1");
                assert_eq!(token.refresh_token.as_deref(), Some("refresh-1"));
            }
            other => panic!("expected complete token, got {other:?}"),
        }
    }

    #[test]
    fn parse_device_poll_response_maps_terminal_errors() {
        let denied =
            parse_device_poll_response(400, r#"{"error":"access_denied"}"#).expect_err("denied");
        let expired =
            parse_device_poll_response(400, r#"{"error":"expired_token"}"#).expect_err("expired");

        assert!(matches!(denied, SchlusselError::AuthorizationDenied));
        assert!(matches!(expired, SchlusselError::DeviceCodeExpired));
    }

    #[test]
    fn raw_token_response_infers_expires_at_when_missing() {
        let before = current_unix_timestamp();
        let payload: RawTokenResponse = parse_body(
            r#"{
                "access_token": "access-1",
                "token_type": "Bearer",
                "expires_in": 60
            }"#,
        )
        .expect("token payload");
        let token = payload.into_token();
        let after = current_unix_timestamp();

        let expires_at = token.expires_at.expect("expires_at");
        assert!(expires_at >= before + 60);
        assert!(expires_at <= after + 60);
    }
}
