use std::io;

use thiserror::Error;

pub type Result<T> = std::result::Result<T, SchlusselError>;

#[derive(Debug, Error)]
pub enum SchlusselError {
    #[error("invalid parameter: {0}")]
    InvalidParameter(String),
    #[error("storage error: {0}")]
    Storage(String),
    #[error("http error: {0}")]
    Http(String),
    #[error("authorization denied")]
    AuthorizationDenied,
    #[error("token expired")]
    TokenExpired,
    #[error("no refresh token available")]
    NoRefreshToken,
    #[error("invalid OAuth state")]
    InvalidState,
    #[error("device code expired")]
    DeviceCodeExpired,
    #[error("authorization pending")]
    AuthorizationPending,
    #[error("slow down")]
    SlowDown,
    #[error("JSON error: {0}")]
    Json(String),
    #[error("I/O error: {0}")]
    Io(String),
    #[error("server error")]
    Server {
        code: Option<String>,
        description: Option<String>,
        status: Option<u16>,
    },
    #[error("callback server error: {0}")]
    CallbackServer(String),
    #[error("configuration error: {0}")]
    Configuration(String),
    #[error("lock error: {0}")]
    Lock(String),
    #[error("unsupported operation: {0}")]
    UnsupportedOperation(String),
    #[error("insecure endpoint: {0}")]
    InsecureEndpoint(String),
    #[error("missing client id")]
    MissingClientId,
    #[error("missing endpoint: {0}")]
    MissingEndpoint(String),
    #[error("unknown method: {0}")]
    MethodNotFound(String),
    #[error("unknown formula: {0}")]
    FormulaNotFound(String),
    #[error("token not found: {0}")]
    TokenNotFound(String),
    #[error("request timed out")]
    Timeout,
}

impl SchlusselError {
    pub fn invalid_parameter(message: impl Into<String>) -> Self {
        Self::InvalidParameter(message.into())
    }

    pub fn storage(message: impl Into<String>) -> Self {
        Self::Storage(message.into())
    }

    pub fn configuration(message: impl Into<String>) -> Self {
        Self::Configuration(message.into())
    }

    pub fn callback_server(message: impl Into<String>) -> Self {
        Self::CallbackServer(message.into())
    }

    pub fn http(message: impl Into<String>) -> Self {
        Self::Http(message.into())
    }

    pub fn server(status: Option<u16>, code: Option<String>, description: Option<String>) -> Self {
        Self::Server {
            code,
            description,
            status,
        }
    }
}

impl From<io::Error> for SchlusselError {
    fn from(error: io::Error) -> Self {
        Self::Io(error.to_string())
    }
}

impl From<reqwest::Error> for SchlusselError {
    fn from(error: reqwest::Error) -> Self {
        if error.is_timeout() {
            Self::Timeout
        } else {
            Self::Http(error.to_string())
        }
    }
}

impl From<serde_json::Error> for SchlusselError {
    fn from(error: serde_json::Error) -> Self {
        Self::Json(error.to_string())
    }
}

impl From<url::ParseError> for SchlusselError {
    fn from(error: url::ParseError) -> Self {
        Self::InvalidParameter(error.to_string())
    }
}

impl From<keyring::Error> for SchlusselError {
    fn from(error: keyring::Error) -> Self {
        Self::Storage(error.to_string())
    }
}
