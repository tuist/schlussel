//! Schlussel is a formula-driven OAuth runtime for agents and CLI applications.
//!
//! It provides:
//! - PKCE utilities
//! - device code and authorization code OAuth flows
//! - token persistence backends
//! - cross-process refresh locking
//! - formula loading from bundled JSON documents

pub mod callback;
pub mod error;
pub mod formulas;
pub mod lock;
pub mod oauth;
pub mod pkce;
pub mod registration;
pub mod script;
pub mod session;

pub use callback::{CallbackResult, CallbackServer};
pub use error::{Result, SchlusselError};
pub use formulas::{
    ApiDef, Client, DynamicRegistrationDef, Endpoints, Formula, FormulaInfo, Identity, MethodDef,
    RegisterInstructions, ScriptStep,
};
pub use lock::{RefreshLock, RefreshLockManager};
pub use oauth::{
    config_from_formula, DeviceAuthorizationResponse, OAuthClient, OAuthConfig, TokenRefresher,
};
pub use pkce::PkcePair;
pub use registration::{ClientMetadata, ClientRegistrationResponse, DynamicRegistrationClient};
pub use script::{ResolvedScript, ScriptContext, ScriptDocument, ScriptStorage};
pub use session::{
    build_storage_key, parse_storage_key, FileStorage, MemoryStorage, SecureStorage, SessionKey,
    SessionStorage, Token,
};
