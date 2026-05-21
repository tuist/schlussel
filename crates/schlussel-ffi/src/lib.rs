use std::cell::RefCell;
use std::ffi::{c_char, c_int, CStr, CString};
use std::ptr;

use schlussel::formulas::{
    find_builtin, list_builtin, load_from_path, Formula as SchlusselFormula, MethodDef,
};
use schlussel::oauth::{OAuthClient, OAuthConfig};
use schlussel::registration::{
    ClientMetadata, ClientRegistrationResponse, DynamicRegistrationClient,
};
use schlussel::session::{MemoryStorage, SecureStorage, Token};
use schlussel::{config_from_formula, SchlusselError};
use serde::Serialize;

const SCHLUSSEL_OK: c_int = 0;
const SCHLUSSEL_ERROR_INVALID_PARAMETER: c_int = 1;
const SCHLUSSEL_ERROR_STORAGE: c_int = 2;
const SCHLUSSEL_ERROR_HTTP: c_int = 3;
const SCHLUSSEL_ERROR_AUTHORIZATION_DENIED: c_int = 4;
const SCHLUSSEL_ERROR_TOKEN_EXPIRED: c_int = 5;
const SCHLUSSEL_ERROR_NO_REFRESH_TOKEN: c_int = 6;
const SCHLUSSEL_ERROR_INVALID_STATE: c_int = 7;
const SCHLUSSEL_ERROR_DEVICE_CODE_EXPIRED: c_int = 8;
const SCHLUSSEL_ERROR_JSON: c_int = 9;
const SCHLUSSEL_ERROR_IO: c_int = 10;
const SCHLUSSEL_ERROR_SERVER: c_int = 11;
const SCHLUSSEL_ERROR_CALLBACK_SERVER: c_int = 12;
const SCHLUSSEL_ERROR_CONFIGURATION: c_int = 13;
const SCHLUSSEL_ERROR_LOCK: c_int = 14;
const SCHLUSSEL_ERROR_UNSUPPORTED: c_int = 15;
const SCHLUSSEL_ERROR_TIMEOUT: c_int = 18;
const DEFAULT_REDIRECT_URI: &str = "http://127.0.0.1/callback";

#[derive(Default)]
struct LastError {
    code: c_int,
    message: Option<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct FormulaSummaryDescriptor {
    id: String,
    label: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct FormulaMetadataDescriptor {
    schema: String,
    id: String,
    label: String,
    description: Option<String>,
    methods: Vec<FormulaMethodDescriptor>,
    identity: Option<FormulaIdentityDescriptor>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct FormulaMethodDescriptor {
    name: String,
    label: Option<String>,
    scope: Option<String>,
    flow: FormulaMethodFlowDescriptor,
    uses_dynamic_registration: bool,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
enum FormulaMethodFlowDescriptor {
    AuthorizationCode,
    DeviceCode,
    ApiKey,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct FormulaIdentityDescriptor {
    label: Option<String>,
    hint: Option<String>,
}

thread_local! {
    static LAST_ERROR: RefCell<LastError> = RefCell::new(LastError::default());
}

enum ClientHandle {
    Memory(OAuthClient<MemoryStorage>),
    Secure(OAuthClient<SecureStorage>),
}

impl ClientHandle {
    fn authorize_device(&self) -> Result<Token, SchlusselError> {
        match self {
            Self::Memory(client) => client.authorize_device(true),
            Self::Secure(client) => client.authorize_device(true),
        }
    }

    fn authorize(&self) -> Result<Token, SchlusselError> {
        match self {
            Self::Memory(client) => client.authorize(true),
            Self::Secure(client) => client.authorize(true),
        }
    }

    fn save_token(&self, key: &str, token: &Token) -> Result<(), SchlusselError> {
        match self {
            Self::Memory(client) => client.save_token(key, token),
            Self::Secure(client) => client.save_token(key, token),
        }
    }

    fn get_token(&self, key: &str) -> Result<Option<Token>, SchlusselError> {
        match self {
            Self::Memory(client) => client.get_token(key),
            Self::Secure(client) => client.get_token(key),
        }
    }

    fn delete_token(&self, key: &str) -> Result<(), SchlusselError> {
        match self {
            Self::Memory(client) => client.delete_token(key),
            Self::Secure(client) => client.delete_token(key),
        }
    }

    fn refresh_token(&self, refresh_token: &str) -> Result<Token, SchlusselError> {
        match self {
            Self::Memory(client) => client.refresh_token(refresh_token),
            Self::Secure(client) => client.refresh_token(refresh_token),
        }
    }
}

#[repr(C)]
pub struct SchlusselClient {
    inner: ClientHandle,
}

#[repr(C)]
pub struct SchlusselToken {
    token: Token,
}

#[repr(C)]
pub struct SchlusselRegistrationClient {
    inner: DynamicRegistrationClient,
}

#[repr(C)]
pub struct SchlusselRegistrationResponse {
    inner: ClientRegistrationResponse,
}

fn clear_last_error() {
    LAST_ERROR.with(|state| {
        *state.borrow_mut() = LastError::default();
    });
}

fn set_last_error(error: &SchlusselError) {
    LAST_ERROR.with(|state| {
        *state.borrow_mut() = LastError {
            code: error_code(error),
            message: Some(error.to_string()),
        };
    });
}

fn error_code(error: &SchlusselError) -> c_int {
    match error {
        SchlusselError::InvalidParameter(_) => SCHLUSSEL_ERROR_INVALID_PARAMETER,
        SchlusselError::Storage(_) => SCHLUSSEL_ERROR_STORAGE,
        SchlusselError::Http(_) => SCHLUSSEL_ERROR_HTTP,
        SchlusselError::AuthorizationDenied => SCHLUSSEL_ERROR_AUTHORIZATION_DENIED,
        SchlusselError::TokenExpired => SCHLUSSEL_ERROR_TOKEN_EXPIRED,
        SchlusselError::NoRefreshToken => SCHLUSSEL_ERROR_NO_REFRESH_TOKEN,
        SchlusselError::InvalidState => SCHLUSSEL_ERROR_INVALID_STATE,
        SchlusselError::DeviceCodeExpired => SCHLUSSEL_ERROR_DEVICE_CODE_EXPIRED,
        SchlusselError::AuthorizationPending => SCHLUSSEL_ERROR_SERVER,
        SchlusselError::SlowDown => SCHLUSSEL_ERROR_SERVER,
        SchlusselError::Json(_) => SCHLUSSEL_ERROR_JSON,
        SchlusselError::Io(_) => SCHLUSSEL_ERROR_IO,
        SchlusselError::Server { .. } => SCHLUSSEL_ERROR_SERVER,
        SchlusselError::CallbackServer(_) => SCHLUSSEL_ERROR_CALLBACK_SERVER,
        SchlusselError::Configuration(_)
        | SchlusselError::InsecureEndpoint(_)
        | SchlusselError::MissingClientId
        | SchlusselError::MissingEndpoint(_)
        | SchlusselError::MethodNotFound(_)
        | SchlusselError::FormulaNotFound(_) => SCHLUSSEL_ERROR_CONFIGURATION,
        SchlusselError::Lock(_) => SCHLUSSEL_ERROR_LOCK,
        SchlusselError::UnsupportedOperation(_) => SCHLUSSEL_ERROR_UNSUPPORTED,
        SchlusselError::TokenNotFound(_) => SCHLUSSEL_ERROR_STORAGE,
        SchlusselError::Timeout => SCHLUSSEL_ERROR_TIMEOUT,
    }
}

fn sanitize_c_string(value: &str) -> CString {
    let value = value.replace('\0', " ");
    CString::new(value).expect("sanitized strings never contain NUL bytes")
}

fn into_c_string(value: &str) -> *mut c_char {
    sanitize_c_string(value).into_raw()
}

fn into_json_string<T: Serialize>(value: &T) -> Result<*mut c_char, SchlusselError> {
    let json =
        serde_json::to_string(value).map_err(|error| SchlusselError::Json(error.to_string()))?;
    Ok(into_c_string(&json))
}

fn formula_flow_descriptor(method: &MethodDef) -> FormulaMethodFlowDescriptor {
    if method.is_device_code() {
        FormulaMethodFlowDescriptor::DeviceCode
    } else if method.is_authorization_code() {
        FormulaMethodFlowDescriptor::AuthorizationCode
    } else {
        FormulaMethodFlowDescriptor::ApiKey
    }
}

fn describe_formula(formula: SchlusselFormula) -> FormulaMetadataDescriptor {
    let methods = formula
        .methods
        .into_iter()
        .map(|(name, method)| {
            let flow = formula_flow_descriptor(&method);
            let uses_dynamic_registration = method.uses_dynamic_registration();

            FormulaMethodDescriptor {
                name,
                label: method.label,
                scope: method.scope,
                flow,
                uses_dynamic_registration,
            }
        })
        .collect();

    FormulaMetadataDescriptor {
        schema: formula.schema,
        id: formula.id,
        label: formula.label,
        description: formula.description,
        methods,
        identity: formula.identity.map(|identity| FormulaIdentityDescriptor {
            label: identity.label,
            hint: identity.hint,
        }),
    }
}

unsafe fn required_str_arg<'a>(
    value: *const c_char,
    name: &str,
) -> Result<&'a str, SchlusselError> {
    if value.is_null() {
        return Err(SchlusselError::invalid_parameter(format!(
            "{name} must not be null"
        )));
    }
    CStr::from_ptr(value)
        .to_str()
        .map_err(|_| SchlusselError::invalid_parameter(format!("{name} must be valid UTF-8")))
}

unsafe fn optional_str_arg<'a>(
    value: *const c_char,
    name: &str,
) -> Result<Option<&'a str>, SchlusselError> {
    if value.is_null() {
        return Ok(None);
    }
    CStr::from_ptr(value)
        .to_str()
        .map(Some)
        .map_err(|_| SchlusselError::invalid_parameter(format!("{name} must be valid UTF-8")))
}

unsafe fn client_ref<'a>(
    client: *mut SchlusselClient,
) -> Result<&'a SchlusselClient, SchlusselError> {
    client
        .as_ref()
        .ok_or_else(|| SchlusselError::invalid_parameter("client must not be null"))
}

unsafe fn token_ref<'a>(token: *mut SchlusselToken) -> Result<&'a SchlusselToken, SchlusselError> {
    token
        .as_ref()
        .ok_or_else(|| SchlusselError::invalid_parameter("token must not be null"))
}

unsafe fn registration_client_ref<'a>(
    client: *mut SchlusselRegistrationClient,
) -> Result<&'a SchlusselRegistrationClient, SchlusselError> {
    client
        .as_ref()
        .ok_or_else(|| SchlusselError::invalid_parameter("registration client must not be null"))
}

unsafe fn registration_response_ref<'a>(
    response: *mut SchlusselRegistrationResponse,
) -> Option<&'a SchlusselRegistrationResponse> {
    response.as_ref()
}

fn token_handle(token: Token) -> *mut SchlusselToken {
    Box::into_raw(Box::new(SchlusselToken { token }))
}

fn client_handle(inner: ClientHandle) -> *mut SchlusselClient {
    Box::into_raw(Box::new(SchlusselClient { inner }))
}

fn persistent_client_handle(
    config: OAuthConfig,
    app_name: &str,
) -> Result<*mut SchlusselClient, SchlusselError> {
    let storage = SecureStorage::new(app_name);
    let client = OAuthClient::new(config, storage)?;
    Ok(client_handle(ClientHandle::Secure(client)))
}

fn ephemeral_client_handle(config: OAuthConfig) -> Result<*mut SchlusselClient, SchlusselError> {
    let client = OAuthClient::new(config, MemoryStorage::new())?;
    Ok(client_handle(ClientHandle::Memory(client)))
}

fn formula_client_handle(
    formula: schlussel::Formula,
    method_name: &str,
    client_id: Option<&str>,
    client_secret: Option<&str>,
    redirect_uri: Option<&str>,
    scope: Option<&str>,
    app_name: Option<&str>,
) -> Result<*mut SchlusselClient, SchlusselError> {
    let config = config_from_formula(
        &formula,
        method_name,
        client_id,
        client_secret,
        redirect_uri.unwrap_or(DEFAULT_REDIRECT_URI),
        scope,
    )?;

    if let Some(app_name) = app_name {
        persistent_client_handle(config, app_name)
    } else {
        ephemeral_client_handle(config)
    }
}

fn registration_response_handle(
    response: ClientRegistrationResponse,
) -> *mut SchlusselRegistrationResponse {
    Box::into_raw(Box::new(SchlusselRegistrationResponse { inner: response }))
}

fn parse_list(value: Option<&str>) -> Vec<String> {
    value
        .map(|value| {
            value
                .split(',')
                .map(str::trim)
                .filter(|item| !item.is_empty())
                .map(ToOwned::to_owned)
                .collect()
        })
        .unwrap_or_default()
}

unsafe fn parse_redirect_uris(
    redirect_uris: *const *const c_char,
    redirect_uris_count: usize,
) -> Result<Vec<String>, SchlusselError> {
    if redirect_uris.is_null() {
        return Err(SchlusselError::invalid_parameter(
            "redirect_uris must not be null",
        ));
    }

    (0..redirect_uris_count)
        .map(|index| {
            let value = *redirect_uris.add(index);
            required_str_arg(value, "redirect_uri").map(ToOwned::to_owned)
        })
        .collect()
}

unsafe fn build_metadata(
    redirect_uris: *const *const c_char,
    redirect_uris_count: usize,
    client_name: *const c_char,
    grant_types: *const c_char,
    response_types: *const c_char,
    scope: *const c_char,
    token_auth_method: *const c_char,
) -> Result<ClientMetadata, SchlusselError> {
    let redirect_uris = parse_redirect_uris(redirect_uris, redirect_uris_count)?;

    Ok(ClientMetadata {
        client_name: optional_str_arg(client_name, "client_name")?
            .unwrap_or_default()
            .to_string(),
        redirect_uris,
        grant_types: parse_list(optional_str_arg(grant_types, "grant_types")?),
        response_types: parse_list(optional_str_arg(response_types, "response_types")?),
        scope: optional_str_arg(scope, "scope")?.map(ToOwned::to_owned),
        token_endpoint_auth_method: optional_str_arg(token_auth_method, "token_auth_method")?
            .map(ToOwned::to_owned),
        ..ClientMetadata::default()
    })
}

#[unsafe(no_mangle)]
pub extern "C" fn schlussel_last_error_code() -> c_int {
    LAST_ERROR.with(|state| state.borrow().code)
}

#[unsafe(no_mangle)]
pub extern "C" fn schlussel_last_error_message() -> *mut c_char {
    LAST_ERROR.with(|state| {
        state
            .borrow()
            .message
            .as_deref()
            .map_or(ptr::null_mut(), into_c_string)
    })
}

#[unsafe(no_mangle)]
pub extern "C" fn schlussel_clear_last_error() {
    clear_last_error();
}

#[unsafe(no_mangle)]
pub extern "C" fn schlussel_formula_list_builtin_json() -> *mut c_char {
    clear_last_error();

    let result = list_builtin()
        .into_iter()
        .map(|formula| FormulaSummaryDescriptor {
            id: formula.id,
            label: formula.label,
        })
        .collect::<Vec<_>>();

    match into_json_string(&result) {
        Ok(json) => json,
        Err(error) => {
            set_last_error(&error);
            ptr::null_mut()
        }
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn schlussel_formula_load_builtin_json(
    formula_id: *const c_char,
) -> *mut c_char {
    clear_last_error();

    let result = (|| {
        let formula_id = required_str_arg(formula_id, "formula_id")?;
        let formula = find_builtin(formula_id)
            .ok_or_else(|| SchlusselError::FormulaNotFound(formula_id.to_string()))?;
        into_json_string(&describe_formula(formula))
    })();

    match result {
        Ok(json) => json,
        Err(error) => {
            set_last_error(&error);
            ptr::null_mut()
        }
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn schlussel_formula_load_path_json(
    formula_path: *const c_char,
) -> *mut c_char {
    clear_last_error();

    let result = (|| {
        let formula_path = required_str_arg(formula_path, "formula_path")?;
        let formula = load_from_path(formula_path)?;
        into_json_string(&describe_formula(formula))
    })();

    match result {
        Ok(json) => json,
        Err(error) => {
            set_last_error(&error);
            ptr::null_mut()
        }
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn schlussel_client_new_github(
    client_id: *const c_char,
    scopes: *const c_char,
    app_name: *const c_char,
) -> *mut SchlusselClient {
    clear_last_error();

    let result = (|| {
        let client_id = required_str_arg(client_id, "client_id")?;
        let app_name = required_str_arg(app_name, "app_name")?;
        let scope = optional_str_arg(scopes, "scopes")?.map(ToOwned::to_owned);
        let config = OAuthConfig::github(client_id, scope);
        persistent_client_handle(config, app_name)
    })();

    match result {
        Ok(client) => client,
        Err(error) => {
            set_last_error(&error);
            ptr::null_mut()
        }
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn schlussel_client_new_google(
    client_id: *const c_char,
    scopes: *const c_char,
    app_name: *const c_char,
) -> *mut SchlusselClient {
    clear_last_error();

    let result = (|| {
        let client_id = required_str_arg(client_id, "client_id")?;
        let app_name = required_str_arg(app_name, "app_name")?;
        let scope = optional_str_arg(scopes, "scopes")?.map(ToOwned::to_owned);
        let config = OAuthConfig::google(client_id, scope);
        persistent_client_handle(config, app_name)
    })();

    match result {
        Ok(client) => client,
        Err(error) => {
            set_last_error(&error);
            ptr::null_mut()
        }
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn schlussel_client_new(
    client_id: *const c_char,
    authorization_endpoint: *const c_char,
    token_endpoint: *const c_char,
    redirect_uri: *const c_char,
    scopes: *const c_char,
    device_authorization_endpoint: *const c_char,
) -> *mut SchlusselClient {
    clear_last_error();

    let result = (|| {
        let config = OAuthConfig {
            client_id: required_str_arg(client_id, "client_id")?.to_string(),
            client_secret: None,
            authorization_endpoint: required_str_arg(
                authorization_endpoint,
                "authorization_endpoint",
            )?
            .to_string(),
            token_endpoint: required_str_arg(token_endpoint, "token_endpoint")?.to_string(),
            redirect_uri: required_str_arg(redirect_uri, "redirect_uri")?.to_string(),
            scope: optional_str_arg(scopes, "scopes")?.map(ToOwned::to_owned),
            device_authorization_endpoint: optional_str_arg(
                device_authorization_endpoint,
                "device_authorization_endpoint",
            )?
            .map(ToOwned::to_owned),
        };
        ephemeral_client_handle(config)
    })();

    match result {
        Ok(client) => client,
        Err(error) => {
            set_last_error(&error);
            ptr::null_mut()
        }
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn schlussel_client_new_formula_builtin(
    formula_id: *const c_char,
    method_name: *const c_char,
    client_id: *const c_char,
    client_secret: *const c_char,
    redirect_uri: *const c_char,
    scopes: *const c_char,
    app_name: *const c_char,
) -> *mut SchlusselClient {
    clear_last_error();

    let result = (|| {
        let formula_id = required_str_arg(formula_id, "formula_id")?;
        let method_name = required_str_arg(method_name, "method_name")?;
        let client_id = optional_str_arg(client_id, "client_id")?;
        let client_secret = optional_str_arg(client_secret, "client_secret")?;
        let redirect_uri = optional_str_arg(redirect_uri, "redirect_uri")?;
        let scopes = optional_str_arg(scopes, "scopes")?;
        let app_name = optional_str_arg(app_name, "app_name")?;
        let formula = find_builtin(formula_id)
            .ok_or_else(|| SchlusselError::FormulaNotFound(formula_id.to_string()))?;

        formula_client_handle(
            formula,
            method_name,
            client_id,
            client_secret,
            redirect_uri,
            scopes,
            app_name,
        )
    })();

    match result {
        Ok(client) => client,
        Err(error) => {
            set_last_error(&error);
            ptr::null_mut()
        }
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn schlussel_client_new_formula_path(
    formula_path: *const c_char,
    method_name: *const c_char,
    client_id: *const c_char,
    client_secret: *const c_char,
    redirect_uri: *const c_char,
    scopes: *const c_char,
    app_name: *const c_char,
) -> *mut SchlusselClient {
    clear_last_error();

    let result = (|| {
        let formula_path = required_str_arg(formula_path, "formula_path")?;
        let method_name = required_str_arg(method_name, "method_name")?;
        let client_id = optional_str_arg(client_id, "client_id")?;
        let client_secret = optional_str_arg(client_secret, "client_secret")?;
        let redirect_uri = optional_str_arg(redirect_uri, "redirect_uri")?;
        let scopes = optional_str_arg(scopes, "scopes")?;
        let app_name = optional_str_arg(app_name, "app_name")?;
        let formula = load_from_path(formula_path)?;

        formula_client_handle(
            formula,
            method_name,
            client_id,
            client_secret,
            redirect_uri,
            scopes,
            app_name,
        )
    })();

    match result {
        Ok(client) => client,
        Err(error) => {
            set_last_error(&error);
            ptr::null_mut()
        }
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn schlussel_client_free(client: *mut SchlusselClient) {
    if !client.is_null() {
        drop(Box::from_raw(client));
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn schlussel_authorize_device(
    client: *mut SchlusselClient,
) -> *mut SchlusselToken {
    clear_last_error();

    match client_ref(client).and_then(|client| client.inner.authorize_device()) {
        Ok(token) => token_handle(token),
        Err(error) => {
            set_last_error(&error);
            ptr::null_mut()
        }
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn schlussel_authorize(client: *mut SchlusselClient) -> *mut SchlusselToken {
    clear_last_error();

    match client_ref(client).and_then(|client| client.inner.authorize()) {
        Ok(token) => token_handle(token),
        Err(error) => {
            set_last_error(&error);
            ptr::null_mut()
        }
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn schlussel_save_token(
    client: *mut SchlusselClient,
    key: *const c_char,
    token: *mut SchlusselToken,
) -> c_int {
    clear_last_error();

    let result = (|| {
        let client = client_ref(client)?;
        let key = required_str_arg(key, "key")?;
        let token = token_ref(token)?;
        client.inner.save_token(key, &token.token)
    })();

    match result {
        Ok(()) => SCHLUSSEL_OK,
        Err(error) => {
            set_last_error(&error);
            error_code(&error)
        }
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn schlussel_get_token(
    client: *mut SchlusselClient,
    key: *const c_char,
) -> *mut SchlusselToken {
    clear_last_error();

    let result = (|| {
        let client = client_ref(client)?;
        let key = required_str_arg(key, "key")?;
        client.inner.get_token(key)
    })();

    match result {
        Ok(Some(token)) => token_handle(token),
        Ok(None) => ptr::null_mut(),
        Err(error) => {
            set_last_error(&error);
            ptr::null_mut()
        }
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn schlussel_delete_token(
    client: *mut SchlusselClient,
    key: *const c_char,
) -> c_int {
    clear_last_error();

    let result = (|| {
        let client = client_ref(client)?;
        let key = required_str_arg(key, "key")?;
        client.inner.delete_token(key)
    })();

    match result {
        Ok(()) => SCHLUSSEL_OK,
        Err(error) => {
            set_last_error(&error);
            error_code(&error)
        }
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn schlussel_refresh_token(
    client: *mut SchlusselClient,
    refresh_token: *const c_char,
) -> *mut SchlusselToken {
    clear_last_error();

    let result = (|| {
        let client = client_ref(client)?;
        let refresh_token = required_str_arg(refresh_token, "refresh_token")?;
        client.inner.refresh_token(refresh_token)
    })();

    match result {
        Ok(token) => token_handle(token),
        Err(error) => {
            set_last_error(&error);
            ptr::null_mut()
        }
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn schlussel_token_get_access_token(
    token: *mut SchlusselToken,
) -> *mut c_char {
    token.as_ref().map_or(ptr::null_mut(), |token| {
        into_c_string(&token.token.access_token)
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn schlussel_token_get_refresh_token(
    token: *mut SchlusselToken,
) -> *mut c_char {
    token
        .as_ref()
        .and_then(|token| token.token.refresh_token.as_deref())
        .map_or(ptr::null_mut(), into_c_string)
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn schlussel_token_get_token_type(token: *mut SchlusselToken) -> *mut c_char {
    token.as_ref().map_or(ptr::null_mut(), |token| {
        into_c_string(&token.token.token_type)
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn schlussel_token_get_scope(token: *mut SchlusselToken) -> *mut c_char {
    token
        .as_ref()
        .and_then(|token| token.token.scope.as_deref())
        .map_or(ptr::null_mut(), into_c_string)
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn schlussel_token_is_expired(token: *mut SchlusselToken) -> c_int {
    token
        .as_ref()
        .map_or(-1, |token| if token.token.is_expired() { 1 } else { 0 })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn schlussel_token_get_expires_at(token: *mut SchlusselToken) -> u64 {
    token
        .as_ref()
        .and_then(|token| token.token.expires_at)
        .unwrap_or(0)
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn schlussel_token_free(token: *mut SchlusselToken) {
    if !token.is_null() {
        drop(Box::from_raw(token));
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn schlussel_string_free(value: *mut c_char) {
    if !value.is_null() {
        drop(CString::from_raw(value));
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn schlussel_registration_new(
    endpoint: *const c_char,
) -> *mut SchlusselRegistrationClient {
    clear_last_error();

    let result = (|| {
        let endpoint = required_str_arg(endpoint, "endpoint")?;
        let client = DynamicRegistrationClient::new(endpoint)?;
        Ok(Box::into_raw(Box::new(SchlusselRegistrationClient {
            inner: client,
        })))
    })();

    match result {
        Ok(client) => client,
        Err(error) => {
            set_last_error(&error);
            ptr::null_mut()
        }
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn schlussel_registration_free(client: *mut SchlusselRegistrationClient) {
    if !client.is_null() {
        drop(Box::from_raw(client));
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn schlussel_register_client(
    reg_client: *mut SchlusselRegistrationClient,
    redirect_uris: *const *const c_char,
    redirect_uris_count: usize,
    client_name: *const c_char,
    grant_types: *const c_char,
    response_types: *const c_char,
    scope: *const c_char,
    token_auth_method: *const c_char,
) -> *mut SchlusselRegistrationResponse {
    clear_last_error();

    let result = (|| {
        if redirect_uris_count == 0 {
            return Err(SchlusselError::invalid_parameter(
                "redirect_uris_count must be greater than zero",
            ));
        }
        let client = registration_client_ref(reg_client)?;
        let metadata = build_metadata(
            redirect_uris,
            redirect_uris_count,
            client_name,
            grant_types,
            response_types,
            scope,
            token_auth_method,
        )?;
        client.inner.register(&metadata)
    })();

    match result {
        Ok(response) => registration_response_handle(response),
        Err(error) => {
            set_last_error(&error);
            ptr::null_mut()
        }
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn schlussel_registration_read(
    reg_client: *mut SchlusselRegistrationClient,
    registration_access_token: *const c_char,
) -> *mut SchlusselRegistrationResponse {
    clear_last_error();

    let result = (|| {
        let client = registration_client_ref(reg_client)?;
        let token = required_str_arg(registration_access_token, "registration_access_token")?;
        client.inner.read(token)
    })();

    match result {
        Ok(response) => registration_response_handle(response),
        Err(error) => {
            set_last_error(&error);
            ptr::null_mut()
        }
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn schlussel_registration_update(
    reg_client: *mut SchlusselRegistrationClient,
    registration_access_token: *const c_char,
    redirect_uris: *const *const c_char,
    redirect_uris_count: usize,
    client_name: *const c_char,
    grant_types: *const c_char,
    response_types: *const c_char,
    scope: *const c_char,
    token_auth_method: *const c_char,
) -> *mut SchlusselRegistrationResponse {
    clear_last_error();

    let result = (|| {
        if redirect_uris_count == 0 {
            return Err(SchlusselError::invalid_parameter(
                "redirect_uris_count must be greater than zero",
            ));
        }
        let client = registration_client_ref(reg_client)?;
        let token = required_str_arg(registration_access_token, "registration_access_token")?;
        let metadata = build_metadata(
            redirect_uris,
            redirect_uris_count,
            client_name,
            grant_types,
            response_types,
            scope,
            token_auth_method,
        )?;
        client.inner.update(token, &metadata)
    })();

    match result {
        Ok(response) => registration_response_handle(response),
        Err(error) => {
            set_last_error(&error);
            ptr::null_mut()
        }
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn schlussel_registration_delete(
    reg_client: *mut SchlusselRegistrationClient,
    registration_access_token: *const c_char,
) -> c_int {
    clear_last_error();

    let result = (|| {
        let client = registration_client_ref(reg_client)?;
        let token = required_str_arg(registration_access_token, "registration_access_token")?;
        client.inner.delete(token)
    })();

    match result {
        Ok(()) => SCHLUSSEL_OK,
        Err(error) => {
            set_last_error(&error);
            error_code(&error)
        }
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn schlussel_registration_response_free(
    response: *mut SchlusselRegistrationResponse,
) {
    if !response.is_null() {
        drop(Box::from_raw(response));
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn schlussel_registration_response_get_client_id(
    response: *mut SchlusselRegistrationResponse,
) -> *mut c_char {
    registration_response_ref(response).map_or(ptr::null_mut(), |response| {
        into_c_string(&response.inner.client_id)
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn schlussel_registration_response_get_client_secret(
    response: *mut SchlusselRegistrationResponse,
) -> *mut c_char {
    registration_response_ref(response)
        .and_then(|response| response.inner.client_secret.as_deref())
        .map_or(ptr::null_mut(), into_c_string)
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn schlussel_registration_response_get_client_id_issued_at(
    response: *mut SchlusselRegistrationResponse,
) -> i64 {
    registration_response_ref(response)
        .and_then(|response| response.inner.client_id_issued_at)
        .unwrap_or(0)
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn schlussel_registration_response_get_client_secret_expires_at(
    response: *mut SchlusselRegistrationResponse,
) -> i64 {
    registration_response_ref(response)
        .and_then(|response| response.inner.client_secret_expires_at)
        .unwrap_or(0)
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn schlussel_registration_response_get_registration_access_token(
    response: *mut SchlusselRegistrationResponse,
) -> *mut c_char {
    registration_response_ref(response)
        .and_then(|response| response.inner.registration_access_token.as_deref())
        .map_or(ptr::null_mut(), into_c_string)
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn schlussel_registration_response_get_registration_client_uri(
    response: *mut SchlusselRegistrationResponse,
) -> *mut c_char {
    registration_response_ref(response)
        .and_then(|response| response.inner.registration_client_uri.as_deref())
        .map_or(ptr::null_mut(), into_c_string)
}

#[cfg(test)]
mod tests {
    use std::fs;

    use super::*;
    use tempfile::tempdir;

    #[test]
    fn null_token_accessors_are_safe() {
        assert!(unsafe { schlussel_token_get_access_token(ptr::null_mut()) }.is_null());
        assert!(unsafe { schlussel_token_get_refresh_token(ptr::null_mut()) }.is_null());
        assert!(unsafe { schlussel_token_get_token_type(ptr::null_mut()) }.is_null());
        assert!(unsafe { schlussel_token_get_scope(ptr::null_mut()) }.is_null());
        assert_eq!(unsafe { schlussel_token_is_expired(ptr::null_mut()) }, -1);
        assert_eq!(
            unsafe { schlussel_token_get_expires_at(ptr::null_mut()) },
            0
        );
    }

    #[test]
    fn reports_invalid_parameter_errors() {
        let client = unsafe { schlussel_client_new_github(ptr::null(), ptr::null(), ptr::null()) };

        assert!(client.is_null());
        assert_eq!(
            schlussel_last_error_code(),
            SCHLUSSEL_ERROR_INVALID_PARAMETER
        );

        let message_ptr = schlussel_last_error_message();
        assert!(!message_ptr.is_null());
        let message = unsafe { CStr::from_ptr(message_ptr) }
            .to_str()
            .expect("utf-8");
        assert!(message.contains("client_id"));
        unsafe { schlussel_string_free(message_ptr) };
    }

    #[test]
    fn custom_client_uses_memory_storage() {
        let client_id = CString::new("client-id").expect("cstring");
        let authorization_endpoint =
            CString::new("https://example.com/authorize").expect("cstring");
        let token_endpoint = CString::new("https://example.com/token").expect("cstring");
        let redirect_uri = CString::new("http://127.0.0.1/callback").expect("cstring");

        let client = unsafe {
            schlussel_client_new(
                client_id.as_ptr(),
                authorization_endpoint.as_ptr(),
                token_endpoint.as_ptr(),
                redirect_uri.as_ptr(),
                ptr::null(),
                ptr::null(),
            )
        };

        assert!(!client.is_null());
        unsafe { schlussel_client_free(client) };
    }

    #[test]
    fn lists_builtin_formulas_as_json() {
        let payload = schlussel_formula_list_builtin_json();
        assert!(!payload.is_null());

        let payload = owned_c_string(payload);
        let formulas: serde_json::Value = serde_json::from_str(&payload).expect("valid json");
        let formulas = formulas.as_array().expect("formula list");

        assert!(formulas.iter().any(|formula| formula["id"] == "github"));
        assert!(formulas
            .iter()
            .all(|formula| formula.get("label").is_some()));
    }

    #[test]
    fn loads_builtin_formula_metadata_as_json() {
        let formula_id = CString::new("github").expect("cstring");
        let payload = unsafe { schlussel_formula_load_builtin_json(formula_id.as_ptr()) };
        assert!(!payload.is_null());

        let payload = owned_c_string(payload);
        let formula: serde_json::Value = serde_json::from_str(&payload).expect("valid json");

        assert_eq!(formula["id"], "github");
        assert!(formula["methods"].as_array().is_some_and(|methods| {
            methods.iter().any(|method| method["flow"] == "deviceCode")
        }));
    }

    #[test]
    fn loads_file_formula_metadata_as_json() {
        let directory = tempdir().expect("tempdir");
        let formula_path = directory.path().join("formula.json");
        fs::write(
            &formula_path,
            r#"{
  "schema": "v2",
  "id": "example",
  "label": "Example",
  "description": "Example formula",
  "methods": {
    "api_key": {
      "label": "API Key",
      "script": [{ "type": "copy_key" }]
    }
  }
}"#,
        )
        .expect("write formula");

        let formula_path =
            CString::new(formula_path.to_string_lossy().to_string()).expect("cstring");
        let payload = unsafe { schlussel_formula_load_path_json(formula_path.as_ptr()) };
        assert!(!payload.is_null());

        let payload = owned_c_string(payload);
        let formula: serde_json::Value = serde_json::from_str(&payload).expect("valid json");

        assert_eq!(formula["id"], "example");
        assert_eq!(formula["methods"][0]["flow"], "apiKey");
    }

    #[test]
    fn builtin_formula_client_uses_bundled_configuration() {
        let formula_id = CString::new("github").expect("cstring");
        let method_name = CString::new("device_code").expect("cstring");

        let client = unsafe {
            schlussel_client_new_formula_builtin(
                formula_id.as_ptr(),
                method_name.as_ptr(),
                ptr::null(),
                ptr::null(),
                ptr::null(),
                ptr::null(),
                ptr::null(),
            )
        };

        assert!(!client.is_null());
        unsafe { schlussel_client_free(client) };
    }

    #[test]
    fn file_formula_client_accepts_overrides() {
        let directory = tempdir().expect("tempdir");
        let formula_path = directory.path().join("formula.json");
        fs::write(
            &formula_path,
            r#"{
  "schema": "v2",
  "id": "example",
  "label": "Example",
  "methods": {
    "authorization_code": {
      "endpoints": {
        "authorize": "https://example.com/authorize",
        "token": "https://example.com/token"
      }
    }
  }
}"#,
        )
        .expect("write formula");

        let formula_path =
            CString::new(formula_path.to_string_lossy().to_string()).expect("cstring");
        let method_name = CString::new("authorization_code").expect("cstring");
        let client_id = CString::new("client-id").expect("cstring");

        let client = unsafe {
            schlussel_client_new_formula_path(
                formula_path.as_ptr(),
                method_name.as_ptr(),
                client_id.as_ptr(),
                ptr::null(),
                ptr::null(),
                ptr::null(),
                ptr::null(),
            )
        };

        assert!(!client.is_null());
        unsafe { schlussel_client_free(client) };
    }

    fn owned_c_string(pointer: *mut c_char) -> String {
        let value = unsafe { CStr::from_ptr(pointer) }
            .to_str()
            .expect("utf-8")
            .to_string();
        unsafe { schlussel_string_free(pointer) };
        value
    }
}
