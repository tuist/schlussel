use std::collections::BTreeMap;
use std::fs;
use std::path::Path;
use std::sync::OnceLock;

use include_dir::{include_dir, Dir};
use serde::{Deserialize, Serialize};

use crate::error::{Result, SchlusselError};

static FORMULAS_DIR: Dir<'_> = include_dir!("$CARGO_MANIFEST_DIR/../../src/formulas");
static BUILTIN_FORMULAS: OnceLock<Vec<Formula>> = OnceLock::new();

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ScriptStep {
    #[serde(rename = "type")]
    pub kind: String,
    #[serde(default)]
    pub value: Option<String>,
    #[serde(default)]
    pub note: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RegisterInstructions {
    pub url: String,
    #[serde(default)]
    pub steps: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct Endpoints {
    #[serde(default)]
    pub authorize: Option<String>,
    #[serde(default)]
    pub token: Option<String>,
    #[serde(default, alias = "device_authorization")]
    pub device: Option<String>,
    #[serde(default)]
    pub registration: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct DynamicRegistrationDef {
    #[serde(default)]
    pub client_name: Option<String>,
    #[serde(default)]
    pub grant_types: Vec<String>,
    #[serde(default)]
    pub response_types: Vec<String>,
    #[serde(default)]
    pub token_endpoint_auth_method: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct MethodDef {
    #[serde(default)]
    pub label: Option<String>,
    #[serde(default)]
    pub endpoints: Option<Endpoints>,
    #[serde(default)]
    pub scope: Option<String>,
    #[serde(default)]
    pub register: Option<RegisterInstructions>,
    #[serde(default)]
    pub script: Vec<ScriptStep>,
    #[serde(default)]
    pub dynamic_registration: Option<DynamicRegistrationDef>,
}

impl MethodDef {
    pub fn is_authorization_code(&self) -> bool {
        self.endpoints
            .as_ref()
            .is_some_and(|endpoints| endpoints.authorize.is_some() && endpoints.token.is_some())
            && !self.is_device_code()
    }

    pub fn is_device_code(&self) -> bool {
        self.endpoints
            .as_ref()
            .is_some_and(|endpoints| endpoints.device.is_some() && endpoints.token.is_some())
    }

    pub fn is_api_key(&self) -> bool {
        !self.is_authorization_code() && !self.is_device_code()
    }

    pub fn uses_dynamic_registration(&self) -> bool {
        self.dynamic_registration.is_some()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ApiDef {
    pub base_url: String,
    pub auth_header: String,
    #[serde(default)]
    pub docs_url: Option<String>,
    #[serde(default)]
    pub spec_url: Option<String>,
    #[serde(default)]
    pub spec_type: Option<String>,
    #[serde(default)]
    pub methods: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Client {
    pub name: String,
    pub id: String,
    #[serde(default)]
    pub secret: Option<String>,
    #[serde(default)]
    pub source: Option<String>,
    #[serde(default)]
    pub methods: Vec<String>,
    #[serde(default)]
    pub redirect_uri: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct Identity {
    #[serde(default)]
    pub label: Option<String>,
    #[serde(default)]
    pub hint: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Formula {
    pub schema: String,
    pub id: String,
    pub label: String,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub methods: BTreeMap<String, MethodDef>,
    #[serde(default)]
    pub apis: BTreeMap<String, ApiDef>,
    #[serde(default)]
    pub clients: Vec<Client>,
    #[serde(default)]
    pub identity: Option<Identity>,
}

impl Formula {
    pub fn get_method(&self, name: &str) -> Option<&MethodDef> {
        self.methods.get(name)
    }

    pub fn get_api(&self, name: &str) -> Option<&ApiDef> {
        self.apis.get(name)
    }

    pub fn get_default_client(&self) -> Option<&Client> {
        self.clients.first()
    }

    pub fn get_default_client_for_method(&self, method_name: &str) -> Option<&Client> {
        self.clients.iter().find(|client| {
            client.methods.is_empty() || client.methods.iter().any(|method| method == method_name)
        })
    }

    pub fn get_client_by_name(&self, name: &str) -> Option<&Client> {
        self.clients.iter().find(|client| client.name == name)
    }

    pub fn get_first_method_name(&self) -> Option<&str> {
        self.methods.keys().next().map(String::as_str)
    }

    pub fn method_names(&self) -> Vec<&str> {
        self.methods.keys().map(String::as_str).collect()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FormulaInfo {
    pub id: String,
    pub label: String,
}

pub fn load_from_json_slice(contents: &[u8]) -> Result<Formula> {
    let formula = serde_json::from_slice::<Formula>(contents)?;
    validate_formula(&formula)?;
    Ok(formula)
}

pub fn load_from_path(path: impl AsRef<Path>) -> Result<Formula> {
    let bytes = fs::read(path)?;
    load_from_json_slice(&bytes)
}

pub fn builtin_formulas() -> &'static [Formula] {
    BUILTIN_FORMULAS
        .get_or_init(parse_builtin_formulas)
        .as_slice()
}

pub fn find_builtin(id: &str) -> Option<Formula> {
    builtin_formulas()
        .iter()
        .find(|formula| formula.id == id)
        .cloned()
}

pub fn list_builtin() -> Vec<FormulaInfo> {
    builtin_formulas()
        .iter()
        .map(|formula| FormulaInfo {
            id: formula.id.clone(),
            label: formula.label.clone(),
        })
        .collect()
}

fn parse_builtin_formulas() -> Vec<Formula> {
    let mut formulas = FORMULAS_DIR
        .files()
        .filter(|file| {
            file.path()
                .extension()
                .is_some_and(|extension| extension == "json")
        })
        .map(|file| load_from_json_slice(file.contents()).expect("bundled formula should parse"))
        .collect::<Vec<_>>();

    formulas.sort_by(|left, right| left.id.cmp(&right.id));
    formulas
}

fn validate_formula(formula: &Formula) -> Result<()> {
    if formula.schema != "v2" {
        return Err(SchlusselError::configuration(format!(
            "formula '{}' uses unsupported schema '{}'",
            formula.id, formula.schema
        )));
    }

    if formula.id.trim().is_empty() {
        return Err(SchlusselError::configuration(
            "formula id must not be empty".to_string(),
        ));
    }

    if formula.methods.is_empty() {
        return Err(SchlusselError::configuration(format!(
            "formula '{}' must define at least one method",
            formula.id
        )));
    }

    for (method_name, method) in &formula.methods {
        if let Some(endpoints) = &method.endpoints {
            validate_method_endpoints(&formula.id, method_name, endpoints)?;
        }
    }

    Ok(())
}

fn validate_method_endpoints(
    formula_id: &str,
    method_name: &str,
    endpoints: &Endpoints,
) -> Result<()> {
    let has_authorize = endpoints.authorize.is_some();
    let has_device = endpoints.device.is_some();
    let has_token = endpoints.token.is_some();

    if has_authorize && !has_token {
        return Err(SchlusselError::configuration(format!(
            "formula '{formula_id}' method '{method_name}' is missing a token endpoint for authorization flow",
        )));
    }

    if has_device && !has_token {
        return Err(SchlusselError::configuration(format!(
            "formula '{formula_id}' method '{method_name}' is missing a token endpoint for device flow",
        )));
    }

    if has_token && !has_authorize && !has_device {
        return Err(SchlusselError::configuration(format!(
            "formula '{formula_id}' method '{method_name}' has a token endpoint but no authorize or device endpoint",
        )));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use std::io::Write;

    use serde_json::json;
    use tempfile::NamedTempFile;

    use super::*;

    fn parse_formula(value: serde_json::Value) -> Result<Formula> {
        let bytes = serde_json::to_vec(&value).expect("formula JSON");
        load_from_json_slice(&bytes)
    }

    fn sample_formula() -> Formula {
        parse_formula(json!({
            "schema": "v2",
            "id": "example",
            "label": "Example",
            "clients": [
                { "name": "default", "id": "default-client" },
                { "name": "device-only", "id": "device-client", "methods": ["device_code"] }
            ],
            "methods": {
                "api_key": {
                    "label": "API Key"
                },
                "authorization_code": {
                    "label": "Authorization Code",
                    "endpoints": {
                        "authorize": "https://example.com/authorize",
                        "token": "https://example.com/token"
                    }
                },
                "device_code": {
                    "label": "Device Code",
                    "dynamic_registration": {
                        "client_name": "Example CLI"
                    },
                    "endpoints": {
                        "device": "https://example.com/device",
                        "token": "https://example.com/token"
                    }
                }
            },
            "apis": {
                "rest": {
                    "base_url": "https://example.com/api",
                    "auth_header": "Authorization: Bearer {token}",
                    "methods": ["authorization_code", "device_code"]
                }
            },
            "identity": {
                "label": "Account",
                "hint": "personal"
            }
        }))
        .expect("sample formula")
    }

    #[test]
    fn builtin_formulas_include_github() {
        let github = find_builtin("github").expect("github formula");
        assert_eq!(github.label, "GitHub");
        assert!(github.methods.contains_key("device_code"));
    }

    #[test]
    fn builtin_formulas_include_tuist() {
        let tuist = find_builtin("tuist").expect("tuist formula");
        assert_eq!(tuist.label, "Tuist");
        assert!(tuist.methods.contains_key("session"));
    }

    #[test]
    fn builtin_formula_list_is_sorted() {
        let ids = list_builtin()
            .into_iter()
            .map(|formula| formula.id)
            .collect::<Vec<_>>();
        let mut sorted = ids.clone();
        sorted.sort();
        assert_eq!(ids, sorted);
        assert!(ids.iter().any(|id| id == "github"));
    }

    #[test]
    fn formula_helpers_expose_methods_apis_and_clients() {
        let formula = sample_formula();

        assert_eq!(formula.id, "example");
        assert_eq!(
            formula.get_api("rest").expect("rest api").base_url,
            "https://example.com/api"
        );
        assert_eq!(
            formula.get_default_client().expect("default client").name,
            "default"
        );
        assert_eq!(
            formula
                .get_default_client_for_method("device_code")
                .expect("device client")
                .name,
            "default"
        );
        assert_eq!(
            formula
                .get_client_by_name("device-only")
                .expect("named client")
                .id,
            "device-client"
        );
        assert_eq!(formula.get_first_method_name(), Some("api_key"));
        assert_eq!(
            formula.method_names(),
            vec!["api_key", "authorization_code", "device_code"]
        );
    }

    #[test]
    fn method_helpers_classify_flows() {
        let formula = sample_formula();
        let api_key = formula.get_method("api_key").expect("api key method");
        let authorization_code = formula
            .get_method("authorization_code")
            .expect("authorization code method");
        let device_code = formula
            .get_method("device_code")
            .expect("device code method");

        assert!(api_key.is_api_key());
        assert!(!api_key.is_authorization_code());
        assert!(!api_key.is_device_code());

        assert!(authorization_code.is_authorization_code());
        assert!(!authorization_code.is_device_code());
        assert!(!authorization_code.is_api_key());

        assert!(device_code.is_device_code());
        assert!(!device_code.is_authorization_code());
        assert!(!device_code.is_api_key());
        assert!(device_code.uses_dynamic_registration());
    }

    #[test]
    fn formula_parses_device_authorization_alias() {
        let formula = parse_formula(json!({
            "schema": "v2",
            "id": "gitlab-like",
            "label": "GitLab Like",
            "clients": [{ "name": "cli", "id": "client-id" }],
            "methods": {
                "device_code": {
                    "endpoints": {
                        "device_authorization": "https://example.com/device",
                        "token": "https://example.com/token"
                    }
                }
            }
        }))
        .expect("formula");

        let method = formula
            .get_method("device_code")
            .expect("device_code method");
        let endpoints = method.endpoints.as_ref().expect("device endpoints");
        assert_eq!(
            endpoints.device.as_deref(),
            Some("https://example.com/device")
        );
        assert!(method.is_device_code());
    }

    #[test]
    fn load_from_path_roundtrips_formula() {
        let mut file = NamedTempFile::new().expect("temporary formula file");
        let source = serde_json::to_string_pretty(&json!({
            "schema": "v2",
            "id": "path-example",
            "label": "Path Example",
            "clients": [{ "name": "cli", "id": "client-id" }],
            "methods": {
                "authorization_code": {
                    "endpoints": {
                        "authorize": "https://example.com/authorize",
                        "token": "https://example.com/token"
                    }
                }
            }
        }))
        .expect("formula source");
        file.write_all(source.as_bytes()).expect("write formula");

        let formula = load_from_path(file.path()).expect("load formula");
        assert_eq!(formula.id, "path-example");
        assert!(formula.get_method("authorization_code").is_some());
    }

    #[test]
    fn formula_rejects_unsupported_schema() {
        let error = parse_formula(json!({
            "schema": "v1",
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
        }))
        .expect_err("unsupported schema");

        assert!(matches!(
            error,
            SchlusselError::Configuration(message)
            if message.contains("unsupported schema")
        ));
    }

    #[test]
    fn formula_rejects_empty_id() {
        let error = parse_formula(json!({
            "schema": "v2",
            "id": "   ",
            "label": "Example",
            "methods": {
                "authorization_code": {
                    "endpoints": {
                        "authorize": "https://example.com/authorize",
                        "token": "https://example.com/token"
                    }
                }
            }
        }))
        .expect_err("empty id");

        assert!(matches!(
            error,
            SchlusselError::Configuration(message)
            if message.contains("must not be empty")
        ));
    }

    #[test]
    fn formula_rejects_missing_methods() {
        let error = parse_formula(json!({
            "schema": "v2",
            "id": "example",
            "label": "Example",
            "methods": {}
        }))
        .expect_err("missing methods");

        assert!(matches!(
            error,
            SchlusselError::Configuration(message)
            if message.contains("must define at least one method")
        ));
    }

    #[test]
    fn formula_rejects_token_only_endpoints() {
        let error = parse_formula(json!({
            "schema": "v2",
            "id": "example",
            "label": "Example",
            "methods": {
                "device_code": {
                    "endpoints": {
                        "token": "https://example.com/token"
                    }
                }
            }
        }))
        .expect_err("token-only endpoints");

        assert!(matches!(
            error,
            SchlusselError::Configuration(message)
            if message.contains("token endpoint")
                && message.contains("no authorize or device endpoint")
        ));
    }

    #[test]
    fn formula_rejects_authorization_without_token() {
        let error = parse_formula(json!({
            "schema": "v2",
            "id": "example",
            "label": "Example",
            "methods": {
                "authorization_code": {
                    "endpoints": {
                        "authorize": "https://example.com/authorize"
                    }
                }
            }
        }))
        .expect_err("missing authorization token endpoint");

        assert!(matches!(
            error,
            SchlusselError::Configuration(message)
            if message.contains("authorization flow")
                && message.contains("token endpoint")
        ));
    }

    #[test]
    fn formula_rejects_device_without_token() {
        let error = parse_formula(json!({
            "schema": "v2",
            "id": "example",
            "label": "Example",
            "methods": {
                "device_code": {
                    "endpoints": {
                        "device": "https://example.com/device"
                    }
                }
            }
        }))
        .expect_err("missing device token endpoint");

        assert!(matches!(
            error,
            SchlusselError::Configuration(message)
            if message.contains("device flow")
                && message.contains("token endpoint")
        ));
    }

    #[test]
    fn formula_parses_v2_document() {
        let formula = sample_formula();
        assert_eq!(formula.id, "example");
        assert!(formula.get_method("authorization_code").is_some());
    }
}
