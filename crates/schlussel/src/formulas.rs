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
    #[serde(default)]
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
        if method.is_device_code()
            && method
                .endpoints
                .as_ref()
                .is_none_or(|endpoints| endpoints.device.is_none() || endpoints.token.is_none())
        {
            return Err(SchlusselError::configuration(format!(
                "formula '{}' method '{}' is missing device endpoints",
                formula.id, method_name
            )));
        }

        if method.is_authorization_code()
            && method
                .endpoints
                .as_ref()
                .is_none_or(|endpoints| endpoints.authorize.is_none() || endpoints.token.is_none())
        {
            return Err(SchlusselError::configuration(format!(
                "formula '{}' method '{}' is missing authorization endpoints",
                formula.id, method_name
            )));
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builtin_formulas_include_github() {
        let github = find_builtin("github").expect("github formula");
        assert_eq!(github.label, "GitHub");
        assert!(github.methods.contains_key("device_code"));
    }

    #[test]
    fn formula_parses_v2_document() {
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
              },
              "apis": {
                "rest": {
                  "base_url": "https://example.com/api",
                  "auth_header": "Authorization: Bearer {token}",
                  "methods": ["oauth"]
                }
              }
            }"#,
        )
        .expect("formula");

        assert_eq!(formula.id, "example");
        assert!(formula.get_method("oauth").is_some());
    }
}
