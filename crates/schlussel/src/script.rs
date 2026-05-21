use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::callback::{build_authorization_url, CallbackServer};
use crate::error::{Result, SchlusselError};
use crate::formulas::{Formula, MethodDef, ScriptStep};
use crate::oauth::{build_memory_oauth_client, config_from_formula};
use crate::pkce::PkcePair;
use crate::session::build_storage_key;

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct ScriptContext {
    #[serde(default)]
    pub authorize_url: Option<String>,
    #[serde(default)]
    pub pkce_verifier: Option<String>,
    #[serde(default)]
    pub state: Option<String>,
    #[serde(default)]
    pub redirect_uri: Option<String>,
    #[serde(default)]
    pub device_code: Option<String>,
    #[serde(default)]
    pub user_code: Option<String>,
    #[serde(default)]
    pub verification_uri: Option<String>,
    #[serde(default)]
    pub verification_uri_complete: Option<String>,
    #[serde(default)]
    pub interval: Option<u64>,
    #[serde(default)]
    pub expires_in: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ScriptStorage {
    pub key: String,
    pub formula: String,
    pub method: String,
    #[serde(default)]
    pub identity: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ResolvedScript {
    pub steps: Vec<ScriptStep>,
    pub context: ScriptContext,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ScriptDocument {
    pub formula: String,
    pub methods: Vec<String>,
    #[serde(default)]
    pub method: Option<String>,
    pub script: Vec<ScriptStep>,
    pub storage: ScriptStorage,
    #[serde(default)]
    pub context: Option<ScriptContext>,
}

pub fn build_script_document(
    formula: &Formula,
    method_name: &str,
    identity: Option<&str>,
    resolved: Option<ResolvedScript>,
) -> ScriptDocument {
    let methods = formula.methods.keys().cloned().collect::<Vec<_>>();
    let storage = ScriptStorage {
        key: build_storage_key(&formula.id, Some(method_name), identity),
        formula: formula.id.clone(),
        method: method_name.to_string(),
        identity: identity.map(ToString::to_string),
    };

    let (script, context) = if let Some(resolved) = resolved {
        (resolved.steps, Some(resolved.context))
    } else {
        (
            default_steps(formula.get_method(method_name).expect("method")),
            None,
        )
    };

    ScriptDocument {
        formula: formula.id.clone(),
        methods,
        method: Some(method_name.to_string()),
        script,
        storage,
        context,
    }
}

pub fn resolve_script(
    formula: &Formula,
    method_name: &str,
    client_id_override: Option<&str>,
    client_secret_override: Option<&str>,
    scope_override: Option<&str>,
    redirect_uri: &str,
) -> Result<ResolvedScript> {
    let method = formula
        .get_method(method_name)
        .ok_or_else(|| SchlusselError::MethodNotFound(method_name.to_string()))?;
    let mut replacements = BTreeMap::new();
    let mut context = ScriptContext::default();

    if method.is_authorization_code() {
        let resolved_redirect_uri = if needs_dynamic_redirect_port(redirect_uri) {
            CallbackServer::new(0)?.callback_url()
        } else {
            redirect_uri.to_string()
        };
        let config = config_from_formula(
            formula,
            method_name,
            client_id_override,
            client_secret_override,
            &resolved_redirect_uri,
            scope_override,
        )?;
        let pkce = PkcePair::generate();
        let state = PkcePair::generate().verifier()[..22].to_string();
        let authorize_url = build_authorization_url(
            &config.authorization_endpoint,
            &config.client_id,
            &resolved_redirect_uri,
            config.scope.as_deref(),
            &state,
            pkce.challenge(),
        )?;

        context.redirect_uri = Some(resolved_redirect_uri.clone());
        context.pkce_verifier = Some(pkce.verifier().to_string());
        context.state = Some(state.clone());
        context.authorize_url = Some(authorize_url.clone());

        replacements.insert("redirect_uri", resolved_redirect_uri);
        replacements.insert("pkce_verifier", pkce.verifier().to_string());
        replacements.insert("state", state);
        replacements.insert("authorize_url", authorize_url);
    } else if method.is_device_code() {
        let config = config_from_formula(
            formula,
            method_name,
            client_id_override,
            client_secret_override,
            redirect_uri,
            scope_override,
        )?;
        let client = build_memory_oauth_client(config)?;
        let device = client.request_device_code()?;

        context.device_code = Some(device.device_code.clone());
        context.user_code = Some(device.user_code.clone());
        context.verification_uri = Some(device.verification_uri.clone());
        context.verification_uri_complete = device.verification_uri_complete.clone();
        context.interval = Some(device.interval);
        context.expires_in = Some(device.expires_in);

        replacements.insert("device_code", device.device_code);
        replacements.insert("user_code", device.user_code);
        replacements.insert("verification_uri", device.verification_uri);
        if let Some(verification_uri_complete) = device.verification_uri_complete {
            replacements.insert("verification_uri_complete", verification_uri_complete);
        }
    }

    let steps = default_steps(method)
        .into_iter()
        .map(|step| ScriptStep {
            kind: step.kind,
            value: step
                .value
                .map(|value| expand_template(&value, &replacements)),
            note: step.note.map(|note| expand_template(&note, &replacements)),
        })
        .collect();

    Ok(ResolvedScript { steps, context })
}

pub fn script_json_schema() -> serde_json::Value {
    serde_json::json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "title": "Schlussel Script Document",
        "type": "object",
        "required": ["formula", "methods", "script", "storage"],
        "properties": {
            "formula": { "type": "string" },
            "methods": { "type": "array", "items": { "type": "string" } },
            "method": { "type": "string" },
            "script": {
                "type": "array",
                "items": {
                    "type": "object",
                    "required": ["type"],
                    "properties": {
                        "type": { "type": "string" },
                        "value": { "type": "string" },
                        "note": { "type": "string" }
                    }
                }
            },
            "storage": {
                "type": "object",
                "required": ["key", "formula", "method"],
                "properties": {
                    "key": { "type": "string" },
                    "formula": { "type": "string" },
                    "method": { "type": "string" },
                    "identity": { "type": "string" }
                }
            },
            "context": { "type": "object" }
        }
    })
}

fn default_steps(method: &MethodDef) -> Vec<ScriptStep> {
    if !method.script.is_empty() {
        return method.script.clone();
    }

    if method.is_device_code() {
        vec![
            ScriptStep {
                kind: "open_url".to_string(),
                value: Some("{verification_uri}".to_string()),
                note: None,
            },
            ScriptStep {
                kind: "enter_code".to_string(),
                value: Some("{user_code}".to_string()),
                note: None,
            },
            ScriptStep {
                kind: "wait_for_token".to_string(),
                value: None,
                note: None,
            },
        ]
    } else if method.is_authorization_code() {
        vec![
            ScriptStep {
                kind: "open_url".to_string(),
                value: Some("{authorize_url}".to_string()),
                note: None,
            },
            ScriptStep {
                kind: "wait_for_callback".to_string(),
                value: None,
                note: None,
            },
        ]
    } else {
        vec![ScriptStep {
            kind: "copy_key".to_string(),
            value: None,
            note: Some("Paste your secret into the agent.".to_string()),
        }]
    }
}

fn needs_dynamic_redirect_port(redirect_uri: &str) -> bool {
    redirect_uri.contains(":0/") || redirect_uri.ends_with(":0")
}

fn expand_template(input: &str, replacements: &BTreeMap<&str, String>) -> String {
    let mut output = input.to_string();
    for (key, value) in replacements {
        output = output.replace(&format!("{{{key}}}"), value);
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::formulas::load_from_json_slice;

    #[test]
    fn builds_default_api_key_script() {
        let formula = load_from_json_slice(
            br#"{
              "schema": "v2",
              "id": "linear",
              "label": "Linear",
              "methods": {
                "api_key": {
                  "label": "API Key"
                }
              }
            }"#,
        )
        .expect("formula");

        let document = build_script_document(&formula, "api_key", Some("work"), None);
        assert_eq!(document.storage.key, "linear:api_key:work");
        assert_eq!(document.script[0].kind, "copy_key");
    }
}
