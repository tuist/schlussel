use std::path::Path;

use anyhow::{anyhow, bail, Context, Result};
use schlussel::formulas::{find_builtin, load_from_path, Client, Formula};

use crate::cli::CommonFormulaArgs;
use crate::output::{render_warning, OutputContext};

pub struct ResolvedRunInputs {
    pub selected_client: Option<Client>,
    pub client_id_override: Option<String>,
    pub client_secret_override: Option<String>,
    pub redirect_uri: String,
    pub method_name: String,
}

impl ResolvedRunInputs {
    fn new(args: &CommonFormulaArgs) -> Self {
        Self {
            selected_client: None,
            client_id_override: args.client_id.clone(),
            client_secret_override: args.client_secret.clone(),
            redirect_uri: args.redirect_uri.clone(),
            method_name: String::new(),
        }
    }

    fn apply_client(&mut self, client: Client, args: &CommonFormulaArgs) {
        if self.client_id_override.is_none() {
            self.client_id_override = Some(client.id.clone());
        }
        if self.client_secret_override.is_none() {
            self.client_secret_override = client.secret.clone();
        }
        if uses_default_redirect_uri(args) {
            if let Some(redirect_uri) = &client.redirect_uri {
                self.redirect_uri = redirect_uri.clone();
            }
        }
        self.selected_client = Some(client);
    }
}

pub fn load_formula(provider: &str, path: Option<&Path>, output: OutputContext) -> Result<Formula> {
    if let Some(path) = path {
        let formula = load_from_path(path)
            .with_context(|| format!("failed to load formula JSON from {}", path.display()))?;
        if formula.id != provider {
            render_warning(
                &format!(
                    "formula id '{}' does not match provider '{}'",
                    formula.id, provider
                ),
                output,
            );
        }
        return Ok(formula);
    }

    find_builtin(provider).ok_or_else(|| anyhow!("unknown provider '{provider}'"))
}

pub fn resolve_run_inputs(
    formula: &Formula,
    args: &CommonFormulaArgs,
) -> Result<ResolvedRunInputs> {
    let mut inputs = ResolvedRunInputs::new(args);

    match args.client.as_deref() {
        Some(client_name) => {
            let client = formula
                .get_client_by_name(client_name)
                .cloned()
                .ok_or_else(|| anyhow!("unknown client '{client_name}'"))?;
            inputs.apply_client(client, args);
        }
        None if inputs.client_id_override.is_none() => {
            if let Some(client) = formula.get_default_client() {
                inputs.apply_client(client.clone(), args);
            }
        }
        None => {}
    }

    inputs.method_name = choose_method(
        formula,
        inputs.selected_client.as_ref(),
        args.method.as_deref(),
    )?;
    validate_client_method_support(inputs.selected_client.as_ref(), &inputs.method_name)?;
    Ok(inputs)
}

fn choose_method(
    formula: &Formula,
    selected_client: Option<&Client>,
    requested: Option<&str>,
) -> Result<String> {
    if let Some(method) = requested {
        if formula.get_method(method).is_none() {
            bail!(
                "unknown method '{}'. Available methods: {}",
                method,
                formula.method_names().join(", ")
            );
        }
        return Ok(method.to_string());
    }

    let compatible_methods = formula
        .methods
        .keys()
        .filter(|method| {
            selected_client.is_none_or(|client| client_supports_method(client, method))
        })
        .cloned()
        .collect::<Vec<_>>();

    match compatible_methods.as_slice() {
        [method] => Ok(method.clone()),
        [] => bail!("no methods available for the selected client"),
        _ => bail!(
            "--method is required when multiple methods are available: {}",
            compatible_methods.join(", ")
        ),
    }
}

fn validate_client_method_support(
    selected_client: Option<&Client>,
    method_name: &str,
) -> Result<()> {
    let Some(client) = selected_client else {
        return Ok(());
    };

    if client_supports_method(client, method_name) {
        return Ok(());
    }

    bail!(
        "client '{}' does not support method '{}'",
        client.name,
        method_name
    )
}

fn client_supports_method(client: &Client, method: &str) -> bool {
    client.methods.is_empty() || client.methods.iter().any(|supported| supported == method)
}

fn uses_default_redirect_uri(args: &CommonFormulaArgs) -> bool {
    args.redirect_uri == "http://127.0.0.1:0/callback"
}
