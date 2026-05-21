use std::io::{self, Write};

use anyhow::{anyhow, bail, Result};
use schlussel::callback::CallbackServer;
use schlussel::formulas::{Formula, MethodDef};
use schlussel::oauth::{config_from_formula, OAuthClient};
use schlussel::script::resolve_script;
use schlussel::session::{build_storage_key, FileStorage, MemoryStorage, SessionStorage, Token};
use schlussel::{RefreshLockManager, SchlusselError};

use crate::cli::RunArgs;
use crate::formula_support::{load_formula, resolve_run_inputs, ResolvedRunInputs};
use crate::output::{OutputContext, OutputMode};
use crate::render::{print_dry_run, print_script_steps, print_success};

pub fn execute(args: RunArgs, output: OutputContext) -> Result<()> {
    let formula = load_formula(&args.provider, args.common.formula_json.as_deref(), output)?;
    reject_tuist_formula(&formula)?;

    let inputs = resolve_run_inputs(&formula, &args.common)?;
    let method = formula
        .get_method(&inputs.method_name)
        .ok_or_else(|| anyhow!("unknown method '{}'", inputs.method_name))?;
    let resolved = resolve_script(
        &formula,
        &inputs.method_name,
        inputs.client_id_override.as_deref(),
        inputs.client_secret_override.as_deref(),
        args.common.scope.as_deref(),
        &inputs.redirect_uri,
    )?;
    let storage_key = build_storage_key(
        &formula.id,
        Some(&inputs.method_name),
        args.common.identity.as_deref(),
    );

    print_script_steps(&resolved.steps, output)?;
    if args.dry_run {
        print_dry_run(method, &resolved, &storage_key, output, &mut io::stdout())?;
        return Ok(());
    }

    let token = authorize(&formula, method, &inputs, &args, &resolved)?;
    persist_token(&formula, method, &inputs, &args, &storage_key, &token)?;
    emit_result(&storage_key, &inputs.method_name, &token, output)
}

fn reject_tuist_formula(formula: &Formula) -> Result<()> {
    if formula.id != "tuist" {
        return Ok(());
    }

    bail!(
        "Tuist sessions are managed by Tuist. Run 'tuist auth login' first, then use 'schlussel token get --formula tuist [--identity <server>]'."
    )
}

fn authorize(
    formula: &Formula,
    method: &MethodDef,
    inputs: &ResolvedRunInputs,
    args: &RunArgs,
    resolved: &schlussel::ResolvedScript,
) -> Result<Token> {
    if method.is_device_code() {
        return execute_device_flow(
            formula,
            &inputs.method_name,
            inputs.client_id_override.as_deref(),
            inputs.client_secret_override.as_deref(),
            args.common.scope.as_deref(),
            &inputs.redirect_uri,
            resolved,
            args.open_browser.unwrap_or(true),
        );
    }

    if method.is_authorization_code() {
        return execute_authorization_code_flow(
            formula,
            &inputs.method_name,
            inputs.client_id_override.as_deref(),
            inputs.client_secret_override.as_deref(),
            args.common.scope.as_deref(),
            resolved,
            args.open_browser.unwrap_or(true),
        );
    }

    token_from_manual_credential(
        method.label.as_deref().unwrap_or("credential"),
        &inputs.method_name,
        args.credential.as_deref(),
    )
}

fn persist_token(
    formula: &Formula,
    method: &MethodDef,
    inputs: &ResolvedRunInputs,
    args: &RunArgs,
    storage_key: &str,
    token: &Token,
) -> Result<()> {
    let storage = FileStorage::new("schlussel")?;
    let _ = OAuthClient::new(
        storage_oauth_config(formula, method, inputs, args.common.scope.as_deref())?,
        storage.clone(),
    )?;
    save_token_with_lock(&storage, storage_key, token)
}

fn storage_oauth_config(
    formula: &Formula,
    method: &MethodDef,
    inputs: &ResolvedRunInputs,
    scope_override: Option<&str>,
) -> std::result::Result<schlussel::oauth::OAuthConfig, SchlusselError> {
    config_from_formula(
        formula,
        &inputs.method_name,
        inputs.client_id_override.as_deref(),
        inputs.client_secret_override.as_deref(),
        &inputs.redirect_uri,
        scope_override,
    )
    .or_else(|error| match error {
        SchlusselError::MissingClientId if method.is_api_key() => Ok(manual_api_key_config()),
        _ => Err(error),
    })
}

fn manual_api_key_config() -> schlussel::oauth::OAuthConfig {
    schlussel::oauth::OAuthConfig {
        client_id: "manual".to_string(),
        client_secret: None,
        authorization_endpoint: "http://127.0.0.1/callback".to_string(),
        token_endpoint: "http://127.0.0.1/callback".to_string(),
        redirect_uri: "http://127.0.0.1/callback".to_string(),
        scope: None,
        device_authorization_endpoint: None,
    }
}

fn emit_result(
    storage_key: &str,
    method_name: &str,
    token: &Token,
    output: OutputContext,
) -> Result<()> {
    match output.mode() {
        OutputMode::Json => {
            let payload = serde_json::json!({
                "storage_key": storage_key,
                "method": method_name,
                "token": token,
            });
            println!("{}", serde_json::to_string_pretty(&payload)?);
        }
        _ => print_success(token, storage_key, output)?,
    }

    Ok(())
}

fn execute_device_flow(
    formula: &Formula,
    method_name: &str,
    client_id_override: Option<&str>,
    client_secret_override: Option<&str>,
    scope_override: Option<&str>,
    redirect_uri: &str,
    resolved: &schlussel::ResolvedScript,
    open_browser: bool,
) -> Result<Token> {
    let device_code = resolved
        .context
        .device_code
        .as_deref()
        .ok_or_else(|| anyhow!("script context missing device_code"))?;
    let verification_uri = resolved
        .context
        .verification_uri
        .as_deref()
        .ok_or_else(|| anyhow!("script context missing verification_uri"))?;
    let user_code = resolved
        .context
        .user_code
        .as_deref()
        .ok_or_else(|| anyhow!("script context missing user_code"))?;

    eprintln!();
    eprintln!("To authorize, visit: {verification_uri}");
    eprintln!("And enter code: {user_code}");
    eprintln!();

    if open_browser {
        let uri = resolved
            .context
            .verification_uri_complete
            .as_deref()
            .unwrap_or(verification_uri);
        let _ = schlussel::callback::open_browser(uri);
    }

    let config = config_from_formula(
        formula,
        method_name,
        client_id_override,
        client_secret_override,
        redirect_uri,
        scope_override,
    )?;
    let client = OAuthClient::new(config, MemoryStorage::new())?;
    client
        .poll_device_code(
            device_code,
            resolved.context.interval.unwrap_or(5),
            resolved.context.expires_in,
        )
        .map_err(Into::into)
}

fn execute_authorization_code_flow(
    formula: &Formula,
    method_name: &str,
    client_id_override: Option<&str>,
    client_secret_override: Option<&str>,
    scope_override: Option<&str>,
    resolved: &schlussel::ResolvedScript,
    open_browser: bool,
) -> Result<Token> {
    let authorize_url = resolved
        .context
        .authorize_url
        .as_deref()
        .ok_or_else(|| anyhow!("script context missing authorize_url"))?;
    let pkce_verifier = resolved
        .context
        .pkce_verifier
        .as_deref()
        .ok_or_else(|| anyhow!("script context missing pkce_verifier"))?;
    let state = resolved
        .context
        .state
        .as_deref()
        .ok_or_else(|| anyhow!("script context missing state"))?;
    let redirect_uri = resolved
        .context
        .redirect_uri
        .as_deref()
        .ok_or_else(|| anyhow!("script context missing redirect_uri"))?;

    let server = CallbackServer::new(parse_redirect_port(redirect_uri)?)?;

    eprintln!();
    if open_browser {
        eprintln!("Opening browser for authorization...");
        eprintln!("If the browser does not open, visit:");
        eprintln!("{authorize_url}");
        eprintln!();
        let _ = schlussel::callback::open_browser(authorize_url);
    } else {
        eprintln!("Visit the following URL to authorize:");
        eprintln!("{authorize_url}");
        eprintln!();
    }

    let callback = server.wait_for_callback(120)?;
    if callback.state.as_deref() != Some(state) {
        bail!("invalid OAuth state");
    }
    if callback.error_code.is_some() {
        bail!("authorization denied");
    }
    let code = callback
        .code
        .ok_or_else(|| anyhow!("callback did not include an authorization code"))?;

    let config = config_from_formula(
        formula,
        method_name,
        client_id_override,
        client_secret_override,
        redirect_uri,
        scope_override,
    )?;
    let client = OAuthClient::new(config, MemoryStorage::new())?;
    client
        .exchange_code(&code, pkce_verifier, redirect_uri)
        .map_err(Into::into)
}

fn token_from_manual_credential(
    label: &str,
    method_name: &str,
    credential: Option<&str>,
) -> Result<Token> {
    let secret = if let Some(credential) = credential {
        credential.to_string()
    } else {
        eprint!("\nEnter {label}: ");
        io::stderr().flush()?;
        let mut buffer = String::new();
        io::stdin().read_line(&mut buffer)?;
        let value = buffer.trim();
        if value.is_empty() {
            bail!("credential cannot be empty");
        }
        value.to_string()
    };

    Ok(Token::new(secret, method_name))
}

fn save_token_with_lock(storage: &FileStorage, key: &str, token: &Token) -> Result<()> {
    let manager = RefreshLockManager::new("schlussel")?;
    let mut lock = manager.acquire(key)?;
    storage.save(key, token)?;
    lock.release()?;
    Ok(())
}

fn parse_redirect_port(redirect_uri: &str) -> Result<u16> {
    let url = url::Url::parse(redirect_uri)?;
    url.port_or_known_default()
        .ok_or_else(|| anyhow!("redirect URI is missing a port"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_redirect_port() {
        let port = parse_redirect_port("http://127.0.0.1:43123/callback").expect("port");
        assert_eq!(port, 43123);
    }
}
