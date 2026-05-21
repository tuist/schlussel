use std::io::{self, IsTerminal, Write};
use std::path::{Path, PathBuf};

use anyhow::{anyhow, bail, Context, Result};
use clap::{Args, Parser, Subcommand};
use schlussel::callback::CallbackServer;
use schlussel::formulas::{
    find_builtin, list_builtin, load_from_path, Client, Formula, ScriptStep,
};
use schlussel::oauth::{config_from_formula, OAuthClient};
use schlussel::script::{build_script_document, resolve_script, script_json_schema};
use schlussel::session::{
    build_storage_key, parse_storage_key, FileStorage, MemoryStorage, SessionStorage, Token,
};
use schlussel::{RefreshLockManager, SchlusselError};

mod tuist;

use tuist::{host_matches_identity, normalize_server_url, TuistSessionStore};

#[derive(Parser, Debug)]
#[command(
    name = "schlussel",
    version,
    about = "Formula-driven OAuth runtime for agents and CLI apps"
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    Run(RunArgs),
    Formula(FormulaArgs),
    Token(TokenArgs),
    Script(ScriptArgs),
}

#[derive(Args, Debug)]
struct CommonFormulaArgs {
    #[arg(long)]
    formula_json: Option<PathBuf>,
    #[arg(short = 'm', long)]
    method: Option<String>,
    #[arg(short = 'c', long)]
    client: Option<String>,
    #[arg(long)]
    client_id: Option<String>,
    #[arg(long)]
    client_secret: Option<String>,
    #[arg(long)]
    scope: Option<String>,
    #[arg(long, default_value = "http://127.0.0.1:0/callback")]
    redirect_uri: String,
    #[arg(short = 'i', long)]
    identity: Option<String>,
}

#[derive(Args, Debug)]
struct RunArgs {
    provider: String,
    #[command(flatten)]
    common: CommonFormulaArgs,
    #[arg(long)]
    credential: Option<String>,
    #[arg(long, value_name = "true|false")]
    open_browser: Option<bool>,
    #[arg(short = 'n', long)]
    dry_run: bool,
    #[arg(long)]
    json: bool,
}

#[derive(Args, Debug)]
struct FormulaArgs {
    #[command(subcommand)]
    action: FormulaAction,
}

#[derive(Subcommand, Debug)]
enum FormulaAction {
    List {
        #[arg(long)]
        json: bool,
    },
    Show {
        provider: String,
        #[arg(long)]
        formula_json: Option<PathBuf>,
        #[arg(long)]
        json: bool,
    },
}

#[derive(Args, Debug)]
struct TokenArgs {
    #[command(subcommand)]
    action: TokenAction,
}

#[derive(Subcommand, Debug)]
enum TokenAction {
    Get(TokenKeyArgs),
    List(TokenListArgs),
    Delete(TokenKeyArgs),
}

#[derive(Args, Debug)]
struct TokenKeyArgs {
    #[arg(long)]
    key: Option<String>,
    #[arg(long)]
    formula: Option<String>,
    #[arg(long)]
    formula_json: Option<PathBuf>,
    #[arg(long)]
    method: Option<String>,
    #[arg(long)]
    identity: Option<String>,
    #[arg(long)]
    no_refresh: bool,
    #[arg(long)]
    json: bool,
}

#[derive(Args, Debug)]
struct TokenListArgs {
    #[arg(long)]
    key: Option<String>,
    #[arg(long)]
    formula: Option<String>,
    #[arg(long)]
    formula_json: Option<PathBuf>,
    #[arg(long)]
    method: Option<String>,
    #[arg(long)]
    identity: Option<String>,
    #[arg(long)]
    json: bool,
}

#[derive(Args, Debug)]
struct ScriptArgs {
    provider: Option<String>,
    #[command(flatten)]
    common: CommonFormulaArgs,
    #[arg(long)]
    resolve: bool,
    #[arg(long)]
    json_schema: bool,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Commands::Run(args) => cmd_run(args),
        Commands::Formula(args) => cmd_formula(args),
        Commands::Token(args) => cmd_token(args),
        Commands::Script(args) => cmd_script(args),
    }
}

fn cmd_run(args: RunArgs) -> Result<()> {
    let open_browser = args.open_browser.unwrap_or(true);
    let formula = load_formula(&args.provider, args.common.formula_json.as_deref())?;
    if formula.id == "tuist" {
        bail!(
            "Tuist sessions are managed by Tuist. Run 'tuist auth login' first, then use 'schlussel token get --formula tuist [--identity <server>]'."
        );
    }
    let (selected_client, client_id_override, client_secret_override, redirect_uri, method_name) =
        resolve_run_inputs(&formula, &args.common)?;

    let method = formula
        .get_method(&method_name)
        .ok_or_else(|| anyhow!("unknown method '{method_name}'"))?;
    let resolved = resolve_script(
        &formula,
        &method_name,
        client_id_override.as_deref(),
        client_secret_override.as_deref(),
        args.common.scope.as_deref(),
        &redirect_uri,
    )?;
    let storage_key = build_storage_key(
        &formula.id,
        Some(&method_name),
        args.common.identity.as_deref(),
    );
    let use_color = colors_enabled() && !args.json;
    print_script_steps(&resolved.steps, use_color, args.json)?;

    if args.dry_run {
        print_dry_run(
            method,
            &resolved,
            &storage_key,
            args.json,
            use_color,
            &mut io::stdout(),
        )?;
        return Ok(());
    }

    let storage = FileStorage::new("schlussel")?;
    let token = if method.is_device_code() {
        execute_device_flow(
            &formula,
            &method_name,
            client_id_override.as_deref(),
            client_secret_override.as_deref(),
            args.common.scope.as_deref(),
            &redirect_uri,
            &resolved,
            open_browser,
        )?
    } else if method.is_authorization_code() {
        execute_authorization_code_flow(
            &formula,
            &method_name,
            client_id_override.as_deref(),
            client_secret_override.as_deref(),
            args.common.scope.as_deref(),
            &resolved,
            open_browser,
        )?
    } else {
        token_from_manual_credential(
            method.label.as_deref().unwrap_or("credential"),
            &method_name,
            args.credential.as_deref(),
        )?
    };

    let _client = OAuthClient::new(
        config_from_formula(
            &formula,
            &method_name,
            client_id_override.as_deref(),
            client_secret_override.as_deref(),
            &redirect_uri,
            args.common.scope.as_deref(),
        )
        .or_else(|error| match error {
            SchlusselError::MissingClientId => {
                if method.is_api_key() {
                    Ok(schlussel::oauth::OAuthConfig {
                        client_id: "manual".to_string(),
                        client_secret: None,
                        authorization_endpoint: "http://127.0.0.1/callback".to_string(),
                        token_endpoint: "http://127.0.0.1/callback".to_string(),
                        redirect_uri: "http://127.0.0.1/callback".to_string(),
                        scope: None,
                        device_authorization_endpoint: None,
                    })
                } else {
                    Err(error)
                }
            }
            _ => Err(error),
        })?,
        storage.clone(),
    )?;
    save_token_with_lock(&storage, &storage_key, &token)?;

    if args.json {
        let payload = serde_json::json!({
            "storage_key": storage_key,
            "method": method_name,
            "token": token,
        });
        println!("{}", serde_json::to_string_pretty(&payload)?);
    } else {
        print_success(&token, &storage_key, use_color)?;
    }

    let _ = selected_client;

    Ok(())
}

fn cmd_formula(args: FormulaArgs) -> Result<()> {
    match args.action {
        FormulaAction::List { json } => {
            let formulas = list_builtin();
            if json {
                println!("{}", serde_json::to_string_pretty(&formulas)?);
            } else {
                println!("Available formulas:");
                for formula in formulas {
                    println!("  {} - {}", formula.id, formula.label);
                }
            }
        }
        FormulaAction::Show {
            provider,
            formula_json,
            json,
        } => {
            let formula = load_formula(&provider, formula_json.as_deref())?;
            if json {
                println!("{}", serde_json::to_string_pretty(&formula)?);
            } else {
                println!();
                println!("{}", formula.label);
                println!("ID: {}", formula.id);
                if let Some(identity) = &formula.identity {
                    if let Some(label) = &identity.label {
                        match &identity.hint {
                            Some(hint) => println!("\nIdentity: {} ({hint})", label),
                            None => println!("\nIdentity: {label}"),
                        }
                    }
                }

                println!("\nMethods:");
                for (name, method) in &formula.methods {
                    let label = method.label.as_deref().unwrap_or(name);
                    let kind = if method.is_device_code() {
                        "device code"
                    } else if method.is_authorization_code() {
                        "authorization code"
                    } else {
                        "manual"
                    };
                    println!("  - {label} ({kind})");
                }

                println!("\nAPIs:");
                for (name, api) in &formula.apis {
                    let methods = if api.methods.is_empty() {
                        "unspecified".to_string()
                    } else {
                        api.methods.join(", ")
                    };
                    println!("  - {name}: {}", api.base_url);
                    println!("    Methods: {methods}");
                }

                if !formula.clients.is_empty() {
                    println!("\nPublic Clients:");
                    for client in &formula.clients {
                        match &client.source {
                            Some(source) => println!("  - {} (from {source})", client.name),
                            None => println!("  - {}", client.name),
                        }
                    }
                }
            }
        }
    }
    Ok(())
}

fn cmd_token(args: TokenArgs) -> Result<()> {
    match args.action {
        TokenAction::Get(options) => {
            if options.key.is_none() && is_tuist_formula(options.formula.as_deref()) {
                ensure_tuist_method(options.method.as_deref())?;
                let store = TuistSessionStore::new()?;
                let server_url = normalize_server_url(options.identity.as_deref())?;
                let token = if options.no_refresh {
                    store
                        .load_token(&server_url)?
                        .ok_or_else(|| anyhow!("token not found for server URL '{server_url}'"))?
                } else {
                    store.get_valid_token(&server_url)?
                };

                if options.json {
                    println!(
                        "{}",
                        serde_json::to_string_pretty(&serde_json::json!({
                            "formula": "tuist",
                            "method": "session",
                            "server_url": server_url,
                            "token": token
                        }))?
                    );
                } else {
                    println!("{}", token.access_token);
                }
                return Ok(());
            }

            let storage = FileStorage::new("schlussel")?;
            let key = resolve_token_key(
                options.key.as_deref(),
                options.formula.as_deref(),
                options.method.as_deref(),
                options.identity.as_deref(),
            )?;
            let mut token = storage
                .load(&key)?
                .ok_or_else(|| anyhow!("token not found for key '{key}'"))?;

            if !options.no_refresh && token.refresh_token.is_some() && token.expires_within(300) {
                let manager = RefreshLockManager::new("schlussel")?;
                let mut lock = manager.acquire(&key)?;
                let fresh = storage
                    .load(&key)?
                    .ok_or_else(|| anyhow!("token not found for key '{key}'"))?;
                token = if fresh.refresh_token.is_some() && fresh.expires_within(300) {
                    refresh_stored_token(&storage, &key, fresh, options.formula_json.as_deref())?
                } else {
                    fresh
                };
                lock.release()?;
            }

            if options.json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(
                        &serde_json::json!({ "key": key, "token": token })
                    )?
                );
            } else {
                println!("{}", token.access_token);
            }
        }
        TokenAction::List(options) => {
            if options.key.is_none() && is_tuist_formula(options.formula.as_deref()) {
                ensure_tuist_method(options.method.as_deref())?;
                let store = TuistSessionStore::new()?;
                let hosts = store
                    .list_hosts()?
                    .into_iter()
                    .filter(|host| host_matches_identity(host, options.identity.as_deref()))
                    .collect::<Vec<_>>();

                if options.json {
                    let items = hosts
                        .iter()
                        .map(|host| {
                            serde_json::json!({
                                "formula": "tuist",
                                "method": "session",
                                "host": host,
                            })
                        })
                        .collect::<Vec<_>>();
                    println!("{}", serde_json::to_string_pretty(&items)?);
                } else if hosts.is_empty() {
                    println!("No Tuist sessions found");
                } else {
                    println!("Tuist sessions:");
                    for host in hosts {
                        println!("  {host}");
                    }
                }
                return Ok(());
            }

            let storage = FileStorage::new("schlussel")?;
            let keys = storage
                .list_keys()?
                .into_iter()
                .filter(|key| {
                    options
                        .key
                        .as_ref()
                        .is_none_or(|prefix| key.starts_with(prefix))
                        && key_matches_filter(
                            key,
                            options.formula.as_deref(),
                            options.method.as_deref(),
                            options.identity.as_deref(),
                        )
                })
                .collect::<Vec<_>>();

            if options.json {
                let items = keys
                    .iter()
                    .map(|key| {
                        let parsed = parse_storage_key(key);
                        serde_json::json!({
                            "key": key,
                            "formula": parsed.formula,
                            "method": parsed.method,
                            "identity": parsed.identity,
                        })
                    })
                    .collect::<Vec<_>>();
                println!("{}", serde_json::to_string_pretty(&items)?);
            } else if keys.is_empty() {
                println!("No tokens found");
            } else {
                println!("Stored tokens:");
                for key in keys {
                    let parsed = parse_storage_key(&key);
                    match parsed.identity {
                        Some(identity) => println!("  {key} (identity: {identity})"),
                        None => println!("  {key}"),
                    }
                }
            }
        }
        TokenAction::Delete(options) => {
            if options.key.is_none() && is_tuist_formula(options.formula.as_deref()) {
                ensure_tuist_method(options.method.as_deref())?;
                let store = TuistSessionStore::new()?;
                let server_url = normalize_server_url(options.identity.as_deref())?;
                store.delete_token(&server_url)?;
                if options.json {
                    println!(
                        "{}",
                        serde_json::to_string_pretty(
                            &serde_json::json!({ "deleted": server_url })
                        )?
                    );
                } else {
                    println!("Tuist session deleted: {server_url}");
                }
                return Ok(());
            }

            let storage = FileStorage::new("schlussel")?;
            let key = resolve_token_key(
                options.key.as_deref(),
                options.formula.as_deref(),
                options.method.as_deref(),
                options.identity.as_deref(),
            )?;
            storage.delete(&key)?;
            if options.json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&serde_json::json!({ "deleted": key }))?
                );
            } else {
                println!("Token deleted: {key}");
            }
        }
    }

    Ok(())
}

fn is_tuist_formula(formula: Option<&str>) -> bool {
    matches!(formula, Some("tuist"))
}

fn ensure_tuist_method(method: Option<&str>) -> Result<()> {
    if method.is_none_or(|method| method == "session") {
        Ok(())
    } else {
        bail!("Tuist only supports the 'session' method")
    }
}

fn cmd_script(args: ScriptArgs) -> Result<()> {
    if args.json_schema {
        println!("{}", serde_json::to_string_pretty(&script_json_schema())?);
        return Ok(());
    }

    let provider = args
        .provider
        .as_deref()
        .ok_or_else(|| anyhow!("missing provider name"))?;
    let formula = load_formula(provider, args.common.formula_json.as_deref())?;
    let (_, client_id_override, client_secret_override, redirect_uri, method_name) =
        resolve_run_inputs(&formula, &args.common)?;
    let resolved = if args.resolve {
        Some(resolve_script(
            &formula,
            &method_name,
            client_id_override.as_deref(),
            client_secret_override.as_deref(),
            args.common.scope.as_deref(),
            &redirect_uri,
        )?)
    } else {
        None
    };

    let document = build_script_document(
        &formula,
        &method_name,
        args.common.identity.as_deref(),
        resolved,
    );
    println!("{}", serde_json::to_string_pretty(&document)?);
    Ok(())
}

fn load_formula(provider: &str, path: Option<&Path>) -> Result<Formula> {
    if let Some(path) = path {
        let formula = load_from_path(path)
            .with_context(|| format!("failed to load formula JSON from {}", path.display()))?;
        if formula.id != provider {
            eprintln!(
                "Warning: formula id '{}' does not match provider '{}'",
                formula.id, provider
            );
        }
        Ok(formula)
    } else {
        find_builtin(provider).ok_or_else(|| anyhow!("unknown provider '{provider}'"))
    }
}

fn resolve_run_inputs(
    formula: &Formula,
    args: &CommonFormulaArgs,
) -> Result<(
    Option<Client>,
    Option<String>,
    Option<String>,
    String,
    String,
)> {
    let mut selected_client = None;
    let mut client_id_override = args.client_id.clone();
    let mut client_secret_override = args.client_secret.clone();
    let mut redirect_uri = args.redirect_uri.clone();

    if let Some(client_name) = &args.client {
        let client = formula
            .get_client_by_name(client_name)
            .cloned()
            .ok_or_else(|| anyhow!("unknown client '{client_name}'"))?;
        if client_id_override.is_none() {
            client_id_override = Some(client.id.clone());
        }
        if client_secret_override.is_none() {
            client_secret_override = client.secret.clone();
        }
        if args.redirect_uri == "http://127.0.0.1:0/callback" {
            if let Some(client_redirect_uri) = &client.redirect_uri {
                redirect_uri = client_redirect_uri.clone();
            }
        }
        selected_client = Some(client);
    } else if client_id_override.is_none() {
        if let Some(client) = formula.get_default_client() {
            if client_id_override.is_none() {
                client_id_override = Some(client.id.clone());
            }
            if client_secret_override.is_none() {
                client_secret_override = client.secret.clone();
            }
            if args.redirect_uri == "http://127.0.0.1:0/callback" {
                if let Some(client_redirect_uri) = &client.redirect_uri {
                    redirect_uri = client_redirect_uri.clone();
                }
            }
            selected_client = Some(client.clone());
        }
    }

    let method_name = choose_method(formula, selected_client.as_ref(), args.method.as_deref())?;
    if let Some(client) = &selected_client {
        if !client_supports_method(client, &method_name) {
            bail!(
                "client '{}' does not support method '{}'",
                client.name,
                method_name
            );
        }
    }

    Ok((
        selected_client,
        client_id_override,
        client_secret_override,
        redirect_uri,
        method_name,
    ))
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

    let compatible = formula
        .methods
        .keys()
        .filter(|method| {
            selected_client.is_none_or(|client| client_supports_method(client, method))
        })
        .cloned()
        .collect::<Vec<_>>();

    match compatible.as_slice() {
        [method] => Ok(method.clone()),
        [] => bail!("no methods available for the selected client"),
        _ => bail!(
            "--method is required when multiple methods are available: {}",
            compatible.join(", ")
        ),
    }
}

fn client_supports_method(client: &Client, method: &str) -> bool {
    client.methods.is_empty() || client.methods.iter().any(|supported| supported == method)
}

fn print_script_steps(steps: &[ScriptStep], use_color: bool, json_output: bool) -> Result<()> {
    if steps.is_empty() {
        return Ok(());
    }

    let mut stdout = io::stdout();
    if json_output {
        return Ok(());
    }

    if use_color {
        writeln!(stdout, "\n\x1b[1mScript steps:\x1b[0m")?;
    } else {
        writeln!(stdout, "\nScript steps:")?;
    }

    for (index, step) in steps.iter().enumerate() {
        let friendly = friendly_step_name(&step.kind);
        match &step.note {
            Some(note) => writeln!(stdout, "  {}. {} ({note})", index + 1, friendly)?,
            None => writeln!(stdout, "  {}. {}", index + 1, friendly)?,
        }
    }

    Ok(())
}

fn print_dry_run(
    method: &schlussel::formulas::MethodDef,
    resolved: &schlussel::ResolvedScript,
    storage_key: &str,
    json_output: bool,
    use_color: bool,
    writer: &mut impl io::Write,
) -> Result<()> {
    if json_output {
        let payload = serde_json::json!({
            "dry_run": true,
            "storage_key": storage_key,
            "script": resolved,
        });
        writeln!(writer, "{}", serde_json::to_string_pretty(&payload)?)?;
        return Ok(());
    }

    if method.is_device_code() {
        writeln!(writer, "\n[DRY RUN] Would authorize via device code:")?;
        writeln!(
            writer,
            "  Verification URL: {}",
            resolved
                .context
                .verification_uri
                .as_deref()
                .unwrap_or("<missing>")
        )?;
        writeln!(
            writer,
            "  User code: {}",
            resolved.context.user_code.as_deref().unwrap_or("<missing>")
        )?;
    } else if method.is_authorization_code() {
        writeln!(writer, "\n[DRY RUN] Would authorize via browser:")?;
        writeln!(
            writer,
            "  Authorization URL: {}",
            resolved
                .context
                .authorize_url
                .as_deref()
                .unwrap_or("<missing>")
        )?;
    } else if use_color {
        writeln!(
            writer,
            "\n\x1b[1;33m[DRY RUN]\x1b[0m Would prompt for a credential"
        )?;
    } else {
        writeln!(writer, "\n[DRY RUN] Would prompt for a credential")?;
    }

    writeln!(writer, "\nToken would be saved with key: {storage_key}")?;
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
        if let Some(verification_uri_complete) = &resolved.context.verification_uri_complete {
            let _ = schlussel::callback::open_browser(verification_uri_complete);
        } else {
            let _ = schlussel::callback::open_browser(verification_uri);
        }
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
    Ok(client.poll_device_code(
        device_code,
        resolved.context.interval.unwrap_or(5),
        resolved.context.expires_in,
    )?)
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

    let port = parse_redirect_port(redirect_uri)?;
    let server = CallbackServer::new(port)?;

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
        io::Write::flush(&mut io::stderr())?;
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

fn print_success(token: &Token, storage_key: &str, use_color: bool) -> Result<()> {
    if use_color {
        println!("\n\x1b[1;32m=== Authorization Successful! ===\x1b[0m");
    } else {
        println!("\n=== Authorization Successful! ===");
    }
    println!();
    println!("Token type: {}", token.token_type);
    if let Some(scope) = &token.scope {
        println!("Scope: {scope}");
    }
    if let Some(expires_at) = token.expires_at {
        println!("Expires at: {expires_at} (Unix timestamp)");
    }
    println!("\nToken saved with key: {storage_key}");
    Ok(())
}

fn resolve_token_key(
    key: Option<&str>,
    formula: Option<&str>,
    method: Option<&str>,
    identity: Option<&str>,
) -> Result<String> {
    if let Some(key) = key {
        Ok(key.to_string())
    } else if let Some(formula) = formula {
        Ok(build_storage_key(formula, method, identity))
    } else {
        bail!("either --key or --formula is required")
    }
}

fn refresh_stored_token(
    storage: &FileStorage,
    key: &str,
    token: Token,
    formula_json: Option<&Path>,
) -> Result<Token> {
    let refresh_token = token
        .refresh_token
        .clone()
        .ok_or(SchlusselError::NoRefreshToken)?;
    let parsed = parse_storage_key(key);
    let method_name = parsed.method.as_deref().unwrap_or("oauth");
    let formula = if let Some(path) = formula_json {
        load_formula(&parsed.formula, Some(path))?
    } else {
        find_builtin(&parsed.formula)
            .ok_or_else(|| anyhow!("unknown formula '{}'", parsed.formula))?
    };
    let config = config_from_formula(
        &formula,
        method_name,
        None,
        None,
        "http://127.0.0.1:0/callback",
        None,
    )?;
    let client = OAuthClient::new(config, MemoryStorage::new())?;
    let mut new_token = client.refresh_token(&refresh_token)?;
    if new_token.refresh_token.is_none() {
        new_token.refresh_token = Some(refresh_token);
    }
    storage.save(key, &new_token)?;
    Ok(new_token)
}

fn save_token_with_lock(storage: &FileStorage, key: &str, token: &Token) -> Result<()> {
    let manager = RefreshLockManager::new("schlussel")?;
    let mut lock = manager.acquire(key)?;
    storage.save(key, token)?;
    lock.release()?;
    Ok(())
}

fn key_matches_filter(
    key: &str,
    formula_filter: Option<&str>,
    method_filter: Option<&str>,
    identity_filter: Option<&str>,
) -> bool {
    let parsed = parse_storage_key(key);
    formula_filter.is_none_or(|formula| parsed.formula == formula)
        && method_filter.is_none_or(|method| parsed.method.as_deref() == Some(method))
        && identity_filter.is_none_or(|identity| parsed.identity.as_deref() == Some(identity))
}

fn parse_redirect_port(redirect_uri: &str) -> Result<u16> {
    let url = url::Url::parse(redirect_uri)?;
    url.port_or_known_default()
        .ok_or_else(|| anyhow!("redirect URI is missing a port"))
}

fn friendly_step_name(step_type: &str) -> &str {
    match step_type {
        "open_url" => "Open the authorization URL",
        "enter_code" => "Enter the displayed code",
        "wait_for_token" => "Wait for the token to be issued",
        "wait_for_callback" => "Wait for the OAuth callback",
        "copy_key" => "Copy or paste the credential",
        _ => step_type,
    }
}

fn colors_enabled() -> bool {
    std::env::var_os("NO_COLOR").is_none() && io::stdout().is_terminal()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_redirect_port() {
        let port = parse_redirect_port("http://127.0.0.1:43123/callback").expect("port");
        assert_eq!(port, 43123);
    }

    #[test]
    fn token_key_filters_match_components() {
        assert!(key_matches_filter(
            "github:device_code:personal",
            Some("github"),
            Some("device_code"),
            Some("personal"),
        ));
        assert!(!key_matches_filter(
            "github:device_code:personal",
            Some("github"),
            Some("oauth"),
            Some("personal"),
        ));
    }
}
