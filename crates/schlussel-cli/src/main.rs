use std::io::{self, Write};
use std::path::{Path, PathBuf};

use anyhow::{anyhow, bail, Context, Result};
use clap::{Args, Parser, Subcommand};
use output::{clap_styles, render_error, render_warning, OutputArgs, OutputContext, OutputMode};
use schlussel::callback::CallbackServer;
use schlussel::formulas::{
    find_builtin, list_builtin, load_from_path, Client, Formula, FormulaInfo, ScriptStep,
};
use schlussel::oauth::{config_from_formula, OAuthClient};
use schlussel::script::{
    build_script_document, resolve_script, script_json_schema, ScriptDocument,
};
use schlussel::session::{
    build_storage_key, parse_storage_key, FileStorage, MemoryStorage, SessionStorage, Token,
};
use schlussel::{RefreshLockManager, SchlusselError};
use serde::Serialize;

mod output;
mod tuist;

use tuist::{host_matches_identity, normalize_server_url, TuistSessionStore};

const ROOT_AFTER_HELP: &str = "\
Examples:
  schlussel run github --method device_code --identity personal
  schlussel token list --format toon
  schlussel token get --formula github --method device_code --identity personal
  schlussel script github --method device_code --resolve --format json";

#[derive(Parser, Debug)]
#[command(
    name = "schlussel",
    version,
    about = "Formula-driven OAuth runtime for agents and CLI apps",
    arg_required_else_help = true,
    styles = clap_styles(),
    after_help = ROOT_AFTER_HELP
)]
struct Cli {
    #[command(flatten)]
    output: OutputArgs,
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Authenticate with a provider and store the resulting token
    Run(RunArgs),
    /// Inspect bundled OAuth formulas
    Formula(FormulaArgs),
    /// List, read, and delete stored tokens and Tuist sessions
    Token(TokenArgs),
    /// Emit a script document for agent workflows
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
    /// Built-in provider ID or the ID of the supplied formula JSON
    provider: String,
    #[command(flatten)]
    common: CommonFormulaArgs,
    #[arg(long)]
    credential: Option<String>,
    #[arg(long, value_name = "true|false")]
    open_browser: Option<bool>,
    #[arg(short = 'n', long)]
    dry_run: bool,
}

#[derive(Args, Debug)]
struct FormulaArgs {
    #[command(subcommand)]
    action: FormulaAction,
}

#[derive(Subcommand, Debug)]
enum FormulaAction {
    List,
    Show {
        /// Built-in provider ID or the ID of the supplied formula JSON
        provider: String,
        #[arg(long)]
        formula_json: Option<PathBuf>,
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

fn main() {
    let cli = Cli::parse();
    let output = OutputContext::new(cli.output.mode());
    let result = match cli.command {
        Commands::Run(args) => cmd_run(args, output),
        Commands::Formula(args) => cmd_formula(args, output),
        Commands::Token(args) => cmd_token(args, output),
        Commands::Script(args) => cmd_script(args, output),
    };

    if let Err(error) = result {
        if is_broken_pipe(&error) {
            return;
        }
        render_error(&error, output);
        std::process::exit(1);
    }
}

fn cmd_run(args: RunArgs, output: OutputContext) -> Result<()> {
    let open_browser = args.open_browser.unwrap_or(true);
    let formula = load_formula(&args.provider, args.common.formula_json.as_deref(), output)?;
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
    print_script_steps(&resolved.steps, output)?;

    if args.dry_run {
        print_dry_run(method, &resolved, &storage_key, output, &mut io::stdout())?;
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

    match output.mode() {
        OutputMode::Json => {
            let payload = serde_json::json!({
                "storage_key": storage_key,
                "method": method_name,
                "token": token,
            });
            println!("{}", serde_json::to_string_pretty(&payload)?);
        }
        _ => print_success(&token, &storage_key, output)?,
    }

    let _ = selected_client;

    Ok(())
}

fn cmd_formula(args: FormulaArgs, output: OutputContext) -> Result<()> {
    match args.action {
        FormulaAction::List => {
            let formulas = list_builtin();
            if output.mode() == OutputMode::Json {
                println!("{}", serde_json::to_string_pretty(&formulas)?);
            } else {
                print_formula_list(formulas, output)?;
            }
        }
        FormulaAction::Show {
            provider,
            formula_json,
        } => {
            let formula = load_formula(&provider, formula_json.as_deref(), output)?;
            if output.mode() == OutputMode::Json {
                println!("{}", serde_json::to_string_pretty(&formula)?);
            } else {
                print_formula_details(&formula, output)?;
            }
        }
    }
    Ok(())
}

fn cmd_token(args: TokenArgs, output: OutputContext) -> Result<()> {
    match args.action {
        TokenAction::Get(options) => {
            let target = resolve_token_target(
                options.key.as_deref(),
                options.formula.as_deref(),
                options.method.as_deref(),
                options.identity.as_deref(),
            )?;
            let descriptor = target.descriptor();
            let token = match target {
                TokenTarget::Tuist { server_url } => {
                    let store = TuistSessionStore::new()?;
                    if options.no_refresh {
                        store.load_token(&server_url)?.ok_or_else(|| {
                            anyhow!("token not found for server URL '{server_url}'")
                        })?
                    } else {
                        store.get_valid_token(&server_url)?
                    }
                }
                TokenTarget::File { key } => {
                    let storage = FileStorage::new("schlussel")?;
                    let mut token = storage
                        .load(&key)?
                        .ok_or_else(|| anyhow!("token not found for key '{key}'"))?;

                    if !options.no_refresh
                        && token.refresh_token.is_some()
                        && token.expires_within(300)
                    {
                        let manager = RefreshLockManager::new("schlussel")?;
                        let mut lock = manager.acquire(&key)?;
                        let fresh = storage
                            .load(&key)?
                            .ok_or_else(|| anyhow!("token not found for key '{key}'"))?;
                        token = if fresh.refresh_token.is_some() && fresh.expires_within(300) {
                            refresh_stored_token(
                                &storage,
                                &key,
                                fresh,
                                options.formula_json.as_deref(),
                                output,
                            )?
                        } else {
                            fresh
                        };
                        lock.release()?;
                    }

                    token
                }
            };

            match output.mode() {
                OutputMode::Json => {
                    println!(
                        "{}",
                        serde_json::to_string_pretty(&TokenEnvelope {
                            token,
                            metadata: descriptor,
                        })?
                    );
                }
                OutputMode::Toon => print_token_details(&descriptor, &token, output)?,
                OutputMode::Default => println!("{}", token.access_token),
            }
        }
        TokenAction::List(options) => {
            let items = list_token_descriptors(&options)?;
            if output.mode() == OutputMode::Json {
                println!("{}", serde_json::to_string_pretty(&items)?);
            } else if items.is_empty() {
                if is_tuist_formula(options.formula.as_deref()) {
                    println!("No Tuist sessions found");
                } else {
                    println!("No tokens found");
                }
            } else {
                print_token_list(&items, output)?;
            }
        }
        TokenAction::Delete(options) => {
            let target = resolve_token_target(
                options.key.as_deref(),
                options.formula.as_deref(),
                options.method.as_deref(),
                options.identity.as_deref(),
            )?;
            let descriptor = target.descriptor();
            match target {
                TokenTarget::Tuist { server_url } => {
                    let store = TuistSessionStore::new()?;
                    store.delete_token(&server_url)?;
                }
                TokenTarget::File { key } => {
                    let storage = FileStorage::new("schlussel")?;
                    storage.delete(&key)?;
                }
            }
            if output.mode() == OutputMode::Json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&DeletedToken {
                        deleted: true,
                        metadata: descriptor,
                    })?
                );
            } else {
                print_deleted_token(&descriptor, output)?;
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

fn cmd_script(args: ScriptArgs, output: OutputContext) -> Result<()> {
    if args.json_schema {
        let schema = script_json_schema();
        if output.mode() == OutputMode::Toon {
            println!("{}", output.stdout_heading("JSON schema"));
        }
        println!("{}", serde_json::to_string_pretty(&schema)?);
        return Ok(());
    }

    let provider = args
        .provider
        .as_deref()
        .ok_or_else(|| anyhow!("missing provider name"))?;
    let formula = load_formula(provider, args.common.formula_json.as_deref(), output)?;
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
    if output.mode() == OutputMode::Toon {
        print_script_document(&document, output)?;
    } else {
        println!("{}", serde_json::to_string_pretty(&document)?);
    }
    Ok(())
}

fn load_formula(provider: &str, path: Option<&Path>, output: OutputContext) -> Result<Formula> {
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

#[derive(Debug, Clone, Serialize)]
struct TokenDescriptor {
    key: String,
    formula: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    method: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    identity: Option<String>,
    source: TokenSource,
    #[serde(skip_serializing_if = "Option::is_none")]
    server_url: Option<String>,
}

impl TokenDescriptor {
    fn from_key(key: &str) -> Self {
        let parsed = parse_storage_key(key);
        Self {
            key: key.to_string(),
            formula: parsed.formula,
            method: parsed.method,
            identity: parsed.identity,
            source: TokenSource::File,
            server_url: None,
        }
    }

    fn tuist_host(host: &str) -> Self {
        Self {
            key: build_storage_key("tuist", Some("session"), Some(host)),
            formula: "tuist".to_string(),
            method: Some("session".to_string()),
            identity: Some(host.to_string()),
            source: TokenSource::Tuist,
            server_url: None,
        }
    }

    fn tuist_server_url(server_url: &str) -> Result<Self> {
        let host = tuist_host(server_url)?;
        Ok(Self {
            server_url: Some(server_url.to_string()),
            ..Self::tuist_host(&host)
        })
    }
}

#[derive(Debug, Clone, Copy, Serialize)]
#[serde(rename_all = "snake_case")]
enum TokenSource {
    File,
    Tuist,
}

#[derive(Debug, Serialize)]
struct TokenEnvelope {
    #[serde(flatten)]
    metadata: TokenDescriptor,
    token: Token,
}

#[derive(Debug, Serialize)]
struct DeletedToken {
    deleted: bool,
    #[serde(flatten)]
    metadata: TokenDescriptor,
}

#[derive(Debug, Clone)]
enum TokenTarget {
    File { key: String },
    Tuist { server_url: String },
}

impl TokenTarget {
    fn descriptor(&self) -> TokenDescriptor {
        match self {
            Self::File { key } => TokenDescriptor::from_key(key),
            Self::Tuist { server_url } => {
                TokenDescriptor::tuist_server_url(server_url).expect("valid Tuist target")
            }
        }
    }
}

fn print_formula_list(formulas: Vec<FormulaInfo>, output: OutputContext) -> Result<()> {
    println!("{}", output.stdout_heading("Available formulas"));
    for formula in formulas {
        println!("  {} - {}", output.stdout_value(&formula.id), formula.label);
    }
    Ok(())
}

fn print_formula_details(formula: &Formula, output: OutputContext) -> Result<()> {
    println!("{}", output.stdout_heading(&formula.label));
    print_key_value("ID", &formula.id, output);

    if let Some(identity) = &formula.identity {
        if let Some(label) = &identity.label {
            let value = match &identity.hint {
                Some(hint) => format!("{label} ({hint})"),
                None => label.clone(),
            };
            print_key_value("Identity", &value, output);
        }
    }

    println!();
    println!("{}", output.stdout_heading("Methods"));
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

    println!();
    println!("{}", output.stdout_heading("APIs"));
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
        println!();
        println!("{}", output.stdout_heading("Public clients"));
        for client in &formula.clients {
            match &client.source {
                Some(source) => println!("  - {} (from {source})", client.name),
                None => println!("  - {}", client.name),
            }
        }
    }

    Ok(())
}

fn print_token_list(items: &[TokenDescriptor], output: OutputContext) -> Result<()> {
    println!("{}", output.stdout_heading("Available tokens"));
    for item in items {
        match item.source {
            TokenSource::File => match &item.identity {
                Some(identity) => println!("  {} (identity: {identity})", item.key),
                None => println!("  {}", item.key),
            },
            TokenSource::Tuist => println!("  {} (Tuist session)", item.key),
        }
    }
    Ok(())
}

fn print_token_details(
    descriptor: &TokenDescriptor,
    token: &Token,
    output: OutputContext,
) -> Result<()> {
    println!(
        "{} {} {} loaded",
        output.stdout_prefix(),
        output.stdout_value(&descriptor.key),
        output.stdout_success_mark(),
    );
    println!();
    print_key_value("Access token", &token.access_token, output);
    print_key_value("Token type", &token.token_type, output);
    print_key_value(
        "Source",
        match descriptor.source {
            TokenSource::File => "file",
            TokenSource::Tuist => "tuist",
        },
        output,
    );
    if let Some(server_url) = &descriptor.server_url {
        print_key_value("Server", server_url, output);
    }
    if let Some(scope) = &token.scope {
        print_key_value("Scope", scope, output);
    }
    if let Some(expires_at) = token.expires_at {
        print_key_value(
            "Expires at",
            &format!("{expires_at} (Unix timestamp)"),
            output,
        );
    }
    Ok(())
}

fn print_deleted_token(descriptor: &TokenDescriptor, output: OutputContext) -> Result<()> {
    println!(
        "{} {} {} deleted",
        output.stdout_prefix(),
        output.stdout_value(&descriptor.key),
        output.stdout_success_mark(),
    );
    Ok(())
}

fn print_script_document(document: &ScriptDocument, output: OutputContext) -> Result<()> {
    println!("{}", output.stdout_heading("Script document"));
    print_key_value("Formula", &document.formula, output);
    if let Some(method) = &document.method {
        print_key_value("Method", method, output);
    }
    print_key_value("Storage key", &document.storage.key, output);

    println!();
    println!("{}", output.stdout_heading("Steps"));
    for (index, step) in document.script.iter().enumerate() {
        let friendly = friendly_step_name(&step.kind);
        match &step.note {
            Some(note) => println!("  {}. {} ({note})", index + 1, friendly),
            None => println!("  {}. {}", index + 1, friendly),
        }
    }

    if let Some(context) = &document.context {
        let context_rows = [
            ("Authorization URL", context.authorize_url.as_deref()),
            ("Verification URL", context.verification_uri.as_deref()),
            ("User code", context.user_code.as_deref()),
            ("Redirect URI", context.redirect_uri.as_deref()),
        ];
        let mut printed_context = false;
        for (label, value) in context_rows {
            if let Some(value) = value {
                if !printed_context {
                    println!();
                    println!("{}", output.stdout_heading("Context"));
                    printed_context = true;
                }
                print_key_value(label, value, output);
            }
        }
    }

    Ok(())
}

fn print_script_steps(steps: &[ScriptStep], output: OutputContext) -> Result<()> {
    if steps.is_empty() {
        return Ok(());
    }

    if output.mode() == OutputMode::Json {
        return Ok(());
    }

    let mut stdout = io::stdout();
    writeln!(stdout, "\n{}", output.stdout_heading("Script steps"))?;

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
    output: OutputContext,
    writer: &mut impl io::Write,
) -> Result<()> {
    if output.mode() == OutputMode::Json {
        let payload = serde_json::json!({
            "dry_run": true,
            "storage_key": storage_key,
            "script": resolved,
        });
        writeln!(writer, "{}", serde_json::to_string_pretty(&payload)?)?;
        return Ok(());
    }

    writeln!(writer, "\n{}", output.stdout_heading("Dry run"))?;
    if method.is_device_code() {
        write_key_value(
            writer,
            "Verification URL",
            resolved
                .context
                .verification_uri
                .as_deref()
                .unwrap_or("<missing>"),
            output,
        )?;
        write_key_value(
            writer,
            "User code",
            resolved.context.user_code.as_deref().unwrap_or("<missing>"),
            output,
        )?;
    } else if method.is_authorization_code() {
        write_key_value(
            writer,
            "Authorization URL",
            resolved
                .context
                .authorize_url
                .as_deref()
                .unwrap_or("<missing>"),
            output,
        )?;
    } else {
        writeln!(
            writer,
            "{} Would prompt for a credential",
            output.stdout_prefix()
        )?;
    }

    write_key_value(writer, "Storage key", storage_key, output)?;
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

fn print_success(token: &Token, storage_key: &str, output: OutputContext) -> Result<()> {
    println!(
        "\n{} {} {} authorized",
        output.stdout_prefix(),
        output.stdout_value(storage_key),
        output.stdout_success_mark(),
    );
    println!();
    print_key_value("Token type", &token.token_type, output);
    if let Some(scope) = &token.scope {
        print_key_value("Scope", scope, output);
    }
    if let Some(expires_at) = token.expires_at {
        print_key_value(
            "Expires at",
            &format!("{expires_at} (Unix timestamp)"),
            output,
        );
    }
    print_key_value("Storage key", storage_key, output);
    Ok(())
}

fn resolve_token_target(
    key: Option<&str>,
    formula: Option<&str>,
    method: Option<&str>,
    identity: Option<&str>,
) -> Result<TokenTarget> {
    if let Some(key) = key {
        let parsed = parse_storage_key(key);
        if parsed.formula == "tuist" {
            ensure_tuist_method(parsed.method.as_deref().or(method))?;
            let server_url = normalize_server_url(parsed.identity.as_deref().or(identity))?;
            let _ = tuist_host(&server_url)?;
            return Ok(TokenTarget::Tuist { server_url });
        }

        return Ok(TokenTarget::File {
            key: key.to_string(),
        });
    }

    if let Some(formula) = formula {
        if formula == "tuist" {
            ensure_tuist_method(method)?;
            let server_url = normalize_server_url(identity)?;
            let _ = tuist_host(&server_url)?;
            return Ok(TokenTarget::Tuist { server_url });
        }

        return Ok(TokenTarget::File {
            key: build_storage_key(formula, method, identity),
        });
    }

    bail!("either --key or --formula is required")
}

fn refresh_stored_token(
    storage: &FileStorage,
    key: &str,
    token: Token,
    formula_json: Option<&Path>,
    output: OutputContext,
) -> Result<Token> {
    let refresh_token = token
        .refresh_token
        .clone()
        .ok_or(SchlusselError::NoRefreshToken)?;
    let parsed = parse_storage_key(key);
    let method_name = parsed.method.as_deref().unwrap_or("oauth");
    let formula = if let Some(path) = formula_json {
        load_formula(&parsed.formula, Some(path), output)?
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

fn list_token_descriptors(options: &TokenListArgs) -> Result<Vec<TokenDescriptor>> {
    let storage = FileStorage::new("schlussel")?;
    let mut items = storage
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
        .map(|key| TokenDescriptor::from_key(&key))
        .collect::<Vec<_>>();

    items.extend(list_tuist_descriptors(options)?);
    items.sort_by(|left, right| left.key.cmp(&right.key));
    Ok(items)
}

fn list_tuist_descriptors(options: &TokenListArgs) -> Result<Vec<TokenDescriptor>> {
    if matches!(options.formula.as_deref(), Some(formula) if formula != "tuist") {
        return Ok(Vec::new());
    }

    if let Some(method) = options.method.as_deref() {
        if method != "session" {
            return Ok(Vec::new());
        }
    }

    let store = TuistSessionStore::new()?;
    Ok(store
        .list_hosts()?
        .into_iter()
        .filter(|host| {
            store
                .load_token(&format!("https://{host}"))
                .ok()
                .flatten()
                .is_some()
        })
        .map(|host| TokenDescriptor::tuist_host(&host))
        .filter(|item| {
            options
                .key
                .as_ref()
                .is_none_or(|prefix| item.key.starts_with(prefix))
                && host_matches_identity(
                    item.identity.as_deref().unwrap_or_default(),
                    options.identity.as_deref(),
                )
        })
        .collect())
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

fn print_key_value(label: &str, value: &str, output: OutputContext) {
    println!("{}: {}", output.stdout_label(label), value);
}

fn write_key_value(
    writer: &mut impl io::Write,
    label: &str,
    value: &str,
    output: OutputContext,
) -> Result<()> {
    writeln!(writer, "{}: {}", output.stdout_label(label), value)?;
    Ok(())
}

fn tuist_host(server_url: &str) -> Result<String> {
    url::Url::parse(server_url)?
        .host_str()
        .map(str::to_owned)
        .ok_or_else(|| anyhow!("invalid Tuist server URL '{server_url}'"))
}

fn is_broken_pipe(error: &anyhow::Error) -> bool {
    error
        .chain()
        .filter_map(|cause| cause.downcast_ref::<std::io::Error>())
        .any(|error| error.kind() == std::io::ErrorKind::BrokenPipe)
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

#[cfg(test)]
mod tests {
    use std::ffi::OsString;
    use std::sync::{Mutex, OnceLock};

    use tempfile::tempdir;

    use super::*;

    fn env_lock() -> &'static Mutex<()> {
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| Mutex::new(()))
    }

    struct TuistEnvGuard {
        old_config_home: Option<OsString>,
        old_state_home: Option<OsString>,
    }

    impl TuistEnvGuard {
        fn new(config_home: &Path, state_home: &Path) -> Self {
            let old_config_home = std::env::var_os("TUIST_XDG_CONFIG_HOME");
            let old_state_home = std::env::var_os("TUIST_XDG_STATE_HOME");
            std::env::set_var("TUIST_XDG_CONFIG_HOME", config_home);
            std::env::set_var("TUIST_XDG_STATE_HOME", state_home);
            Self {
                old_config_home,
                old_state_home,
            }
        }
    }

    fn valid_tuist_token() -> Token {
        Token {
            access_token: "eyJhbGciOiJub25lIn0.eyJleHAiOjQxMDI0NDQ4MDB9.".to_string(),
            token_type: "Bearer".to_string(),
            refresh_token: Some("refresh-token".to_string()),
            expires_in: None,
            expires_at: Some(4_102_444_800),
            scope: None,
            id_token: None,
        }
    }

    impl Drop for TuistEnvGuard {
        fn drop(&mut self) {
            match &self.old_config_home {
                Some(value) => std::env::set_var("TUIST_XDG_CONFIG_HOME", value),
                None => std::env::remove_var("TUIST_XDG_CONFIG_HOME"),
            }
            match &self.old_state_home {
                Some(value) => std::env::set_var("TUIST_XDG_STATE_HOME", value),
                None => std::env::remove_var("TUIST_XDG_STATE_HOME"),
            }
        }
    }

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

    #[test]
    fn resolves_tuist_targets_to_synthetic_keys() {
        let descriptor = resolve_token_target(None, Some("tuist"), None, Some("cloud.tuist.dev"))
            .expect("tuist target")
            .descriptor();

        assert_eq!(descriptor.key, "tuist:session:cloud.tuist.dev");
        assert_eq!(descriptor.identity.as_deref(), Some("cloud.tuist.dev"));
        assert_eq!(
            descriptor.server_url.as_deref(),
            Some("https://cloud.tuist.dev")
        );
    }

    #[test]
    fn token_list_includes_tuist_sessions() {
        let _lock = env_lock().lock().expect("env lock");
        let temp = tempdir().expect("tempdir");
        let config_home = temp.path().join("config-home");
        let state_home = temp.path().join("state-home");
        let _guard = TuistEnvGuard::new(&config_home, &state_home);
        let store =
            TuistSessionStore::with_paths(config_home.join("tuist"), state_home.join("tuist"))
                .expect("store");
        store
            .save_token("https://app.tuist.dev", &valid_tuist_token())
            .expect("save token");

        let items = list_token_descriptors(&TokenListArgs {
            key: None,
            formula: None,
            formula_json: None,
            method: None,
            identity: None,
        })
        .expect("list tokens");

        assert!(items
            .iter()
            .any(|item| item.key == "tuist:session:app.tuist.dev"));
    }
}
