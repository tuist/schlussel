use std::path::PathBuf;

use clap::{Args, Parser, Subcommand};

use crate::output::{clap_styles, OutputArgs};

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
pub struct Cli {
    #[command(flatten)]
    pub output: OutputArgs,
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand, Debug)]
pub enum Commands {
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
pub struct CommonFormulaArgs {
    #[arg(long)]
    pub formula_json: Option<PathBuf>,
    #[arg(short = 'm', long)]
    pub method: Option<String>,
    #[arg(short = 'c', long)]
    pub client: Option<String>,
    #[arg(long)]
    pub client_id: Option<String>,
    #[arg(long)]
    pub client_secret: Option<String>,
    #[arg(long)]
    pub scope: Option<String>,
    #[arg(long, default_value = "http://127.0.0.1:0/callback")]
    pub redirect_uri: String,
    #[arg(short = 'i', long)]
    pub identity: Option<String>,
}

#[derive(Args, Debug)]
pub struct RunArgs {
    /// Built-in provider ID or the ID of the supplied formula JSON
    pub provider: String,
    #[command(flatten)]
    pub common: CommonFormulaArgs,
    #[arg(long)]
    pub credential: Option<String>,
    #[arg(long, value_name = "true|false")]
    pub open_browser: Option<bool>,
    #[arg(short = 'n', long)]
    pub dry_run: bool,
}

#[derive(Args, Debug)]
pub struct FormulaArgs {
    #[command(subcommand)]
    pub action: FormulaAction,
}

#[derive(Subcommand, Debug)]
pub enum FormulaAction {
    List,
    Show {
        /// Built-in provider ID or the ID of the supplied formula JSON
        provider: String,
        #[arg(long)]
        formula_json: Option<PathBuf>,
    },
}

#[derive(Args, Debug)]
pub struct TokenArgs {
    #[command(subcommand)]
    pub action: TokenAction,
}

#[derive(Subcommand, Debug)]
pub enum TokenAction {
    Get(TokenKeyArgs),
    List(TokenListArgs),
    Delete(TokenKeyArgs),
}

#[derive(Args, Debug)]
pub struct TokenKeyArgs {
    #[arg(long)]
    pub key: Option<String>,
    #[arg(long)]
    pub formula: Option<String>,
    #[arg(long)]
    pub formula_json: Option<PathBuf>,
    #[arg(long)]
    pub method: Option<String>,
    #[arg(long)]
    pub identity: Option<String>,
    #[arg(long)]
    pub no_refresh: bool,
}

#[derive(Args, Debug)]
pub struct TokenListArgs {
    #[arg(long)]
    pub key: Option<String>,
    #[arg(long)]
    pub formula: Option<String>,
    #[arg(long)]
    pub formula_json: Option<PathBuf>,
    #[arg(long)]
    pub method: Option<String>,
    #[arg(long)]
    pub identity: Option<String>,
}

#[derive(Args, Debug)]
pub struct ScriptArgs {
    pub provider: Option<String>,
    #[command(flatten)]
    pub common: CommonFormulaArgs,
    #[arg(long)]
    pub resolve: bool,
    #[arg(long)]
    pub json_schema: bool,
}
