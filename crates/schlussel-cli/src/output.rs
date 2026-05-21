use std::io::{self, IsTerminal};

use anyhow::Error;
use clap::builder::styling::{AnsiColor, Effects, Styles};
use clap::{Args, ValueEnum};
use serde::Serialize;

const PROGRAM_NAME: &str = "schlussel";
const RESET: &str = "\x1b[0m";

#[derive(Args, Debug, Clone, Default)]
pub struct OutputArgs {
    /// Render command output as structured JSON or styled terminal text
    #[arg(long, global = true, value_enum, value_name = "FORMAT")]
    format: Option<OutputFormat>,
    #[arg(long, global = true, hide = true, conflicts_with = "format")]
    json: bool,
}

impl OutputArgs {
    pub fn mode(&self) -> OutputMode {
        if self.json {
            OutputMode::Json
        } else {
            match self.format {
                Some(OutputFormat::Json) => OutputMode::Json,
                Some(OutputFormat::Toon) => OutputMode::Toon,
                None => OutputMode::Default,
            }
        }
    }
}

#[derive(Copy, Clone, Debug, Eq, PartialEq, ValueEnum)]
pub enum OutputFormat {
    Json,
    Toon,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum OutputMode {
    Default,
    Json,
    Toon,
}

#[derive(Copy, Clone, Debug)]
pub struct OutputContext {
    mode: OutputMode,
    stdout_color: bool,
    stderr_color: bool,
}

impl OutputContext {
    pub fn new(mode: OutputMode) -> Self {
        Self {
            mode,
            stdout_color: stream_color_enabled(io::stdout().is_terminal()),
            stderr_color: stream_color_enabled(io::stderr().is_terminal()),
        }
    }

    pub fn mode(self) -> OutputMode {
        self.mode
    }

    pub fn is_json(self) -> bool {
        self.mode == OutputMode::Json
    }

    pub fn stdout_prefix(self) -> String {
        paint(PROGRAM_NAME, "2", self.stdout_color)
    }

    pub fn stdout_heading(self, text: &str) -> String {
        paint(text, "1;36", self.stdout_color)
    }

    pub fn stdout_label(self, text: &str) -> String {
        paint(text, "2", self.stdout_color)
    }

    pub fn stdout_value(self, text: &str) -> String {
        paint(text, "1", self.stdout_color)
    }

    pub fn stdout_success_mark(self) -> String {
        paint("✓", "32", self.stdout_color)
    }

    pub fn stderr_level_prefix(self, level: OutputLevel) -> String {
        let color = match level {
            OutputLevel::Warn => "33",
            OutputLevel::Error => "31",
        };
        let label = match level {
            OutputLevel::Warn => "WARN",
            OutputLevel::Error => "ERROR",
        };
        format!(
            "{} {}",
            paint(PROGRAM_NAME, color, self.stderr_color),
            paint(label, color, self.stderr_color)
        )
    }
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum OutputLevel {
    Warn,
    Error,
}

pub fn clap_styles() -> Styles {
    Styles::styled()
        .header(AnsiColor::Cyan.on_default() | Effects::BOLD)
        .usage(AnsiColor::Cyan.on_default() | Effects::BOLD)
        .literal(AnsiColor::Blue.on_default() | Effects::BOLD)
        .placeholder(AnsiColor::Green.on_default())
        .valid(AnsiColor::Green.on_default() | Effects::BOLD)
        .invalid(AnsiColor::Yellow.on_default() | Effects::BOLD)
        .error(AnsiColor::Red.on_default() | Effects::BOLD)
}

pub fn render_error(error: &Error, output: OutputContext) {
    let mut chain = error.chain();
    let message = chain
        .next()
        .map(ToString::to_string)
        .unwrap_or_else(|| "unknown error".to_string());
    let causes = chain.map(ToString::to_string).collect::<Vec<_>>();

    if output.is_json() {
        let payload = JsonErrorPayload {
            error: JsonError {
                message: message.clone(),
                causes,
            },
        };
        match serde_json::to_string_pretty(&payload) {
            Ok(rendered) => eprintln!("{rendered}"),
            Err(_) => eprintln!("{message}"),
        }
        return;
    }

    eprintln!(
        "{} {}",
        output.stderr_level_prefix(OutputLevel::Error),
        message
    );
    for cause in causes {
        eprintln!(
            "{} caused by: {}",
            output.stderr_level_prefix(OutputLevel::Error),
            cause
        );
    }
}

pub fn render_warning(message: &str, output: OutputContext) {
    eprintln!(
        "{} {}",
        output.stderr_level_prefix(OutputLevel::Warn),
        message
    );
}

#[derive(Serialize)]
struct JsonErrorPayload {
    error: JsonError,
}

#[derive(Serialize)]
struct JsonError {
    message: String,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    causes: Vec<String>,
}

fn stream_color_enabled(is_terminal: bool) -> bool {
    if std::env::var_os("NO_COLOR").is_some() {
        return false;
    }

    if std::env::var("CLICOLOR").ok().as_deref() == Some("0") {
        return false;
    }

    if std::env::var("CLICOLOR_FORCE")
        .ok()
        .is_some_and(|value| value != "0")
    {
        return true;
    }

    is_terminal
}

fn paint(text: &str, code: &str, enabled: bool) -> String {
    if enabled {
        format!("\x1b[{code}m{text}{RESET}")
    } else {
        text.to_string()
    }
}
