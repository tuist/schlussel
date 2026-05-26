use clap::Parser;

use crate::cli::Cli;
use crate::output::{render_error, OutputContext};

mod cli;
mod commands;
mod formula_support;
mod output;
mod render;

fn main() {
    let cli = Cli::parse();
    let output = OutputContext::new(cli.output.mode());

    if let Err(error) = commands::execute(cli.command, output) {
        if is_broken_pipe(&error) {
            return;
        }
        render_error(&error, output);
        std::process::exit(1);
    }
}

fn is_broken_pipe(error: &anyhow::Error) -> bool {
    error
        .chain()
        .filter_map(|cause| cause.downcast_ref::<std::io::Error>())
        .any(|error| error.kind() == std::io::ErrorKind::BrokenPipe)
}
