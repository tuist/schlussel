pub mod formula;
pub mod run;
pub mod script;
pub mod token;

use anyhow::Result;

use crate::cli::Commands;
use crate::output::OutputContext;

pub fn execute(command: Commands, output: OutputContext) -> Result<()> {
    match command {
        Commands::Run(args) => run::execute(args, output),
        Commands::Formula(args) => formula::execute(args, output),
        Commands::Token(args) => token::execute(args, output),
        Commands::Script(args) => script::execute(args, output),
    }
}
