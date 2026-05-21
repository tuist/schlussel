use anyhow::Result;
use schlussel::formulas::list_builtin;

use crate::cli::{FormulaAction, FormulaArgs};
use crate::formula_support::load_formula;
use crate::output::{OutputContext, OutputMode};
use crate::render::{print_formula_details, print_formula_list};

pub fn execute(args: FormulaArgs, output: OutputContext) -> Result<()> {
    match args.action {
        FormulaAction::List => list_formulas(output),
        FormulaAction::Show {
            provider,
            formula_json,
        } => show_formula(&provider, formula_json.as_deref(), output),
    }
}

fn list_formulas(output: OutputContext) -> Result<()> {
    let formulas = list_builtin();
    match output.mode() {
        OutputMode::Json => println!("{}", serde_json::to_string_pretty(&formulas)?),
        _ => print_formula_list(formulas, output)?,
    }
    Ok(())
}

fn show_formula(
    provider: &str,
    path: Option<&std::path::Path>,
    output: OutputContext,
) -> Result<()> {
    let formula = load_formula(provider, path, output)?;
    match output.mode() {
        OutputMode::Json => println!("{}", serde_json::to_string_pretty(&formula)?),
        _ => print_formula_details(&formula, output)?,
    }
    Ok(())
}
