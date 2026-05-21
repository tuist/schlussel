use anyhow::{anyhow, Result};
use schlussel::script::{build_script_document, resolve_script, script_json_schema};

use crate::cli::ScriptArgs;
use crate::formula_support::{load_formula, resolve_run_inputs};
use crate::output::{OutputContext, OutputMode};
use crate::render::print_script_document;

pub fn execute(args: ScriptArgs, output: OutputContext) -> Result<()> {
    if args.json_schema {
        emit_json_schema(output)?;
        return Ok(());
    }

    let provider = args
        .provider
        .as_deref()
        .ok_or_else(|| anyhow!("missing provider name"))?;
    let formula = load_formula(provider, args.common.formula_json.as_deref(), output)?;
    let inputs = resolve_run_inputs(&formula, &args.common)?;
    let resolved = args
        .resolve
        .then(|| {
            resolve_script(
                &formula,
                &inputs.method_name,
                inputs.client_id_override.as_deref(),
                inputs.client_secret_override.as_deref(),
                args.common.scope.as_deref(),
                &inputs.redirect_uri,
            )
        })
        .transpose()?;

    let document = build_script_document(
        &formula,
        &inputs.method_name,
        args.common.identity.as_deref(),
        resolved,
    );
    match output.mode() {
        OutputMode::Toon => print_script_document(&document, output)?,
        _ => println!("{}", serde_json::to_string_pretty(&document)?),
    }
    Ok(())
}

fn emit_json_schema(output: OutputContext) -> Result<()> {
    let schema = script_json_schema();
    if output.mode() == OutputMode::Toon {
        println!("{}", output.stdout_heading("JSON schema"));
    }
    println!("{}", serde_json::to_string_pretty(&schema)?);
    Ok(())
}
