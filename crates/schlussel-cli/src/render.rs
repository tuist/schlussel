use std::io::{self, Write};

use anyhow::Result;
use schlussel::formulas::{Formula, FormulaInfo, MethodDef, ScriptStep};
use schlussel::script::ScriptDocument;
use schlussel::{ResolvedScript, Token};

use crate::commands::token::{TokenDescriptor, TokenSource};
use crate::output::{OutputContext, OutputMode};

pub fn print_formula_list(formulas: Vec<FormulaInfo>, output: OutputContext) -> Result<()> {
    println!("{}", output.stdout_heading("Available formulas"));
    for formula in formulas {
        println!("  {} - {}", output.stdout_value(&formula.id), formula.label);
    }
    Ok(())
}

pub fn print_formula_details(formula: &Formula, output: OutputContext) -> Result<()> {
    println!("{}", output.stdout_heading(&formula.label));
    print_key_value("ID", &formula.id, output);

    if let Some(value) = formula
        .identity
        .as_ref()
        .and_then(|identity| identity.label.as_ref().map(|label| (identity, label)))
        .map(|(identity, label)| match &identity.hint {
            Some(hint) => format!("{label} ({hint})"),
            None => label.clone(),
        })
    {
        print_key_value("Identity", &value, output);
    }

    println!();
    println!("{}", output.stdout_heading("Methods"));
    for (name, method) in &formula.methods {
        let label = method.label.as_deref().unwrap_or(name);
        println!("  - {label} ({})", method_kind(method));
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

pub fn print_token_list(items: &[TokenDescriptor], output: OutputContext) -> Result<()> {
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

pub fn print_token_details(
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
    print_key_value("Source", descriptor.source.as_label(), output);

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

pub fn print_deleted_token(descriptor: &TokenDescriptor, output: OutputContext) -> Result<()> {
    println!(
        "{} {} {} deleted",
        output.stdout_prefix(),
        output.stdout_value(&descriptor.key),
        output.stdout_success_mark(),
    );
    Ok(())
}

pub fn print_script_document(document: &ScriptDocument, output: OutputContext) -> Result<()> {
    println!("{}", output.stdout_heading("Script document"));
    print_key_value("Formula", &document.formula, output);
    if let Some(method) = &document.method {
        print_key_value("Method", method, output);
    }
    print_key_value("Storage key", &document.storage.key, output);

    println!();
    println!("{}", output.stdout_heading("Steps"));
    for (index, step) in document.script.iter().enumerate() {
        print_script_step(index, step)?;
    }

    if let Some(context) = &document.context {
        let context_rows = [
            ("Authorization URL", context.authorize_url.as_deref()),
            ("Verification URL", context.verification_uri.as_deref()),
            ("User code", context.user_code.as_deref()),
            ("Redirect URI", context.redirect_uri.as_deref()),
        ];

        let mut rows = context_rows
            .into_iter()
            .filter_map(|(label, value)| value.map(|value| (label, value)));
        if let Some((label, value)) = rows.next() {
            println!();
            println!("{}", output.stdout_heading("Context"));
            print_key_value(label, value, output);
            for (label, value) in rows {
                print_key_value(label, value, output);
            }
        }
    }

    Ok(())
}

pub fn print_script_steps(steps: &[ScriptStep], output: OutputContext) -> Result<()> {
    if steps.is_empty() || output.mode() == OutputMode::Json {
        return Ok(());
    }

    let mut stdout = io::stdout();
    writeln!(stdout, "\n{}", output.stdout_heading("Script steps"))?;
    for (index, step) in steps.iter().enumerate() {
        match &step.note {
            Some(note) => writeln!(
                stdout,
                "  {}. {} ({note})",
                index + 1,
                friendly_step_name(&step.kind),
            )?,
            None => writeln!(
                stdout,
                "  {}. {}",
                index + 1,
                friendly_step_name(&step.kind)
            )?,
        }
    }

    Ok(())
}

pub fn print_dry_run(
    method: &MethodDef,
    resolved: &ResolvedScript,
    storage_key: &str,
    output: OutputContext,
    writer: &mut impl Write,
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

pub fn print_success(token: &Token, storage_key: &str, output: OutputContext) -> Result<()> {
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

pub fn write_key_value(
    writer: &mut impl Write,
    label: &str,
    value: &str,
    output: OutputContext,
) -> Result<()> {
    writeln!(writer, "{}: {}", output.stdout_label(label), value)?;
    Ok(())
}

pub fn print_key_value(label: &str, value: &str, output: OutputContext) {
    println!("{}: {}", output.stdout_label(label), value);
}

fn print_script_step(index: usize, step: &ScriptStep) -> Result<()> {
    match &step.note {
        Some(note) => println!(
            "  {}. {} ({note})",
            index + 1,
            friendly_step_name(&step.kind)
        ),
        None => println!("  {}. {}", index + 1, friendly_step_name(&step.kind)),
    }
    Ok(())
}

fn method_kind(method: &MethodDef) -> &'static str {
    if method.is_device_code() {
        "device code"
    } else if method.is_authorization_code() {
        "authorization code"
    } else {
        "manual"
    }
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
