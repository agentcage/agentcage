//! `agentcage secret rotate-placeholders NAME [KEYS]...`.
//!
//! `cli.py:4057`. Placeholders are decoys, not credentials, so this
//! command prints both the old and the new token — that is the point of
//! it, and there is nothing here to redact.

use std::process::ExitCode;

use agentcage_core::config::injection_rules_mut;
use agentcage_core::yaml::Value;
use clap::ArgMatches;

use crate::cli::context::{Ctx, EXIT_FAILURE};
use crate::cli::secret::{check_cage, load_config, require_container};

/// The body.
pub(crate) fn main(ctx: &Ctx, matches: &ArgMatches) -> ExitCode {
    match run(ctx, matches) {
        Ok(()) => ExitCode::SUCCESS,
        Err(code) => code,
    }
}

fn run(ctx: &Ctx, matches: &ArgMatches) -> Result<(), ExitCode> {
    let name = matches
        .get_one::<String>("name")
        .expect("required by the parser")
        .clone();
    let keys: Vec<String> = matches
        .get_many::<String>("keys")
        .map(|values| values.cloned().collect())
        .unwrap_or_default();

    check_cage(ctx, &name, false)?;

    let mut raw = ctx
        .paths
        .load_raw_config(&name, agentcage_state::AgentSchema::Check)
        .map_err(|error| {
            eprintln!("error: {error}");
            ExitCode::from(EXIT_FAILURE)
        })?;

    // `[r for r in _injection_rules(raw) if isinstance(r, dict) and r.get("env")]`
    // — the indices of the rules that are rotatable at all, taken once
    // so the borrow of `raw` ends before the mutation below.
    let envs: Vec<(usize, String)> = injection_rules_mut(&mut raw)
        .iter()
        .enumerate()
        .filter_map(|(index, rule)| {
            let env = rule.as_mapping()?.get("env")?;
            agentcage_core::yaml::python_bool(env)
                .then(|| (index, agentcage_core::python::str_of(env)))
        })
        .collect();

    let targets: Vec<usize> = if keys.is_empty() {
        if envs.is_empty() {
            println!("Cage '{name}' has no secret_injection rules to rotate.");
            return Ok(());
        }
        envs.iter().map(|(index, _)| *index).collect()
    } else {
        let missing: Vec<&String> = keys
            .iter()
            .filter(|key| !envs.iter().any(|(_, env)| env == *key))
            .collect();
        if !missing.is_empty() {
            let names: Vec<&str> = missing.iter().map(|key| key.as_str()).collect();
            eprintln!("error: no secret_injection rule for: {}", names.join(", "));
            return Err(ExitCode::from(EXIT_FAILURE));
        }
        // Named order, not document order: `rotate-placeholders NAME B A`
        // reports B then A, as the Python's `[by_env[k] for k in keys]`
        // does. A key named twice rotates twice, and the second token
        // wins — also the Python's behaviour.
        keys.iter()
            .filter_map(|key| {
                envs.iter()
                    .find(|(_, env)| env == key)
                    .map(|(index, _)| *index)
            })
            .collect()
    };

    let mut rotations: Vec<(String, String, String)> = Vec::new();
    {
        let rules = injection_rules_mut(&mut raw);
        for index in targets {
            let Some(rule) = rules[index].as_mapping_mut() else {
                continue;
            };
            let env = rule
                .get("env")
                .map_or_else(String::new, agentcage_core::python::str_of);
            let old = rule
                .get("placeholder")
                .filter(|value| !matches!(value, Value::Null))
                .map_or_else(String::new, agentcage_core::python::str_of);
            let new = agentcage_state::mint_placeholder(&env);
            rule.insert(
                Value::String("placeholder".to_owned()),
                Value::String(new.clone()),
            );
            rotations.push((env, old, new));
        }
    }

    ctx.paths.save_raw_config(&name, &raw).map_err(|error| {
        eprintln!("error: {error}");
        ExitCode::from(EXIT_FAILURE)
    })?;

    println!("Rotated {} placeholder(s) for '{name}':", rotations.len());
    for (env, old, new) in &rotations {
        let old = if old.is_empty() { "(unset)" } else { old };
        println!("  {env}  {old}  →  {new}");
    }

    let config = load_config(ctx, &name)?;
    require_container(&config, &name)?;
    if ctx.backend().is_running(&config.name, "cage") {
        println!(
            "Restarting cage '{}' to apply — the old placeholder(s) stop \
             injecting now.",
            config.name
        );
        // A full restart, not the staging channel: a placeholder change
        // has to reach the *cage* container's environment, which podman
        // only re-reads from `EnvironmentFile=` at container creation.
        // Staging carries values, not decoys.
        crate::cli::secret::live::restart(ctx, &config.name);
    } else {
        println!("Cage is not running — the new placeholders apply on next start.");
    }
    Ok(())
}
