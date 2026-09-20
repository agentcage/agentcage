//! Every committed config, loaded, dumped, and loaded again.
//!
//! The requirement this enforces is key order. `state.save_raw_config`
//! calls `yaml.safe_dump(..., sort_keys=False)`, `cage edit` writes the
//! file back through it, and the user then opens the result — so a YAML
//! layer that reorders keys rewrites the user's file every time any
//! command touches it. `Value`'s own `PartialEq` would not notice
//! (`IndexMap`'s equality ignores order), which is why
//! `yaml::eq_with_key_order` exists and is what this asserts.
//!
//! This is a Rust→Rust round trip and it is honest about what that is
//! worth: it proves order and structure survive, and it cannot prove
//! anything about the YAML 1.1 divergence. `yaml_pyyaml_crossing.rs`
//! runs the same corpus of files past real PyYAML.

mod common;

use agentcage_core::yaml::{self, Value};

use common::committed_configs;

#[test]
fn every_committed_config_round_trips_with_its_key_order() {
    let configs = committed_configs();
    let mut checked = 0_usize;

    for path in &configs {
        let source = std::fs::read_to_string(path)
            .unwrap_or_else(|error| panic!("reading {}: {error}", path.display()));
        let original = yaml::load(&source)
            .unwrap_or_else(|error| panic!("loading {}: {error}", path.display()));

        let rendered = yaml::dump(&original)
            .unwrap_or_else(|error| panic!("dumping {}: {error}", path.display()));
        let reloaded = yaml::load(&rendered)
            .unwrap_or_else(|error| panic!("reloading {}: {error}", path.display()));

        assert!(
            yaml::eq_with_key_order(&reloaded, &original),
            "{} does not round-trip with its key order intact\n--- emitted ---\n{rendered}",
            path.display()
        );

        // And again, to catch an emitter that is not idempotent — the
        // failure mode where `cage edit` grows a level of indentation or
        // a pair of quotes on every invocation.
        let twice = yaml::dump(&reloaded)
            .unwrap_or_else(|error| panic!("re-dumping {}: {error}", path.display()));
        assert_eq!(
            twice,
            rendered,
            "{} emits differently the second time",
            path.display()
        );

        checked += 1;
    }

    // Track B's acceptance criterion is a number, so state it.
    assert_eq!(
        checked,
        configs.len(),
        "checked {checked} of {} configs",
        configs.len()
    );
    assert!(
        checked >= 10,
        "only {checked} configs found; the corpus shrank"
    );
    println!("round-tripped {checked} committed configs with key order preserved");
}

#[test]
fn a_reordered_mapping_is_not_equal() {
    // Proves the assertion above bites: the same pairs in a different
    // order must fail `eq_with_key_order`, or the round-trip test would
    // pass against an emitter that sorts keys.
    let one: Value = yaml::load("name: a\nimage: b\n").expect("load");
    let other: Value = yaml::load("image: b\nname: a\n").expect("load");
    assert_eq!(one, other, "Value's own equality ignores order");
    assert!(!yaml::eq_with_key_order(&one, &other));
}
