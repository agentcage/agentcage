//! The YAML 1.1 ambiguity fixture, asserted without Python.
//!
//! This half is the fast one: it runs on every `cargo test`, needs no
//! interpreter, and proves that `agentcage-core`'s transliteration of
//! PyYAML's implicit-resolver table agrees with the corpus, and that the
//! emitter quotes everything the corpus says is hazardous.
//!
//! It is **not** the test that proves the bug is fixed. A pure-Rust test
//! cannot: the corruption happens when PyYAML reads what Rust wrote, and
//! Rust reading what Rust wrote is fine either way. That proof is
//! `yaml_pyyaml_crossing.rs`, which runs real `yaml.safe_load`.

mod common;

use std::collections::BTreeSet;

use agentcage_core::yaml::{self, Mapping, Value};

use common::fixture;

#[test]
fn the_corpus_is_well_formed() {
    let fixture = fixture();
    assert!(
        fixture.cases.len() >= 100,
        "corpus shrank to {}; cases are only ever added",
        fixture.cases.len()
    );

    let mut ids = BTreeSet::new();
    let mut scalars = BTreeSet::new();
    for case in &fixture.cases {
        assert!(ids.insert(case.id.clone()), "duplicate id {:?}", case.id);
        assert!(
            scalars.insert(case.scalar.clone()),
            "duplicate scalar {:?} ({})",
            case.scalar,
            case.id
        );
        assert!(!case.why.is_empty(), "{} has no `why`", case.id);
    }

    // The corpus is only useful if it carries both arms. A file of
    // nothing but hazards proves the predicate says "yes"; a file of
    // nothing but safe scalars proves it says "no".
    let hazards = fixture
        .cases
        .iter()
        .filter(|case| case.plain_tag != "str")
        .count();
    assert!(hazards >= 50, "only {hazards} hazardous cases");
    assert!(
        fixture.cases.len() - hazards >= 40,
        "only {} safe cases",
        fixture.cases.len() - hazards
    );
}

#[test]
fn the_predicate_agrees_with_pyyaml_s_resolver_table() {
    for case in fixture().cases {
        let expected = case.plain_tag != "str";
        assert_eq!(
            yaml::is_yaml_1_1_ambiguous(&case.scalar),
            expected,
            "{}: {:?} resolves to `{}` as a plain scalar ({})",
            case.id,
            case.scalar,
            case.plain_tag,
            case.why
        );
    }
}

#[test]
fn every_hazardous_scalar_is_emitted_quoted() {
    for case in fixture().cases {
        if case.plain_tag == "str" {
            continue;
        }
        let mut mapping = Mapping::new();
        mapping.insert(
            Value::String("k".to_owned()),
            Value::String(case.scalar.clone()),
        );
        let rendered = yaml::dump(&Value::Mapping(mapping)).expect("dump");
        let emitted = rendered
            .strip_prefix("k: ")
            .expect("one-key mapping")
            .trim_end_matches('\n');
        assert!(
            emitted.starts_with('\'') || emitted.starts_with('"') || emitted.starts_with('|'),
            "{}: {:?} was emitted plain as {emitted:?}; PyYAML would read a `{}`",
            case.id,
            case.scalar,
            case.plain_tag
        );
    }
}

#[test]
fn every_scalar_survives_as_a_value_and_as_a_key() {
    let fixture = fixture();

    let mut values = Mapping::new();
    let mut keys = Mapping::new();
    for case in &fixture.cases {
        values.insert(
            Value::String(case.id.clone()),
            Value::String(case.scalar.clone()),
        );
        keys.insert(
            Value::String(case.scalar.clone()),
            Value::String(case.id.clone()),
        );
    }
    let mut document = Mapping::new();
    document.insert(Value::String("values".to_owned()), Value::Mapping(values));
    document.insert(Value::String("keys".to_owned()), Value::Mapping(keys));
    let original = Value::Mapping(document);

    let rendered = yaml::dump(&original).expect("dump");
    let reloaded = yaml::load(&rendered).expect("reload");
    assert!(
        yaml::eq_with_key_order(&reloaded, &original),
        "the corpus does not survive a Rust round trip:\n{rendered}"
    );
}
