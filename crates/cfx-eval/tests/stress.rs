//! Stress corpora (scripts/build_stress_corpus.py): every encoding family the engine claims,
//! multi-line decoy shapes, and benign look-alikes aimed at each rule. These rows are
//! authored for testing, so they guard the rules; they are not field detection rates.

use cfx_engine::{Engine, Level};
use cfx_eval::*;
use std::path::Path;

fn root() -> &'static Path {
    Path::new(concat!(env!("CARGO_MANIFEST_DIR"), "/../.."))
}

fn malicious(rel: &str) -> Vec<Case> {
    load_malicious(&root().join(rel))
        .unwrap()
        .iter()
        .map(Case::from)
        .collect()
}

fn engines() -> Vec<(&'static str, Engine)> {
    configs()
        .into_iter()
        .filter(|(name, _)| *name == "full" || name.starts_with("no_context"))
        .map(|(name, c)| (name, Engine::default().with_config(c)))
        .collect()
}

#[test]
fn every_encoded_row_warns_with_and_without_context() {
    let cases = malicious("corpus/evasion/encoded.csv");
    assert!(cases.len() >= 160, "encoded corpus shrank: {}", cases.len());
    for (name, engine) in engines() {
        let missed: Vec<_> = cases
            .iter()
            .filter(|c| engine.fast_path(&c.obs).level < Level::Warn)
            .map(|c| c.id.as_str())
            .collect();
        assert!(missed.is_empty(), "{name}: missed {missed:?}");
    }
}

#[test]
fn multiline_decoys_are_found() {
    let engine = Engine::default();
    for c in malicious("corpus/evasion/multiline.csv") {
        // Prose before the command is not a trailing decoy; that row documents the limit.
        if c.id == "L-decoy_first_line" {
            continue;
        }
        let v = engine.fast_path(&c.obs);
        assert!(
            v.features
                .iter()
                .any(|f| f.feature == "trailing_decoy_prose"),
            "{}: {:?}",
            c.id,
            v.features.iter().map(|f| &f.feature).collect::<Vec<_>>()
        );
    }
}

#[test]
fn benign_look_alikes_stay_clean() {
    let cases: Vec<Case> = load_benign(&root().join("corpus/benign_stress.csv"))
        .unwrap()
        .iter()
        .map(Case::from)
        .collect();
    assert!(
        cases.len() >= 80,
        "benign stress corpus shrank: {}",
        cases.len()
    );
    for (name, engine) in engines() {
        let fps: Vec<_> = cases
            .iter()
            .filter_map(|c| {
                let v = engine.fast_path(&c.obs);
                (v.level >= Level::Warn).then(|| {
                    format!(
                        "{} {:?}",
                        c.id,
                        v.features.iter().map(|f| &f.feature).collect::<Vec<_>>()
                    )
                })
            })
            .collect();
        assert!(fps.is_empty(), "{name}: false positives {fps:?}");
    }
}
