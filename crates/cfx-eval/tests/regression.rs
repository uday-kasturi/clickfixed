//! CI guards. If the allowlist ever lowers a malicious verdict, an entry is too broad.

use cfx_eval::*;
use std::path::Path;

fn root() -> &'static Path {
    Path::new(concat!(env!("CARGO_MANIFEST_DIR"), "/../.."))
}

#[test]
fn allowlist_never_lowers_a_malicious_verdict() {
    let mal: Vec<Case> = load_malicious(&root().join("corpus/malicious.csv"))
        .unwrap()
        .iter()
        .map(Case::from)
        .collect();
    let bad = allowlist_regression(&mal);
    assert!(bad.is_empty(), "allowlist too broad: {bad:?}");
}

#[test]
fn required_negatives_are_not_blocked() {
    let ben: Vec<Case> = load_benign(&root().join("corpus/benign.csv"))
        .unwrap()
        .iter()
        .map(Case::from)
        .collect();
    let engine = cfx_engine::Engine::default();
    // Chocolatey, Homebrew, kubectl|base64 -d, JWT, certutil -hashfile (brief §8).
    for id in ["B007", "B002", "B022", "B010", "B016"] {
        let c = ben.iter().find(|c| c.id == id).unwrap();
        let v = engine.fast_path(&c.obs);
        assert_eq!(v.level, cfx_engine::Level::Clean, "{id} {:?}", v.features);
    }
}
