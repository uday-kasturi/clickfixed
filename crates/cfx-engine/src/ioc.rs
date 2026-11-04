//! IOC extraction for Signal 3 analyst reports.

use crate::types::host_of;
use crate::util::re;
use regex::Regex;
use serde::Serialize;
use std::collections::BTreeSet;
use std::sync::LazyLock;

#[derive(Debug, Clone, Default, Serialize)]
pub struct Iocs {
    pub urls: BTreeSet<String>,
    pub domains: BTreeSet<String>,
    pub ipv4: BTreeSet<String>,
    pub file_paths: BTreeSet<String>,
    pub registry_keys: BTreeSet<String>,
    pub hashes: BTreeSet<String>,
}

static URL: LazyLock<Regex> = LazyLock::new(|| re(r#"https?://[^\s'"<>)`\]|;]+"#));
static IPV4: LazyLock<Regex> =
    LazyLock::new(|| re(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b"));
static PATH: LazyLock<Regex> = LazyLock::new(|| {
    re(
        r#"(?:%[a-z]+%|\$env:[a-z]+|[a-z]:)\\[^\s'"<>|&;]+|(?:/tmp|/var/tmp|~/\.cache|~/Library/LaunchAgents|/Library/LaunchDaemons)/[^\s'"<>|&;]+"#,
    )
});
static REG: LazyLock<Regex> =
    LazyLock::new(|| re(r#"\b(?:HKCU|HKLM|HKEY_CURRENT_USER|HKEY_LOCAL_MACHINE)(?::)?\\[^\s'"]+"#));
static HASH: LazyLock<Regex> =
    LazyLock::new(|| re(r"\b(?:[0-9a-f]{64}|[0-9a-f]{40}|[0-9a-f]{32})\b"));

pub fn extract<'a>(texts: impl IntoIterator<Item = &'a str>) -> Iocs {
    let mut out = Iocs::default();
    for t in texts {
        for m in URL.find_iter(t) {
            let u = m.as_str().trim_end_matches(['.', ',', ')']).to_string();
            if let Some(h) = host_of(&u) {
                if IPV4.is_match(&h) {
                    out.ipv4.insert(h);
                } else {
                    out.domains.insert(h);
                }
            }
            out.urls.insert(u);
        }
        for m in IPV4.find_iter(t) {
            out.ipv4.insert(m.as_str().to_string());
        }
        for m in PATH.find_iter(t) {
            out.file_paths.insert(m.as_str().to_string());
        }
        for m in REG.find_iter(t) {
            out.registry_keys.insert(m.as_str().to_string());
        }
        for m in HASH.find_iter(t) {
            out.hashes.insert(m.as_str().to_ascii_lowercase());
        }
    }
    out
}
