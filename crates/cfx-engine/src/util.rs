use regex::{Regex, RegexBuilder};
use sha2::{Digest, Sha256};
use std::sync::LazyLock;

/// Compile a regex with hard size limits. The `regex` crate is linear-time (no
/// backtracking), so pathological inputs cannot blow up matching; these limits bound
/// what a hostile or careless *rule* can cost.
pub fn build_regex(pattern: &str) -> Result<Regex, regex::Error> {
    RegexBuilder::new(pattern)
        .case_insensitive(true)
        .size_limit(1 << 20)
        .dfa_size_limit(2 << 20)
        .nest_limit(64)
        .build()
}

pub(crate) fn re(pattern: &str) -> Regex {
    build_regex(pattern).expect("static regex")
}

/// Tokens that put an observation in an *execution context*. Entropy, decoded-layer
/// weight and several allowlist shapes are gated on this.
static INTERPRETER: LazyLock<Regex> = LazyLock::new(|| {
    re(
        r#"(?:\b(?:powershell|pwsh|mshta|wscript|cscript|rundll32|regsvr32|msiexec|bash|zsh|dash|python[0-9.]*|perl|ruby|osascript|iex|invoke-expression|conhost|certutil|bitsadmin|start-process|scriptblock)\b|\bcmd(?:\.exe)?\s*/[ckr]\b|\bsh\s+-c\b|\|\s*sh\b|\bnode\s+-e\b|\beval\b)"#,
    )
});

pub fn has_interpreter_token(text: &str) -> bool {
    INTERPRETER.is_match(text)
}

pub fn shannon_entropy(s: &str) -> f64 {
    let bytes = s.as_bytes();
    if bytes.is_empty() {
        return 0.0;
    }
    let mut counts = [0usize; 256];
    for &b in bytes {
        counts[b as usize] += 1;
    }
    let n = bytes.len() as f64;
    counts
        .iter()
        .filter(|&&c| c > 0)
        .map(|&c| {
            let p = c as f64 / n;
            -p * p.log2()
        })
        .sum()
}

pub fn sha256_hex(data: &[u8]) -> String {
    let digest = Sha256::digest(data);
    let mut out = String::with_capacity(64);
    for b in digest {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

/// Truncate on a char boundary.
pub fn truncate(s: &str, max: usize) -> &str {
    if s.len() <= max {
        return s;
    }
    let mut end = max;
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    &s[..end]
}

/// Short evidence snippet for reports. Never used for clipboard content below warn.
pub fn snippet(s: &str, start: usize, end: usize) -> String {
    let mut a = start.saturating_sub(12);
    while !s.is_char_boundary(a) {
        a -= 1;
    }
    let mut b = (end + 12).min(s.len());
    while !s.is_char_boundary(b) {
        b += 1;
    }
    let mut out: String = s[a..b].chars().take(120).collect();
    out = out.replace(['\n', '\r'], " ");
    out
}

/// Fraction of chars that are printable ASCII or common whitespace.
pub fn printable_ratio(s: &str) -> f64 {
    if s.is_empty() {
        return 0.0;
    }
    let total = s.chars().count();
    let good = s
        .chars()
        .filter(|c| (' '..='~').contains(c) || matches!(c, '\n' | '\r' | '\t'))
        .count();
    good as f64 / total as f64
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn interpreter_tokens() {
        assert!(has_interpreter_token("curl x | sh"));
        assert!(has_interpreter_token("powershell -c foo"));
        assert!(has_interpreter_token("cmd /c dir"));
        assert!(!has_interpreter_token("kubectl get pods -o wide"));
        assert!(!has_interpreter_token("sha256sum file | grep abc"));
        assert!(!has_interpreter_token(
            "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.abc"
        ));
    }
    #[test]
    fn entropy_sane() {
        assert!(shannon_entropy("aaaa") < 0.01);
        assert!(shannon_entropy("abcdefghijklmnop") > 3.9);
    }
}
