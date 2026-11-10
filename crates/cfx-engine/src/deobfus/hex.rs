use super::base64::bytes_to_text;
use super::Decoder;
use crate::util::re;
use regex::Regex;
use std::sync::LazyLock;

/// Hex escapes: `\x63\x75\x72\x6c`, `$'\x63\x75'`, `0x63,0x75,...` byte arrays, and the
/// octal escapes `printf` and `$'..'` also accept: `\143\165\162\154`.
/// Requires 4+ consecutive units so lone `\x1b` colour codes and single constants are ignored.
pub struct HexDecoder;

static BACKSLASH_X: LazyLock<Regex> = LazyLock::new(|| re(r"(?:\\x[0-9a-f]{2}){4,}"));
static ZERO_X_LIST: LazyLock<Regex> =
    LazyLock::new(|| re(r"0x[0-9a-f]{2}(?:\s*,\s*0x[0-9a-f]{2}){3,}"));
static OCTAL: LazyLock<Regex> = LazyLock::new(|| re(r"(?:\\[0-3][0-7]{2}){4,}"));
static BYTE: LazyLock<Regex> = LazyLock::new(|| re(r"(?:\\x|0x)([0-9a-f]{2})"));

fn decode_units(s: &str) -> Option<String> {
    let bytes: Vec<u8> = if s.starts_with("\\") && !s.starts_with("\\x") {
        s.split('\\')
            .filter(|o| !o.is_empty())
            .filter_map(|o| u8::from_str_radix(o, 8).ok())
            .collect()
    } else {
        BYTE.captures_iter(s)
            .filter_map(|c| u8::from_str_radix(&c[1], 16).ok())
            .collect()
    };
    bytes_to_text(&bytes, 0.9).or_else(|| {
        // Short runs (<6 bytes) are still worth resolving if they are plain ASCII.
        (bytes.len() >= 4 && bytes.iter().all(|b| (0x20..0x7f).contains(b)))
            .then(|| String::from_utf8_lossy(&bytes).into_owned())
    })
}

impl Decoder for HexDecoder {
    fn name(&self) -> &'static str {
        "hex"
    }
    fn try_decode(&self, input: &str) -> Option<String> {
        let mut changed = false;
        let mut cur = input.to_string();
        for pat in [&*BACKSLASH_X, &*ZERO_X_LIST, &*OCTAL] {
            let next = pat.replace_all(&cur, |c: &regex::Captures| match decode_units(&c[0]) {
                Some(s) => {
                    changed = true;
                    s
                }
                None => c[0].to_string(),
            });
            cur = next.into_owned();
        }
        changed.then_some(cur)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn decodes() {
        assert_eq!(
            HexDecoder.try_decode(r"printf '\x63\x75\x72\x6c'").unwrap(),
            "printf 'curl'"
        );
        assert_eq!(
            HexDecoder.try_decode("0x69,0x65,0x78,0x20").unwrap(),
            "iex "
        );
        assert!(HexDecoder.try_decode(r"echo -e '\x1b[31m red'").is_none());
        assert_eq!(
            HexDecoder
                .try_decode(r"printf '\143\165\162\154' | sh")
                .unwrap(),
            "printf 'curl' | sh"
        );
        // Three escapes are a colour code or a line ending, not a payload.
        assert!(HexDecoder.try_decode(r"printf '\033[0m\012\015'").is_none());
    }
}
