use super::Decoder;
use crate::util::re;
use regex::Regex;
use std::sync::LazyLock;

/// Character-code arrays:
/// - `[char]105+[char]101+[char]120`
/// - `[char[]](105,101,120)` / `[char[]]@(105,101,120)`
/// - `chr(105) & chr(101)` (VBS) and `chr(105).chr(101)` (PHP/Perl)
/// - `String.fromCharCode(105,101,120)`
pub struct CharCodeDecoder;

static CHAR_CHAIN: LazyLock<Regex> = LazyLock::new(|| {
    re(
        r"\[char\]\s*(?:\(\s*\d{1,5}\s*\)|\d{1,5})(?:\s*\+\s*\[char\]\s*(?:\(\s*\d{1,5}\s*\)|\d{1,5}))+",
    )
});
static CHAR_ARRAY: LazyLock<Regex> =
    LazyLock::new(|| re(r"\[char\[\]\]\s*@?\(\s*(\d{1,5}(?:\s*,\s*\d{1,5})+)\s*\)"));
static CHR_CHAIN: LazyLock<Regex> =
    LazyLock::new(|| re(r"chrw?\(\s*\d{1,5}\s*\)(?:\s*[&+.]\s*chrw?\(\s*\d{1,5}\s*\))+"));
static FROM_CC: LazyLock<Regex> =
    LazyLock::new(|| re(r"string\.fromcharcode\(\s*(\d{1,5}(?:\s*,\s*\d{1,5})+)\s*\)"));
static NUM: LazyLock<Regex> = LazyLock::new(|| re(r"\d{1,5}"));

fn codes_to_string(s: &str) -> Option<String> {
    let mut out = String::new();
    for m in NUM.find_iter(s) {
        let n: u32 = m.as_str().parse().ok()?;
        out.push(char::from_u32(n)?);
    }
    (!out.is_empty()).then_some(out)
}

impl Decoder for CharCodeDecoder {
    fn name(&self) -> &'static str {
        "charcode"
    }
    fn try_decode(&self, input: &str) -> Option<String> {
        let mut changed = false;
        let mut cur = input.to_string();
        for pat in [&*CHAR_CHAIN, &*CHAR_ARRAY, &*CHR_CHAIN, &*FROM_CC] {
            let next = pat.replace_all(&cur, |c: &regex::Captures| {
                match codes_to_string(&c[0].replace("[char[]]", "")) {
                    Some(s) => {
                        changed = true;
                        format!("'{}'", s.replace('\'', "''"))
                    }
                    None => c[0].to_string(),
                }
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
    fn forms() {
        assert_eq!(
            CharCodeDecoder
                .try_decode("&([char]105+[char]101+[char]120)")
                .unwrap(),
            "&('iex')"
        );
        assert_eq!(
            CharCodeDecoder
                .try_decode("-join [char[]](105,119,114)")
                .unwrap(),
            "-join 'iwr'"
        );
        assert_eq!(
            CharCodeDecoder.try_decode("chr(105)&chr(101)").unwrap(),
            "'ie'"
        );
        assert_eq!(
            CharCodeDecoder
                .try_decode("String.fromCharCode(104,105)")
                .unwrap(),
            "'hi'"
        );
    }
}
