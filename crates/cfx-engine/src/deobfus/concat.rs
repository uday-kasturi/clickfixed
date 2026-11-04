use super::Decoder;
use crate::util::re;
use regex::Regex;
use std::sync::LazyLock;

/// `'po'+'wer'+'shell'` -> `'powershell'`, also `"a" + "b"` and `'a'"b"` adjacency in sh.
/// Literal concatenation only; `$a + 'b'` needs runtime state and is left alone.
pub struct ConcatDecoder;

static PLUS: LazyLock<Regex> = LazyLock::new(|| {
    re(
        r#"'([^'\n]*)'\s*\+\s*'([^'\n]*)'|"([^"\n$`]*)"\s*\+\s*"([^"\n$`]*)"|'([^'\n]*)'\s*\+\s*"([^"\n$`]*)"|"([^"\n$`]*)"\s*\+\s*'([^'\n]*)'"#,
    )
});

impl Decoder for ConcatDecoder {
    fn name(&self) -> &'static str {
        "concat"
    }
    fn try_decode(&self, input: &str) -> Option<String> {
        let mut cur = input.to_string();
        let mut changed = false;
        // Each pass merges adjacent pairs; chains of N pieces need ~log2(N) passes.
        for _ in 0..16 {
            let next = PLUS.replace_all(&cur, |c: &regex::Captures| {
                let parts: Vec<&str> = (1..=8)
                    .filter_map(|i| c.get(i).map(|m| m.as_str()))
                    .collect();
                format!("'{}'", parts.concat())
            });
            if next == cur {
                break;
            }
            changed = true;
            cur = next.into_owned();
        }
        changed.then_some(cur)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn merges_chains() {
        assert_eq!(
            ConcatDecoder
                .try_decode("&('i'+'e'+'x') ('Down'+\"loadString\")")
                .unwrap(),
            "&('iex') ('DownloadString')"
        );
    }
    #[test]
    fn leaves_variables() {
        assert!(ConcatDecoder.try_decode("$a + 'b'").is_none());
    }
}
