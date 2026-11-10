use super::Decoder;
use crate::util::re;
use regex::Regex;
use std::sync::LazyLock;

/// A word broken by non-empty quotes: `c"m"d`, `pow"er"shell`, `"c"md`. Unquoted, the shell
/// sees one word. Only rewritten when the result is an execution word, so `a"b"c` in
/// ordinary text is left alone.
static QUOTED_WORD: LazyLock<Regex> = LazyLock::new(|| {
    re(r#"(^|[^a-z0-9_.\-"'])((?:[a-z0-9_.\-]|"[a-z0-9_.\-]+"|'[a-z0-9_.\-]+')+)"#)
});
static EXEC_WORD: LazyLock<Regex> = LazyLock::new(|| {
    re(
        r"^(?:cmd|powershell|pwsh|mshta|iex|iwr|irm|curl|wget|bash|sh|zsh|certutil|bitsadmin|rundll32|regsvr32|wscript|cscript|msiexec|conhost|invoke-expression|invoke-webrequest|invoke-restmethod|start-process)(?:\.exe)?$",
    )
});

static EXEC_WORD_ANYWHERE: LazyLock<Regex> = LazyLock::new(|| {
    re(
        r"\b(?:cmd|powershell|pwsh|mshta|iex|iwr|irm|curl|wget|bash|sh|zsh|certutil|bitsadmin|rundll32|regsvr32|wscript|cscript|msiexec|conhost|invoke-expression|invoke-webrequest|invoke-restmethod|start-process)\b",
    )
});

fn unquote_words(input: &str) -> Option<String> {
    // Cheap pre-check: a quote directly touching a letter or digit on either side.
    let b = input.as_bytes();
    let touching = (1..b.len()).any(|i| {
        let (p, c) = (b[i - 1], b[i]);
        (matches!(c, b'"' | b'\'') && p.is_ascii_alphanumeric())
            || (matches!(p, b'"' | b'\'') && c.is_ascii_alphanumeric())
    });
    if !touching || !EXEC_WORD_ANYWHERE.is_match(&input.replace(['"', '\''], "")) {
        return None;
    }
    let mut changed = false;
    let out = QUOTED_WORD.replace_all(input, |c: &regex::Captures| {
        let w = &c[2];
        let quoted = w.contains(['"', '\'']);
        // A fully quoted argument ("powershell") is an ordinary string, not a broken word.
        let enclosed = w.len() >= 2
            && w.starts_with(['"', '\''])
            && w.ends_with(['"', '\''])
            && !w[1..w.len() - 1].contains(['"', '\'']);
        let bare: String = w.chars().filter(|c| *c != '"' && *c != '\'').collect();
        if quoted && !enclosed && EXEC_WORD.is_match(&bare) {
            changed = true;
            format!("{}{}", &c[1], bare)
        } else {
            c[0].to_string()
        }
    });
    changed.then(|| out.into_owned())
}

/// cmd caret insertion (`p^o^w^e^r^s^h^e^l^l`), empty-quote insertion (`p""owershell`,
/// `po''wershell`) and PowerShell backtick insertion (`i`e`x`).
///
/// Only removes the character when it sits *between two word characters*, which is
/// where it has no meaning to the shell except to break string matching. Legitimate
/// uses (`^&` escaping, `""` empty args, `` `n `` in strings) are left alone.
pub struct CaretQuoteDecoder;

impl Decoder for CaretQuoteDecoder {
    fn name(&self) -> &'static str {
        "caret_quote"
    }
    fn try_decode(&self, input: &str) -> Option<String> {
        let chars: Vec<char> = input.chars().collect();
        let word = |c: Option<&char>| {
            c.is_some_and(|c| c.is_alphanumeric() || *c == '_' || *c == '-' || *c == '.')
        };
        let mut out = String::with_capacity(input.len());
        let mut changed = false;
        let mut i = 0;
        while i < chars.len() {
            let c = chars[i];
            let prev = out.chars().last();
            if (c == '^' || c == '`') && word(prev.as_ref()) && word(chars.get(i + 1)) {
                changed = true;
                i += 1;
                continue;
            }
            if (c == '"' || c == '\'')
                && chars.get(i + 1) == Some(&c)
                && word(prev.as_ref())
                && word(chars.get(i + 2))
            {
                changed = true;
                i += 2;
                continue;
            }
            out.push(c);
            i += 1;
        }
        match unquote_words(&out) {
            Some(u) => Some(u),
            None => changed.then_some(out),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quotes_inside_command_words() {
        let d = CaretQuoteDecoder;
        assert_eq!(
            d.try_decode(r#"c"m"d /c pow"er"shell -c x"#).unwrap(),
            "cmd /c powershell -c x"
        );
        assert_eq!(d.try_decode(r#""c"md /c dir"#).unwrap(), "cmd /c dir");
        assert!(d
            .try_decode(r#"start "powershell" -ArgumentList x"#)
            .is_none());
        assert!(d.try_decode(r#"echo a"b"c and "quoted" text"#).is_none());
    }
    #[test]
    fn strips() {
        assert_eq!(
            CaretQuoteDecoder
                .try_decode("p^o^w^e^r^s^h^e^l^l -c i`e`x")
                .unwrap(),
            "powershell -c iex"
        );
        assert_eq!(
            CaretQuoteDecoder.try_decode(r#"m""sh''ta"#).unwrap(),
            "mshta"
        );
    }
    #[test]
    fn leaves_legit_escapes() {
        assert!(CaretQuoteDecoder.try_decode(r#"echo a ^& b"#).is_none());
        assert!(CaretQuoteDecoder
            .try_decode(r#"git commit -m "" --allow-empty"#)
            .is_none());
    }
}
