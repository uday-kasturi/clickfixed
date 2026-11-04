use super::Decoder;

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
        changed.then_some(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
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
