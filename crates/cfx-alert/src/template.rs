//! Webhook/Jira payload templates. Templates are JSON files, not code.
//!
//! A template is any JSON document. String values may contain `{{path}}` placeholders
//! that resolve against the alert's JSON (`{{host.name}}`, `{{clickfixed.score}}`,
//! `{{threat.technique.subtechnique.id.0}}`) plus helpers under `fmt.*` and, for Jira,
//! `jira.*`. Rendering works on parsed JSON, so substituted values are always escaped:
//! attacker-controlled decoded text cannot break out of a JSON string.
//!
//! - A string that is exactly one placeholder takes the value's JSON type
//!   (`"{{clickfixed.score}}"` renders as a number, `"{{alert}}"` as the whole alert).
//! - Otherwise placeholders are interpolated as text. Missing or null values render empty.
//! - Filters: `{{fmt.decoded|slack}}` escapes Slack mrkdwn control characters (`& < >`),
//!   `|jira` neutralises Jira wiki block macros, `|json` renders a value as a JSON string.
//!
//! Every placeholder is checked against the schema at startup: a typo fails loudly.

use regex::Regex;
use serde_json::{Map, Value};
use std::path::Path;
use std::sync::LazyLock;

static PLACEHOLDER: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\{\{\s*([A-Za-z0-9_@.\-]+)\s*(?:\|\s*([a-z_]+)\s*)?\}\}").unwrap()
});

const FILTERS: &[&str] = &["slack", "jira", "json"];

#[derive(Debug, Clone)]
pub struct Template {
    pub name: String,
    root: Value,
}

impl Template {
    pub fn load(path: &Path) -> Result<Self, String> {
        let s = std::fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
        let root: Value = serde_json::from_str(&s)
            .map_err(|e| format!("{}: invalid JSON: {e}", path.display()))?;
        Ok(Self {
            name: path.display().to_string(),
            root,
        })
    }

    pub fn from_value(name: impl Into<String>, root: Value) -> Self {
        Self {
            name: name.into(),
            root,
        }
    }

    pub fn root(&self) -> &Value {
        &self.root
    }

    /// Sub-template at a top-level key (Jira's `create` / `comment` / `update`).
    pub fn section(&self, key: &str) -> Option<Template> {
        self.root
            .get(key)
            .map(|v| Template::from_value(format!("{}#{key}", self.name), v.clone()))
    }

    /// Every placeholder must resolve against `ctx` (a schema sample) and use a known filter.
    pub fn validate(&self, ctx: &Value) -> Result<(), String> {
        let mut errs = Vec::new();
        walk_strings(&self.root, &mut |s| {
            for c in PLACEHOLDER.captures_iter(s) {
                let path = &c[1];
                if lookup(ctx, path).is_none() {
                    errs.push(format!("unknown field {{{{{path}}}}}"));
                }
                if let Some(f) = c.get(2) {
                    if !FILTERS.contains(&f.as_str()) {
                        errs.push(format!(
                            "unknown filter |{} (known: {})",
                            f.as_str(),
                            FILTERS.join(", ")
                        ));
                    }
                }
            }
        });
        if errs.is_empty() {
            Ok(())
        } else {
            Err(format!("template {}: {}", self.name, errs.join("; ")))
        }
    }

    pub fn render(&self, ctx: &Value) -> Value {
        render_value(&self.root, ctx)
    }
}

fn walk_strings(v: &Value, f: &mut dyn FnMut(&str)) {
    match v {
        Value::String(s) => f(s),
        Value::Array(a) => a.iter().for_each(|x| walk_strings(x, f)),
        Value::Object(o) => o.values().for_each(|x| walk_strings(x, f)),
        _ => {}
    }
}

fn render_value(v: &Value, ctx: &Value) -> Value {
    match v {
        Value::String(s) => render_string(s, ctx),
        Value::Array(a) => Value::Array(a.iter().map(|x| render_value(x, ctx)).collect()),
        Value::Object(o) => Value::Object(
            o.iter()
                .map(|(k, x)| (k.clone(), render_value(x, ctx)))
                .collect::<Map<_, _>>(),
        ),
        other => other.clone(),
    }
}

fn render_string(s: &str, ctx: &Value) -> Value {
    if let Some(c) = PLACEHOLDER.captures(s.trim()) {
        if c.get(0).unwrap().as_str() == s.trim() {
            let v = lookup(ctx, &c[1]).cloned().unwrap_or(Value::Null);
            return match c.get(2).map(|m| m.as_str()) {
                None => v,
                Some(f) => Value::String(apply_filter(f, &v)),
            };
        }
    }
    let out = PLACEHOLDER.replace_all(s, |c: &regex::Captures| {
        let v = lookup(ctx, &c[1]).cloned().unwrap_or(Value::Null);
        match c.get(2).map(|m| m.as_str()) {
            None => as_text(&v),
            Some(f) => apply_filter(f, &v),
        }
    });
    Value::String(out.into_owned())
}

fn as_text(v: &Value) -> String {
    match v {
        Value::Null => String::new(),
        Value::String(s) => s.clone(),
        Value::Array(a) => a.iter().map(as_text).collect::<Vec<_>>().join(", "),
        other => other.to_string(),
    }
}

fn apply_filter(f: &str, v: &Value) -> String {
    match f {
        "slack" => as_text(v)
            .replace('&', "&amp;")
            .replace('<', "&lt;")
            .replace('>', "&gt;"),
        "jira" => {
            let t = as_text(v);
            // Inside {noformat} nothing renders except a closing {noformat}; break any
            // macro-opening brace so decoded text cannot end the block or open another.
            t.replace('{', "\u{FF5B}")
        }
        "json" => v.to_string(),
        _ => as_text(v),
    }
}

/// Dotted path lookup; numeric segments index arrays.
pub fn lookup<'a>(v: &'a Value, path: &str) -> Option<&'a Value> {
    let mut cur = v;
    for seg in path.split('.') {
        cur = match cur {
            Value::Object(o) => o.get(seg)?,
            Value::Array(a) => a.get(seg.parse::<usize>().ok()?)?,
            _ => return None,
        };
    }
    Some(cur)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn typed_interpolated_and_escaped() {
        let ctx = json!({"a": {"n": 2.5, "s": "x\"}<y>"}, "l": ["T1", "T2"]});
        let t = Template::from_value(
            "t",
            json!({"num": "{{a.n}}", "txt": "score {{a.n}} {{a.s}}", "first": "{{l.0}}",
                   "slack": "{{a.s|slack}}", "missing": "[{{a.none}}]"}),
        );
        let r = t.render(&ctx);
        assert_eq!(r["num"], json!(2.5));
        assert_eq!(r["txt"], json!("score 2.5 x\"}<y>"));
        assert_eq!(r["first"], json!("T1"));
        assert_eq!(r["slack"], json!("x\"}&lt;y&gt;"));
        assert_eq!(r["missing"], json!("[]"));
        // Output is valid JSON with the quote escaped.
        assert!(serde_json::to_string(&r).unwrap().contains(r#"x\"}<y>"#));
    }

    #[test]
    fn validate_catches_typos() {
        let ctx = json!({"host": {"name": "h"}});
        assert!(Template::from_value("t", json!({"x": "{{host.name}}"}))
            .validate(&ctx)
            .is_ok());
        let e = Template::from_value("t", json!({"x": "{{host.nmae}}"}))
            .validate(&ctx)
            .unwrap_err();
        assert!(e.contains("host.nmae"));
        assert!(
            Template::from_value("t", json!({"x": "{{host.name|bogus}}"}))
                .validate(&ctx)
                .is_err()
        );
    }
}
