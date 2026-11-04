//! Secrets come from environment variables only.
//!
//! The config never holds a secret. It names the variable with `${VAR}`, and the loader
//! resolves every reference at startup. All missing variables are reported together,
//! by name, before any output starts.

use regex::Regex;
use std::collections::HashMap;
use std::path::Path;
use std::sync::LazyLock;

static REF: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}").unwrap());
static ONLY_REF: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^\$\{([A-Za-z_][A-Za-z0-9_]*)\}$").unwrap());

/// Process environment, optionally backed by a dev-only `.env` file. Real environment
/// variables always win over the file.
#[derive(Debug, Default, Clone)]
pub struct Env {
    dotenv: HashMap<String, String>,
}

impl Env {
    pub fn process() -> Self {
        Self::default()
    }

    /// Dev convenience only: `KEY=value` lines, `#` comments, optional quotes.
    pub fn with_dotenv(path: &Path) -> Result<Self, String> {
        let s = std::fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
        let mut dotenv = HashMap::new();
        for (n, line) in s.lines().enumerate() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let line = line.strip_prefix("export ").unwrap_or(line);
            let (k, v) = line
                .split_once('=')
                .ok_or_else(|| format!("{}:{}: expected KEY=value", path.display(), n + 1))?;
            let v = v.trim();
            let v = v
                .strip_prefix('"')
                .and_then(|x| x.strip_suffix('"'))
                .or_else(|| v.strip_prefix('\'').and_then(|x| x.strip_suffix('\'')))
                .unwrap_or(v);
            dotenv.insert(k.trim().to_string(), v.to_string());
        }
        Ok(Self { dotenv })
    }

    /// Explicit values (tests, embedding). Real environment variables still win.
    pub fn from_pairs(m: &[(&str, &str)]) -> Self {
        Self {
            dotenv: m
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
        }
    }

    pub fn get(&self, key: &str) -> Option<String> {
        std::env::var(key)
            .ok()
            .or_else(|| self.dotenv.get(key).cloned())
            .filter(|v| !v.is_empty())
    }
}

/// Collects every problem so startup can report them all at once.
#[derive(Debug, Default)]
pub struct Resolver {
    pub errors: Vec<String>,
}

impl Resolver {
    /// Expand `${VAR}` references in a non-secret-or-secret string field.
    pub fn expand(&mut self, env: &Env, field: &str, value: &str) -> String {
        REF.replace_all(value, |c: &regex::Captures| match env.get(&c[1]) {
            Some(v) => v,
            None => {
                self.errors.push(format!(
                    "missing environment variable {} (required by {field})",
                    &c[1]
                ));
                String::new()
            }
        })
        .into_owned()
    }

    /// A field that must be a secret: it has to be exactly `${VAR}`.
    pub fn secret(&mut self, env: &Env, field: &str, value: &str) -> String {
        if !ONLY_REF.is_match(value.trim()) {
            self.errors.push(format!(
                "{field} must name an environment variable, e.g. \"${{CFX_JIRA_API_TOKEN}}\"; secrets are never read from the config file"
            ));
            return String::new();
        }
        self.expand(env, field, value.trim())
    }

    /// Header values that carry credentials must come from the environment.
    pub fn header(&mut self, env: &Env, field: &str, name: &str, value: &str) -> String {
        let n = name.to_ascii_lowercase();
        let sensitive = [
            "authorization",
            "token",
            "key",
            "secret",
            "cookie",
            "signature",
        ]
        .iter()
        .any(|s| n.contains(s));
        if sensitive && !REF.is_match(value) {
            self.errors.push(format!(
                "{field}.{name} looks like a credential; reference an environment variable (\"Bearer ${{VAR}}\") instead of a literal"
            ));
            return String::new();
        }
        self.expand(env, &format!("{field}.{name}"), value)
    }

    /// Webhook URLs may be literal, but URLs that embed a credential must be `${VAR}`.
    pub fn url(&mut self, env: &Env, field: &str, value: &str) -> String {
        if !REF.is_match(value) {
            let l = value.to_ascii_lowercase();
            let embeds = l.contains("hooks.slack.com/services/")
                || l.contains("webhook.office.com")
                || ["token=", "key=", "sig=", "secret=", "code="]
                    .iter()
                    .any(|p| l.contains(p))
                || value
                    .split_once("://")
                    .is_some_and(|(_, r)| r.split('/').next().unwrap_or("").contains('@'));
            if embeds {
                self.errors.push(format!(
                    "{field} embeds a credential; put the URL in an environment variable and use \"${{VAR}}\""
                ));
                return String::new();
            }
        }
        self.expand(env, field, value)
    }
}

pub fn env_refs(value: &str) -> Vec<String> {
    REF.captures_iter(value).map(|c| c[1].to_string()).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_vars_named() {
        let env = Env::from_pairs(&[("CFX_A", "1")]);
        let mut r = Resolver::default();
        assert_eq!(r.expand(&env, "x", "${CFX_A}/${CFX_B_UNSET_TEST}"), "1/");
        assert_eq!(r.errors.len(), 1);
        assert!(r.errors[0].contains("CFX_B_UNSET_TEST"));
        assert!(r.errors[0].contains("x"));
    }

    #[test]
    fn literal_secrets_rejected() {
        let env = Env::default();
        let mut r = Resolver::default();
        r.secret(&env, "outputs.jira.token", "abc123");
        r.header(
            &env,
            "outputs.webhook[0].headers",
            "Authorization",
            "Bearer abc",
        );
        r.url(
            &env,
            "outputs.webhook[0].url",
            "https://hooks.slack.com/services/T/B/x",
        );
        assert_eq!(r.errors.len(), 3, "{:?}", r.errors);
        let mut ok = Resolver::default();
        ok.url(&env, "u", "https://soar.example/ingest");
        assert!(ok.errors.is_empty());
    }

    #[test]
    fn dotenv_parse() {
        let p = std::env::temp_dir().join(format!("cfx-dotenv-{}", std::process::id()));
        std::fs::write(&p, "# c\nexport CFX_T1=\"a b\"\nCFX_T2='c'\n\nCFX_T3=d\n").unwrap();
        let e = Env::with_dotenv(&p).unwrap();
        std::fs::remove_file(&p).ok();
        assert_eq!(e.get("CFX_T1").as_deref(), Some("a b"));
        assert_eq!(e.get("CFX_T2").as_deref(), Some("c"));
        assert_eq!(e.get("CFX_T3").as_deref(), Some("d"));
    }
}
