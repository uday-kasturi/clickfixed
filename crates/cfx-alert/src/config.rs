//! `[alerts]` and `[outputs.*]` sections of config.toml. Non-secret settings only;
//! secrets are `${VAR}` references resolved from the environment at startup.

use crate::severity::{default_bands, Band};
use serde::Deserialize;
use std::collections::BTreeMap;
use std::path::PathBuf;

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AlertsConfig {
    /// Override the host name stamped on alerts (default: system hostname).
    pub host: Option<String>,
    /// Override the user name (default: $SUDO_USER, then $USER).
    pub user: Option<String>,
    /// Severity bands, lowest to highest. One mapping for every output.
    #[serde(default = "default_bands")]
    pub severity: Vec<Band>,
    #[serde(default)]
    pub dedupe: DedupeConfig,
}

impl Default for AlertsConfig {
    fn default() -> Self {
        toml::from_str("").expect("defaults")
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DedupeConfig {
    /// An alert with the same dedupe key and action as one sent within this window is
    /// dropped before any output sees it, unless its severity is higher. 0 disables.
    #[serde(default = "d_window")]
    pub suppress_window_secs: u64,
}

impl Default for DedupeConfig {
    fn default() -> Self {
        Self {
            suppress_window_secs: d_window(),
        }
    }
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OutputsConfig {
    #[serde(default)]
    pub stdout: StdoutConfig,
    #[serde(default)]
    pub file: FileConfig,
    #[serde(default)]
    pub syslog: SyslogConfig,
    #[serde(default)]
    pub webhook: Vec<WebhookConfig>,
    #[serde(default)]
    pub jira: JiraConfig,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StdoutConfig {
    #[serde(default)]
    pub enabled: bool,
    /// Lowest severity band name sent to this output (default: all bands).
    pub min_severity: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FileConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "d_alert_log")]
    pub path: PathBuf,
    pub min_severity: Option<String>,
}

impl Default for FileConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            path: d_alert_log(),
            min_severity: None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SyslogTransport {
    Unix,
    Udp,
    Tcp,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SyslogFormat {
    Rfc5424,
    Rfc3164,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SyslogConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "d_transport")]
    pub transport: SyslogTransport,
    /// Socket path for unix, host:port for udp/tcp.
    #[serde(default = "d_syslog_addr")]
    pub address: String,
    /// Default: rfc3164 for the local socket, rfc5424 for the network.
    pub format: Option<SyslogFormat>,
    #[serde(default = "d_facility")]
    pub facility: String,
    pub min_severity: Option<String>,
}

impl Default for SyslogConfig {
    fn default() -> Self {
        toml::from_str("").expect("defaults")
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WebhookConfig {
    pub name: String,
    #[serde(default = "d_true")]
    pub enabled: bool,
    /// Literal URL, or `${VAR}` when the URL itself is a credential (Slack, Teams).
    pub url: String,
    /// Path to a JSON template, relative to the config file.
    pub template: PathBuf,
    /// Extra headers. Credential headers must reference env vars: `"Bearer ${VAR}"`.
    #[serde(default)]
    pub headers: BTreeMap<String, String>,
    #[serde(default = "d_timeout")]
    pub timeout_secs: u64,
    /// Retries on transport errors, HTTP 429 and 5xx. 4xx is not retried.
    #[serde(default = "d_retries")]
    pub retries: u32,
    pub min_severity: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum JiraAuth {
    /// Jira Cloud: account email + API token.
    Basic,
    /// Jira Data Center / Server: personal access token.
    Bearer,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OnDuplicate {
    /// Comment on the open issue (and raise its priority if this alert is more severe).
    Comment,
    /// Leave the open issue untouched.
    Skip,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JiraConfig {
    #[serde(default)]
    pub enabled: bool,
    /// e.g. https://yourorg.atlassian.net
    #[serde(default)]
    pub base_url: String,
    #[serde(default)]
    pub project: String,
    #[serde(default = "d_issue_type")]
    pub issue_type: String,
    #[serde(default = "d_auth")]
    pub auth: JiraAuth,
    /// Account email for basic auth. Literal or `${VAR}`.
    #[serde(default)]
    pub user: String,
    /// Must be `${VAR}`.
    #[serde(default = "d_jira_token")]
    pub token: String,
    #[serde(default = "d_jira_template")]
    pub template: PathBuf,
    /// Cloud: /rest/api/2/search/jql. Data Center / Server: /rest/api/2/search.
    #[serde(default = "d_search_path")]
    pub search_path: String,
    /// The dedupe key is stored on the issue as a label: `<prefix><first 32 hex>`.
    #[serde(default = "d_label_prefix")]
    pub dedupe_label_prefix: String,
    #[serde(default = "d_on_dup")]
    pub on_duplicate: OnDuplicate,
    #[serde(default = "d_timeout")]
    pub timeout_secs: u64,
    #[serde(default = "d_retries")]
    pub retries: u32,
    pub min_severity: Option<String>,
}

impl Default for JiraConfig {
    fn default() -> Self {
        toml::from_str("").expect("defaults")
    }
}

fn d_true() -> bool {
    true
}
fn d_window() -> u64 {
    3600
}
fn d_timeout() -> u64 {
    5
}
fn d_retries() -> u32 {
    2
}
fn d_transport() -> SyslogTransport {
    if cfg!(unix) {
        SyslogTransport::Unix
    } else {
        SyslogTransport::Udp
    }
}
fn d_syslog_addr() -> String {
    if cfg!(unix) {
        "/dev/log".into()
    } else {
        "127.0.0.1:514".into()
    }
}
fn d_facility() -> String {
    "local4".into()
}
fn d_issue_type() -> String {
    "Bug".into()
}
fn d_auth() -> JiraAuth {
    JiraAuth::Basic
}
fn d_jira_token() -> String {
    "${CFX_JIRA_API_TOKEN}".into()
}
fn d_jira_template() -> PathBuf {
    "templates/jira.json".into()
}
fn d_search_path() -> String {
    "/rest/api/2/search/jql".into()
}
fn d_label_prefix() -> String {
    "clickfixed-".into()
}
fn d_on_dup() -> OnDuplicate {
    OnDuplicate::Comment
}
pub fn d_alert_log() -> PathBuf {
    state_dir().join("alerts.json")
}

/// Per-user state directory: `%LOCALAPPDATA%\clickfixed` on Windows,
/// `$XDG_STATE_HOME/clickfixed` (default `~/.local/state/clickfixed`) elsewhere.
pub fn state_dir() -> PathBuf {
    let base = if cfg!(windows) {
        std::env::var_os("LOCALAPPDATA").map(PathBuf::from)
    } else {
        std::env::var_os("XDG_STATE_HOME")
            .map(PathBuf::from)
            .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".local/state")))
    };
    base.unwrap_or_else(std::env::temp_dir).join("clickfixed")
}

/// Per-user config directory: `%APPDATA%\clickfixed` on Windows,
/// `$XDG_CONFIG_HOME/clickfixed` (default `~/.config/clickfixed`) elsewhere.
pub fn config_dir() -> PathBuf {
    let base = if cfg!(windows) {
        std::env::var_os("APPDATA").map(PathBuf::from)
    } else {
        std::env::var_os("XDG_CONFIG_HOME")
            .map(PathBuf::from)
            .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".config")))
    };
    base.unwrap_or_else(|| ".".into()).join("clickfixed")
}

pub fn facility_code(name: &str) -> Option<u8> {
    Some(match name {
        "kern" => 0,
        "user" => 1,
        "daemon" => 3,
        "auth" => 4,
        "syslog" => 5,
        "authpriv" => 10,
        "local0" => 16,
        "local1" => 17,
        "local2" => 18,
        "local3" => 19,
        "local4" => 20,
        "local5" => 21,
        "local6" => 22,
        "local7" => 23,
        _ => return None,
    })
}
