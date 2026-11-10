use cfx_alert::{AlertsConfig, OutputsConfig};
use cfx_engine::{DomainClassifier, UserRole};
use serde::Deserialize;
use std::path::PathBuf;

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Mode {
    /// Desktop notification only.
    Warn,
    /// On a Block verdict, replace the clipboard content before it can be pasted.
    Block,
}

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ExecSource {
    Proc,
    Audit,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    #[serde(default = "d_mode")]
    pub mode: Mode,
    #[serde(default = "d_role")]
    pub role: UserRole,
    #[serde(default)]
    pub domains: DomainClassifier,
    /// Content from these apps is never scored, hashed into reports, or logged.
    #[serde(default = "d_pw")]
    pub password_managers: Vec<String>,
    #[serde(default = "d_browsers")]
    pub browsers: Vec<String>,
    /// Exec parents that mean "the user ran this in an interactive shell".
    #[serde(default = "d_shells")]
    pub shells: Vec<String>,
    #[serde(default = "d_ttl")]
    pub hash_buffer_ttl_secs: u64,
    #[serde(default = "d_exec")]
    pub exec_source: ExecSource,
    /// auditd log for `exec_source = "audit"` (Linux only).
    #[serde(default = "d_audit")]
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    pub audit_log: PathBuf,
    #[serde(default = "d_reports")]
    pub reports_dir: PathBuf,
    #[serde(default = "d_true")]
    pub notify: bool,
    /// Alert schema settings: severity mapping, dedupe, host/user overrides.
    #[serde(default)]
    pub alerts: AlertsConfig,
    /// Alert outputs: stdout, file, syslog, webhook, jira.
    #[serde(default)]
    pub outputs: OutputsConfig,
    /// Directory relative output paths (templates, files) resolve against.
    #[serde(skip)]
    pub config_dir: PathBuf,
}

fn d_mode() -> Mode {
    Mode::Warn
}
fn d_role() -> UserRole {
    UserRole::Unknown
}
fn d_ttl() -> u64 {
    6 * 3600
}
fn d_exec() -> ExecSource {
    ExecSource::Proc
}
fn d_audit() -> PathBuf {
    "/var/log/audit/audit.log".into()
}
fn d_true() -> bool {
    true
}
fn d_reports() -> PathBuf {
    cfx_alert::state_dir().join("reports")
}
fn d_pw() -> Vec<String> {
    [
        "keepassxc",
        "1password",
        "bitwarden",
        "lastpass",
        "enpass",
        "gopass",
        "seahorse",
        "pass",
        "passmenu",
        // Windows process names
        "keepass",
        "dashlane",
        "nordpass",
        "roboform",
        "proton pass",
    ]
    .map(String::from)
    .to_vec()
}
fn d_browsers() -> Vec<String> {
    [
        "firefox",
        "firefox-bin",
        "chrome",
        "chromium",
        "chromium-browse",
        "brave",
        "brave-browser",
        "msedge",
        "vivaldi-bin",
        "opera",
        "librewolf",
        // Windows process names
        "vivaldi",
        "arc",
        "zen",
        "waterfox",
    ]
    .map(String::from)
    .to_vec()
}
fn d_shells() -> Vec<String> {
    let names: &[&str] = if cfg!(windows) {
        // `run_dialog` is the parent reported for commands recorded in RunMRU. Explorer
        // launches what the user starts from the desktop or Start; only programs that
        // run their arguments (see correlate::runs_its_arguments) are scored.
        &[
            "cmd",
            "powershell",
            "pwsh",
            "windowsterminal",
            "explorer",
            "run_dialog",
            "bash",
            "wsl",
        ]
    } else {
        &["bash", "zsh", "fish", "sh", "dash", "ksh", "pwsh", "nu"]
    };
    names.iter().map(|s| s.to_string()).collect()
}

impl Default for Config {
    fn default() -> Self {
        toml::from_str("").expect("defaults")
    }
}

impl Config {
    pub fn load(path: Option<&std::path::Path>) -> Result<Self, String> {
        match path {
            Some(p) => {
                let s = std::fs::read_to_string(p).map_err(|e| format!("{}: {e}", p.display()))?;
                let mut c: Self =
                    toml::from_str(&s).map_err(|e| format!("{}: {e}", p.display()))?;
                c.config_dir = p
                    .parent()
                    .map(|d| {
                        if d.as_os_str().is_empty() {
                            PathBuf::from(".")
                        } else {
                            d.to_path_buf()
                        }
                    })
                    .unwrap_or_else(|| ".".into());
                Ok(c)
            }
            None => {
                // The per-user config, if one exists: ~/.config/clickfixed/config.toml or
                // %APPDATA%\clickfixed\config.toml.
                let default = cfx_alert::config_dir().join("config.toml");
                if default.is_file() {
                    return Self::load(Some(&default));
                }
                Ok(Self {
                    config_dir: ".".into(),
                    ..Self::default()
                })
            }
        }
    }

    pub fn is_password_manager(&self, app: &str) -> bool {
        self.password_managers
            .iter()
            .any(|p| app.eq_ignore_ascii_case(p) || app.contains(p.as_str()))
    }

    pub fn is_browser(&self, app: &str) -> bool {
        self.browsers
            .iter()
            .any(|b| app.eq_ignore_ascii_case(b) || app.starts_with(b.as_str()))
    }
}
