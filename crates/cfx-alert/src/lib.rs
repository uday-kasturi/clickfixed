//! # cfx-alert
//!
//! The alerting and output layer for clickfixed.
//!
//! - [`schema::Alert`]: the one ECS-compatible alert every output renders from. Privacy
//!   rules (hash only, no raw text, no password-manager sources) are enforced here.
//! - [`severity::SeverityMap`]: one mapping from verdict + score to every output's
//!   severity form (Wazuh level, syslog, CEF, ECS, Slack colour, Jira priority).
//! - [`outputs`]: stdout and file (JSON lines), syslog (CEF), webhook (template files),
//!   Jira (deduplicated on host + command hash).
//! - [`sink::Sink`]: startup validation (secrets from env vars, fail loudly) and
//!   per-output threads and queues for failure isolation.

pub mod config;
pub mod outputs;
pub mod schema;
pub mod secrets;
pub mod severity;
pub mod sink;
pub mod template;
pub mod wazuh;

pub use config::{config_dir, state_dir, AlertsConfig, OutputsConfig};
pub use schema::{Action, Alert, AlertContext, AlertInput, Platform, ProcessInfo, Suppressed};
pub use secrets::Env;
pub use severity::{Band, SeverityMap, VerdictName};
pub use sink::{Sink, StartupError};
