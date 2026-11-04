//! Startup (config + secrets + templates, all validated up front) and fan-out.
//!
//! Failure isolation: every output has its own thread and its own bounded queue. `emit`
//! only ever `try_send`s, so a webhook timeout or a Jira 500 backs up that output's
//! queue alone; stdout, file and syslog keep flowing, and the detection threads that call
//! `emit` never block.

use crate::config::{AlertsConfig, JiraAuth, OutputsConfig};
use crate::outputs::jira::{Jira, JiraSettings, JiraTemplates};
use crate::outputs::jsonl::{JsonFile, Stdout};
use crate::outputs::syslog::Syslog;
use crate::outputs::webhook::Webhook;
use crate::outputs::{template_ctx, Http, Output};
use crate::schema::{Action, Alert, AlertContext, Platform};
use crate::secrets::{Env, Resolver};
use crate::severity::SeverityMap;
use crate::template::Template;
use base64::Engine as _;
use serde_json::json;
use std::collections::HashMap;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{sync_channel, SyncSender, TrySendError};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

const QUEUE: usize = 256;

#[derive(Debug)]
pub struct StartupError(pub Vec<String>);

impl std::fmt::Display for StartupError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "alerting configuration has {} problem(s):", self.0.len())?;
        for e in &self.0 {
            writeln!(f, "  - {e}")?;
        }
        Ok(())
    }
}

struct Handle {
    name: String,
    min_rank: usize,
    tx: Option<SyncSender<Arc<Alert>>>,
    thread: Option<JoinHandle<()>>,
    dropped: AtomicU64,
}

pub struct Sink {
    handles: Vec<Handle>,
    window: Duration,
    recent: Mutex<HashMap<(String, Action), (Instant, usize)>>,
}

fn host_name() -> String {
    gethostname::gethostname()
        .into_string()
        .unwrap_or_else(|_| "unknown".into())
}

fn user_name() -> String {
    ["SUDO_USER", "USER", "LOGNAME"]
        .iter()
        .find_map(|k| std::env::var(k).ok().filter(|v| !v.is_empty()))
        .unwrap_or_else(|| "unknown".into())
}

/// Resolve a config-relative path.
fn rel(base: &Path, p: &Path) -> std::path::PathBuf {
    if p.is_absolute() {
        p.to_path_buf()
    } else {
        base.join(p)
    }
}

impl Sink {
    /// Build every enabled output. Collects all problems (missing env vars by name, bad
    /// templates, unknown severity names, unreachable paths) and fails once, listing them.
    pub fn start(
        alerts: &AlertsConfig,
        outputs: &OutputsConfig,
        password_managers: Vec<String>,
        env: &Env,
        config_dir: &Path,
    ) -> Result<(Sink, AlertContext), StartupError> {
        let mut errs = Vec::new();
        let severity = match SeverityMap::new(alerts.severity.clone()) {
            Ok(m) => m,
            Err(e) => return Err(StartupError(vec![e])),
        };
        let ctx = AlertContext::new(
            alerts.host.clone().unwrap_or_else(host_name),
            alerts.user.clone().unwrap_or_else(user_name),
            Platform::current(),
            severity.clone(),
            password_managers,
        );
        let sample_ctx = template_ctx(&Alert::schema_sample());
        let mut r = Resolver::default();
        let mut built: Vec<(Box<dyn Output>, usize)> = Vec::new();

        let min_rank = |field: &str, v: &Option<String>, errs: &mut Vec<String>| match v {
            None => 0,
            Some(n) => severity.rank_of(n).unwrap_or_else(|| {
                errs.push(format!(
                    "{field}.min_severity: unknown band {n:?} (bands: {})",
                    severity
                        .bands()
                        .iter()
                        .map(|b| b.name.as_str())
                        .collect::<Vec<_>>()
                        .join(", ")
                ));
                0
            }),
        };

        if outputs.stdout.enabled {
            let m = min_rank("outputs.stdout", &outputs.stdout.min_severity, &mut errs);
            built.push((Box::new(Stdout), m));
        }
        if outputs.file.enabled {
            let m = min_rank("outputs.file", &outputs.file.min_severity, &mut errs);
            match JsonFile::open(rel(config_dir, &outputs.file.path)) {
                Ok(f) => built.push((Box::new(f), m)),
                Err(e) => errs.push(format!("outputs.file.path: {e}")),
            }
        }
        if outputs.syslog.enabled {
            let m = min_rank("outputs.syslog", &outputs.syslog.min_severity, &mut errs);
            match Syslog::new(&outputs.syslog, &ctx.host) {
                Ok(s) => built.push((Box::new(s), m)),
                Err(e) => errs.push(e),
            }
        }

        let mut names = std::collections::HashSet::new();
        for (i, w) in outputs.webhook.iter().enumerate() {
            let field = format!("outputs.webhook[{i}] ({})", w.name);
            if !names.insert(w.name.clone()) {
                errs.push(format!("{field}: duplicate webhook name"));
            }
            if !w.enabled {
                continue;
            }
            let m = min_rank(&field, &w.min_severity, &mut errs);
            let url = r.url(env, &format!("{field}.url"), &w.url);
            let headers: Vec<(String, String)> = w
                .headers
                .iter()
                .map(|(k, v)| (k.clone(), r.header(env, &format!("{field}.headers"), k, v)))
                .collect();
            let t = match Template::load(&rel(config_dir, &w.template)) {
                Ok(t) => t,
                Err(e) => {
                    errs.push(format!("{field}.template: {e}"));
                    continue;
                }
            };
            if let Err(e) = t.validate(&sample_ctx) {
                errs.push(format!("{field}: {e}"));
                continue;
            }
            built.push((
                Box::new(Webhook::new(
                    w.name.clone(),
                    url,
                    headers,
                    t,
                    Http::new(Duration::from_secs(w.timeout_secs), w.retries),
                )),
                m,
            ));
        }

        let j = &outputs.jira;
        if j.enabled {
            let m = min_rank("outputs.jira", &j.min_severity, &mut errs);
            for (k, v) in [
                ("base_url", &j.base_url),
                ("project", &j.project),
                ("issue_type", &j.issue_type),
            ] {
                if v.trim().is_empty() {
                    errs.push(format!("outputs.jira.{k} is required"));
                }
            }
            let base_url = r.expand(env, "outputs.jira.base_url", &j.base_url);
            let token = r.secret(env, "outputs.jira.token", &j.token);
            let auth_header = match j.auth {
                JiraAuth::Basic => {
                    if j.user.trim().is_empty() {
                        errs.push("outputs.jira.user is required for auth = \"basic\"".into());
                    }
                    let user = r.expand(env, "outputs.jira.user", &j.user);
                    format!(
                        "Basic {}",
                        base64::engine::general_purpose::STANDARD.encode(format!("{user}:{token}"))
                    )
                }
                JiraAuth::Bearer => format!("Bearer {token}"),
            };
            let jira_ctx = {
                let mut c = sample_ctx.clone();
                c.as_object_mut().unwrap().insert(
                    "jira".into(),
                    json!({"project": "", "issue_type": "", "dedupe_label": ""}),
                );
                c
            };
            match Template::load(&rel(config_dir, &j.template))
                .and_then(|t| t.validate(&jira_ctx).map(|_| t))
                .and_then(|t| JiraTemplates::from_template(&t))
            {
                Ok(t) => built.push((
                    Box::new(Jira::new(
                        JiraSettings {
                            base_url,
                            search_path: j.search_path.clone(),
                            project: j.project.clone(),
                            issue_type: j.issue_type.clone(),
                            auth_header,
                            label_prefix: j.dedupe_label_prefix.clone(),
                            on_duplicate: j.on_duplicate,
                        },
                        t,
                        Http::new(Duration::from_secs(j.timeout_secs), j.retries),
                        severity.clone(),
                    )),
                    m,
                )),
                Err(e) => errs.push(format!("outputs.jira.template: {e}")),
            }
        }

        errs.extend(r.errors);
        if !errs.is_empty() {
            return Err(StartupError(errs));
        }
        let handles = built.into_iter().map(|(o, m)| spawn(o, m)).collect();
        Ok((
            Sink {
                handles,
                window: Duration::from_secs(alerts.dedupe.suppress_window_secs),
                recent: Mutex::new(HashMap::new()),
            },
            ctx,
        ))
    }

    pub fn output_names(&self) -> Vec<&str> {
        self.handles.iter().map(|h| h.name.as_str()).collect()
    }

    /// Never blocks. Returns false if the alert was suppressed as a duplicate.
    pub fn emit(&self, alert: Alert) -> bool {
        let rank = alert.severity_rank();
        if !self.window.is_zero() {
            let mut recent = self.recent.lock().unwrap();
            recent.retain(|_, (at, _)| at.elapsed() < self.window);
            let k = (alert.dedupe_key().to_string(), alert.action());
            if let Some((_, prev)) = recent.get(&k) {
                if rank <= *prev {
                    tracing::debug!(
                        dedupe = &alert.dedupe_key()[..12],
                        "duplicate alert suppressed"
                    );
                    return false;
                }
            }
            recent.insert(k, (Instant::now(), rank));
        }
        let alert = Arc::new(alert);
        for h in &self.handles {
            if rank < h.min_rank {
                continue;
            }
            if let Some(tx) = &h.tx {
                match tx.try_send(alert.clone()) {
                    Ok(()) => {}
                    Err(TrySendError::Full(_)) => {
                        let n = h.dropped.fetch_add(1, Ordering::Relaxed) + 1;
                        tracing::warn!(output = %h.name, dropped = n, "output queue full; alert dropped for this output only");
                    }
                    Err(TrySendError::Disconnected(_)) => {
                        tracing::error!(output = %h.name, "output thread gone");
                    }
                }
            }
        }
        true
    }

    /// Drain every queue and stop the output threads.
    pub fn shutdown(mut self) {
        for h in &mut self.handles {
            h.tx.take();
        }
        for h in &mut self.handles {
            if let Some(t) = h.thread.take() {
                let _ = t.join();
            }
        }
    }
}

fn spawn(mut out: Box<dyn Output>, min_rank: usize) -> Handle {
    let name = out.name().to_string();
    let (tx, rx) = sync_channel::<Arc<Alert>>(QUEUE);
    let thread = std::thread::Builder::new()
        .name(format!("out-{name}"))
        .spawn(move || {
            for alert in rx {
                if let Err(e) = out.send(&alert) {
                    tracing::warn!(
                        output = out.name(),
                        error = %e,
                        dedupe = &alert.dedupe_key()[..12],
                        "alert delivery failed"
                    );
                }
            }
        })
        .expect("spawn output thread");
    Handle {
        name,
        min_rank,
        tx: Some(tx),
        thread: Some(thread),
        dropped: AtomicU64::new(0),
    }
}
