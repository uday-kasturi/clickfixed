//! Linux reference collectors.
//!
//! Clipboard: X11 via XFixes selection-owner notifications. On a Wayland session this runs
//! against XWayland; writes from native Wayland apps arrive through the compositor's
//! clipboard bridge, so their source app is the bridge and origin is lost. Documented in
//! THREAT_MODEL.md.
//!
//! Exec: auditd log (preferred, needs root and an execve rule) or /proc polling (no
//! privileges, lossy for very short-lived processes).

mod audit;
mod procfs;
mod x11;

use crate::{ClipboardControl, ClipboardEvent, Collector, ExecEvent};
use std::path::PathBuf;
use std::sync::mpsc::{channel, Receiver};

pub use procfs::proc_info;

#[derive(Debug, Clone)]
pub enum ExecBackend {
    Audit { log: PathBuf },
    Proc { interval_ms: u64 },
}

#[derive(Debug, Clone)]
pub struct LinuxCollector {
    pub exec_backend: ExecBackend,
    /// Clipboard payloads larger than this are truncated before reaching the engine.
    pub max_clipboard_bytes: usize,
}

impl Default for LinuxCollector {
    fn default() -> Self {
        Self {
            exec_backend: ExecBackend::Proc { interval_ms: 50 },
            max_clipboard_bytes: 256 * 1024,
        }
    }
}

impl Collector for LinuxCollector {
    fn clipboard_events(&self) -> Receiver<ClipboardEvent> {
        let (tx, rx) = channel();
        let max = self.max_clipboard_bytes;
        std::thread::Builder::new()
            .name("cfx-x11-clipboard".into())
            .spawn(move || {
                if let Err(e) = x11::watch(tx, max) {
                    tracing::error!(error = %e, "clipboard watcher stopped");
                }
            })
            .expect("spawn clipboard thread");
        rx
    }

    fn exec_events(&self) -> Receiver<ExecEvent> {
        let (tx, rx) = channel();
        let backend = self.exec_backend.clone();
        std::thread::Builder::new()
            .name("cfx-exec".into())
            .spawn(move || {
                let r = match backend {
                    ExecBackend::Audit { log } => audit::tail(&log, tx),
                    ExecBackend::Proc { interval_ms } => procfs::poll(interval_ms, tx),
                };
                if let Err(e) = r {
                    tracing::error!(error = %e, "exec watcher stopped");
                }
            })
            .expect("spawn exec thread");
        rx
    }
}

impl ClipboardControl for LinuxCollector {
    fn replace_clipboard(&self, text: String) -> Result<(), String> {
        x11::own_clipboard(text).map_err(|e| e.to_string())
    }
}

/// Desktop notification through `notify-send`. Critical urgency stays on screen in GNOME
/// until dismissed; normal is transient and does not re-present from the tray.
pub fn notify(title: &str, body: &str, urgent: bool) {
    let mut cmd = std::process::Command::new("notify-send");
    cmd.args(["-a", "clickfixed", "-i", "dialog-warning"]);
    if urgent {
        cmd.args(["-u", "critical"]);
    } else {
        cmd.args(["-u", "normal", "-e"]);
    }
    if let Ok(mut c) = cmd.args([title, body]).spawn() {
        std::thread::spawn(move || {
            let _ = c.wait();
        });
    }
}
