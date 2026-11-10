//! Windows collectors.
//!
//! - Clipboard: a hidden window registered with `AddClipboardFormatListener`. The clipboard
//!   owner's process gives the source app; Chromium and Firefox attach the page URL.
//! - Paste target: a foreground-window hook. When the Run dialog or a terminal comes to the
//!   front, the daemon re-scores the current clipboard with that target, before Ctrl+V.
//! - Exec: a process snapshot poller (command lines via `NtQueryInformationProcess`), plus
//!   the RunMRU registry key, which records exactly what was run from Win+R.
//! - Notifications: a tray balloon, shown as a toast on Windows 10 and 11.
//!
//! Everything runs as the logged-in user. The clipboard and foreground window belong to
//! the user's desktop session, which a Windows service cannot see, so clickfixed starts
//! at login instead (see [`autostart`]).

pub mod autostart;
mod clipboard;
mod exec;
mod focus;
mod notify;
mod util;

pub use notify::notify;

use crate::{ClipboardControl, ClipboardEvent, Collector, ExecEvent, PasteTarget};
use std::sync::mpsc::{channel, Receiver};

#[derive(Debug, Clone)]
pub struct WindowsCollector {
    /// Process snapshot interval. Short-lived processes can be missed between snapshots;
    /// RunMRU still records commands run from Win+R.
    pub exec_interval_ms: u64,
    /// Clipboard payloads larger than this are truncated before reaching the engine.
    pub max_clipboard_bytes: usize,
}

impl Default for WindowsCollector {
    fn default() -> Self {
        Self {
            exec_interval_ms: 50,
            max_clipboard_bytes: 256 * 1024,
        }
    }
}

fn spawn(name: &str, f: impl FnOnce() + Send + 'static) {
    if let Err(e) = std::thread::Builder::new().name(name.into()).spawn(f) {
        tracing::error!(thread = name, error = %e, "cannot start collector thread");
    }
}

impl Collector for WindowsCollector {
    fn clipboard_events(&self) -> Receiver<ClipboardEvent> {
        let (tx, rx) = channel();
        let max = self.max_clipboard_bytes;
        spawn("cfx-win-clipboard", move || {
            if let Err(e) = clipboard::watch(tx, max) {
                tracing::error!(error = %e, "clipboard watcher stopped");
            }
        });
        rx
    }

    fn exec_events(&self) -> Receiver<ExecEvent> {
        let (tx, rx) = channel();
        let interval = self.exec_interval_ms;
        let mru_tx = tx.clone();
        spawn("cfx-win-exec", move || exec::poll_processes(tx, interval));
        spawn("cfx-win-runmru", move || exec::watch_run_mru(mru_tx, 250));
        rx
    }

    fn paste_targets(&self) -> Receiver<PasteTarget> {
        let (tx, rx) = channel();
        spawn("cfx-win-focus", move || {
            if let Err(e) = focus::watch(tx) {
                tracing::error!(error = %e, "foreground watcher stopped");
            }
        });
        rx
    }
}

impl ClipboardControl for WindowsCollector {
    fn replace_clipboard(&self, text: String) -> Result<(), String> {
        clipboard::replace(&text)
    }
}

/// Detach from the console window, for `run --background` started at login.
pub fn detach_console() {
    // SAFETY: FreeConsole has no preconditions; failure (no console) is harmless.
    unsafe {
        windows_sys::Win32::System::Console::FreeConsole();
    }
}
