//! Platform collectors. The engine never knows which OS it is on; this crate is the only
//! place OS APIs appear.

use std::sync::mpsc::Receiver;
use std::time::SystemTime;

#[cfg(target_os = "linux")]
pub mod linux;
#[cfg(windows)]
pub mod windows;

/// The process that put content on the clipboard.
#[derive(Debug, Clone, Default)]
pub struct SourceApp {
    pub pid: Option<u32>,
    /// `/proc/<pid>/comm`, lowercased.
    pub name: Option<String>,
    pub exe: Option<String>,
}

#[derive(Debug, Clone)]
pub struct ClipboardEvent {
    pub text: String,
    pub source: SourceApp,
    /// Page URL the browser attached to the copy (`chromium/x-source-url`,
    /// `text/x-moz-url-priv`). Best effort; absent for many writes.
    pub source_url: Option<String>,
    /// True when content was larger than we read (INCR transfers are skipped).
    pub truncated: bool,
    pub timestamp: SystemTime,
}

#[derive(Debug, Clone)]
pub struct ExecEvent {
    pub pid: u32,
    pub ppid: Option<u32>,
    pub argv: Vec<String>,
    pub exe: Option<String>,
    pub parent_comm: Option<String>,
    pub timestamp: SystemTime,
}

/// Where the user is about to paste: a window that takes commands came to the foreground.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PasteTargetKind {
    /// The Windows Run dialog (Win+R).
    RunDialog,
    /// A terminal or shell window. `shell` is a short name such as `powershell` or `cmd`.
    Terminal { shell: String },
}

#[derive(Debug, Clone)]
pub struct PasteTarget {
    pub kind: PasteTargetKind,
    pub pid: Option<u32>,
    pub app: Option<String>,
    pub timestamp: SystemTime,
}

/// Each call starts a fresh watcher thread and returns its channel. A watcher that fails
/// logs the error and drops its sender, so the receiver simply disconnects; the other
/// signal keeps running.
pub trait Collector {
    fn clipboard_events(&self) -> Receiver<ClipboardEvent>;
    fn exec_events(&self) -> Receiver<ExecEvent>;
    /// Foreground changes to a paste target. Platforms that cannot see them return a
    /// receiver that is already disconnected.
    fn paste_targets(&self) -> Receiver<PasteTarget> {
        std::sync::mpsc::channel().1
    }
}

/// Paste-time prevention: replace what the user is about to paste.
pub trait ClipboardControl {
    fn replace_clipboard(&self, text: String) -> Result<(), String>;
}

/// Fire-and-forget desktop notification. Never blocks the caller.
///
/// `urgent` is for Block verdicts and flagged pastes that actually ran: they stay on screen
/// where the platform allows it. Everything else is shown once.
pub fn notify(title: &str, body: &str, urgent: bool) {
    #[cfg(target_os = "linux")]
    linux::notify(title, body, urgent);
    #[cfg(windows)]
    windows::notify(title, body, urgent);
    #[cfg(not(any(target_os = "linux", windows)))]
    let _ = (title, body, urgent);
}
