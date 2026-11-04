//! Platform collectors. The engine never knows which OS it is on; this crate is the only
//! place OS APIs appear.

use std::sync::mpsc::Receiver;
use std::time::SystemTime;

#[cfg(target_os = "linux")]
pub mod linux;

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

/// Each call starts a fresh watcher thread and returns its channel. A watcher that fails
/// logs the error and drops its sender, so the receiver simply disconnects; the other
/// signal keeps running.
pub trait Collector {
    fn clipboard_events(&self) -> Receiver<ClipboardEvent>;
    fn exec_events(&self) -> Receiver<ExecEvent>;
}

/// Paste-time prevention: replace what the user is about to paste.
pub trait ClipboardControl {
    fn replace_clipboard(&self, text: String) -> Result<(), String>;
}
