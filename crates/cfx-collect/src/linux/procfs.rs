//! /proc polling exec source. Unprivileged; misses processes that live shorter than the
//! poll interval. Use the audit backend when you can.

use crate::ExecEvent;
use std::collections::HashSet;
use std::error::Error;
use std::sync::mpsc::Sender;
use std::time::{Duration, SystemTime};

/// (comm, exe) for a pid.
pub fn proc_info(pid: u32) -> (Option<String>, Option<String>) {
    let comm = std::fs::read_to_string(format!("/proc/{pid}/comm"))
        .ok()
        .map(|s| s.trim().to_ascii_lowercase());
    let exe = std::fs::read_link(format!("/proc/{pid}/exe"))
        .ok()
        .map(|p| p.display().to_string());
    (comm, exe)
}

fn ppid(pid: u32) -> Option<u32> {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    // comm may contain spaces/parens; fields after the last ')' are fixed.
    let rest = &stat[stat.rfind(')')? + 2..];
    rest.split_whitespace().nth(1)?.parse().ok()
}

fn pids() -> HashSet<u32> {
    std::fs::read_dir("/proc")
        .map(|d| {
            d.filter_map(|e| e.ok()?.file_name().to_str()?.parse().ok())
                .collect()
        })
        .unwrap_or_default()
}

pub fn poll(interval_ms: u64, tx: Sender<ExecEvent>) -> Result<(), Box<dyn Error + Send + Sync>> {
    let mut seen = pids();
    let me = std::process::id();
    tracing::info!(interval_ms, "procfs exec poller running");
    loop {
        std::thread::sleep(Duration::from_millis(interval_ms));
        let now = pids();
        for &pid in now.difference(&seen) {
            if pid == me {
                continue;
            }
            let Ok(raw) = std::fs::read(format!("/proc/{pid}/cmdline")) else {
                continue;
            };
            if raw.is_empty() {
                continue; // kernel thread or already gone
            }
            let argv: Vec<String> = raw
                .split(|b| *b == 0)
                .filter(|s| !s.is_empty())
                .map(|s| String::from_utf8_lossy(s).into_owned())
                .collect();
            let pp = ppid(pid);
            let ev = ExecEvent {
                pid,
                ppid: pp,
                argv,
                exe: proc_info(pid).1,
                parent_comm: pp.and_then(|p| proc_info(p).0),
                timestamp: SystemTime::now(),
            };
            if tx.send(ev).is_err() {
                return Ok(());
            }
        }
        seen = now;
    }
}
