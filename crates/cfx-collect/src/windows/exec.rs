//! Execution events: a process snapshot poller, and the RunMRU registry key.
//!
//! The poller runs unprivileged. It reads each new process's command line with
//! `NtQueryInformationProcess(ProcessCommandLineInformation)`, which works for the user's
//! own processes. Processes that start and exit between two snapshots are missed; ETW
//! would catch them but needs administrator rights.
//!
//! RunMRU (`HKCU\...\Explorer\RunMRU`) is where Explorer records every command run from
//! Win+R, so a ClickFix paste into the Run dialog is seen there even if the process it
//! started was too short-lived for the poller. Those events report the parent as
//! `run_dialog`.

use super::util::{exe_name, process_image, read_user_string, wide};
use crate::ExecEvent;
use std::collections::{HashMap, HashSet};
use std::ptr::null_mut;
use std::sync::mpsc::Sender;
use std::time::{Duration, SystemTime};
use windows_sys::Wdk::System::Threading::{
    NtQueryInformationProcess, ProcessCommandLineInformation,
};
use windows_sys::Win32::Foundation::{
    CloseHandle, LocalFree, INVALID_HANDLE_VALUE, UNICODE_STRING,
};
use windows_sys::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W, TH32CS_SNAPPROCESS,
};
use windows_sys::Win32::System::Threading::{OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION};
use windows_sys::Win32::UI::Shell::CommandLineToArgvW;

const RUN_MRU: &str = r"Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU";

/// The parent name reported for commands run from Win+R.
pub const RUN_DIALOG_PARENT: &str = "run_dialog";

struct Proc {
    ppid: u32,
    name: String,
}

fn snapshot() -> Option<HashMap<u32, Proc>> {
    // SAFETY: the snapshot handle is checked and closed; dwSize is set before the first call.
    unsafe {
        let snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if snap == INVALID_HANDLE_VALUE || snap.is_null() {
            return None;
        }
        let mut out = HashMap::new();
        let mut e: PROCESSENTRY32W = std::mem::zeroed();
        e.dwSize = std::mem::size_of::<PROCESSENTRY32W>() as u32;
        let mut ok = Process32FirstW(snap, &mut e);
        while ok != 0 {
            out.insert(
                e.th32ProcessID,
                Proc {
                    ppid: e.th32ParentProcessID,
                    name: exe_name(&super::util::from_wide(&e.szExeFile)),
                },
            );
            ok = Process32NextW(snap, &mut e);
        }
        CloseHandle(snap);
        Some(out)
    }
}

/// A process's full command line, or `None` if it exited or belongs to another user.
fn command_line(pid: u32) -> Option<String> {
    // SAFETY: the buffer is sized by the first call and u64-aligned for UNICODE_STRING; the
    // string's Buffer points inside it. The handle is closed on every path.
    unsafe {
        let h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid);
        if h.is_null() {
            return None;
        }
        let mut len = 0u32;
        NtQueryInformationProcess(h, ProcessCommandLineInformation, null_mut(), 0, &mut len);
        if len == 0 || len > 1 << 20 {
            CloseHandle(h);
            return None;
        }
        let mut buf = vec![0u64; (len as usize).div_ceil(8)];
        let status = NtQueryInformationProcess(
            h,
            ProcessCommandLineInformation,
            buf.as_mut_ptr().cast(),
            len,
            &mut len,
        );
        CloseHandle(h);
        if status < 0 {
            return None;
        }
        let us = &*(buf.as_ptr() as *const UNICODE_STRING);
        if us.Buffer.is_null() || us.Length == 0 {
            return None;
        }
        let s = std::slice::from_raw_parts(us.Buffer, us.Length as usize / 2);
        Some(String::from_utf16_lossy(s))
    }
}

/// Split a command line the way the C runtime does.
fn split_args(cmd: &str) -> Vec<String> {
    if cmd.trim().is_empty() {
        return Vec::new();
    }
    let w = wide(cmd);
    let mut n = 0i32;
    // SAFETY: CommandLineToArgvW returns one LocalAlloc block that is freed here.
    unsafe {
        let argv = CommandLineToArgvW(w.as_ptr(), &mut n);
        if argv.is_null() {
            return vec![cmd.to_string()];
        }
        let out = (0..n as usize)
            .map(|i| {
                let p = *argv.add(i);
                let len = (0..).take_while(|&j| *p.add(j) != 0).count();
                String::from_utf16_lossy(std::slice::from_raw_parts(p, len))
            })
            .collect();
        LocalFree(argv.cast());
        out
    }
}

pub fn poll_processes(tx: Sender<ExecEvent>, interval_ms: u64) {
    let mut known: HashSet<u32> = snapshot()
        .map(|s| s.into_keys().collect())
        .unwrap_or_default();
    tracing::info!(interval_ms, "windows process poller running");
    loop {
        std::thread::sleep(Duration::from_millis(interval_ms));
        let Some(snap) = snapshot() else { continue };
        for (&pid, p) in &snap {
            if known.contains(&pid) || pid == std::process::id() {
                continue;
            }
            let argv = command_line(pid)
                .map(|c| split_args(&c))
                .filter(|a| !a.is_empty())
                .unwrap_or_else(|| vec![p.name.clone()]);
            let ev = ExecEvent {
                pid,
                ppid: Some(p.ppid),
                argv,
                exe: process_image(pid),
                parent_comm: snap.get(&p.ppid).map(|pp| pp.name.clone()),
                timestamp: SystemTime::now(),
            };
            if tx.send(ev).is_err() {
                return;
            }
        }
        known = snap.into_keys().collect();
    }
}

/// The most recent Run dialog command: (MRUList, command).
fn latest_run() -> Option<(String, String)> {
    let order = read_user_string(RUN_MRU, "MRUList")?;
    let first = order.chars().next()?.to_string();
    let cmd = read_user_string(RUN_MRU, &first)?;
    // Explorer stores each entry with a trailing "\1".
    let cmd = cmd.strip_suffix(r"\1").unwrap_or(&cmd).to_string();
    Some((order, cmd))
}

pub fn watch_run_mru(tx: Sender<ExecEvent>, interval_ms: u64) {
    let mut last = latest_run();
    loop {
        std::thread::sleep(Duration::from_millis(interval_ms));
        let cur = latest_run();
        if cur.is_some() && cur != last {
            let (_, cmd) = cur.clone().unwrap();
            let argv = split_args(&cmd);
            let ev = ExecEvent {
                pid: 0,
                ppid: None,
                exe: argv.first().map(|a| a.to_string()),
                argv: if argv.is_empty() { vec![cmd] } else { argv },
                parent_comm: Some(RUN_DIALOG_PARENT.to_string()),
                timestamp: SystemTime::now(),
            };
            if tx.send(ev).is_err() {
                return;
            }
        }
        last = cur;
    }
}
