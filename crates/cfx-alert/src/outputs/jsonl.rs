//! JSON lines (ECS field names): stdout, and an append-only file for Wazuh to tail.

use super::Output;
use crate::schema::Alert;
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::PathBuf;

/// Identity of the file behind a path, to notice rotation: the inode on Unix, the
/// creation time on Windows (a rotated log is a new file with a new creation time).
fn file_id(m: &std::fs::Metadata) -> u64 {
    #[cfg(unix)]
    {
        std::os::unix::fs::MetadataExt::ino(m)
    }
    #[cfg(windows)]
    {
        std::os::windows::fs::MetadataExt::creation_time(m)
    }
    #[cfg(not(any(unix, windows)))]
    {
        m.len()
    }
}

pub struct Stdout;

impl Output for Stdout {
    fn name(&self) -> &str {
        "stdout"
    }
    fn send(&mut self, alert: &Alert) -> Result<(), String> {
        let mut out = std::io::stdout().lock();
        writeln!(out, "{}", alert.to_json_line())
            .and_then(|_| out.flush())
            .map_err(|e| format!("stdout: {e}"))
    }
}

/// Appends one alert per line. Reopens when the file is rotated or removed
/// (logrotate `create` or `copytruncate` both work).
pub struct JsonFile {
    path: PathBuf,
    file: Option<(File, u64)>,
}

impl JsonFile {
    pub fn open(path: PathBuf) -> Result<Self, String> {
        let mut f = Self { path, file: None };
        f.reopen()?;
        Ok(f)
    }

    fn reopen(&mut self) -> Result<(), String> {
        if let Some(dir) = self.path.parent() {
            std::fs::create_dir_all(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
        }
        let mut opts = OpenOptions::new();
        opts.create(true).append(true);
        // Windows: the default state dir (%LOCALAPPDATA%) is already private to the user.
        #[cfg(unix)]
        std::os::unix::fs::OpenOptionsExt::mode(&mut opts, 0o600);
        let f = opts
            .open(&self.path)
            .map_err(|e| format!("{}: {e}", self.path.display()))?;
        let ino = f.metadata().map(|m| file_id(&m)).unwrap_or(0);
        self.file = Some((f, ino));
        Ok(())
    }

    fn rotated(&self) -> bool {
        match (&self.file, std::fs::metadata(&self.path)) {
            (Some((_, ino)), Ok(m)) => file_id(&m) != *ino,
            _ => true,
        }
    }
}

impl Output for JsonFile {
    fn name(&self) -> &str {
        "file"
    }
    fn send(&mut self, alert: &Alert) -> Result<(), String> {
        if self.rotated() {
            self.reopen()?;
        }
        let line = format!("{}\n", alert.to_json_line());
        let (f, _) = self.file.as_mut().expect("opened");
        // One write call per line: O_APPEND keeps lines whole for a concurrent reader.
        f.write_all(line.as_bytes())
            .map_err(|e| format!("{}: {e}", self.path.display()))
    }
}
