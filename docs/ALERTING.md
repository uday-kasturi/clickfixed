# Alerting and outputs

Every output renders the same alert from one ECS-compatible schema. Elastic and Splunk ingest it without a custom parser, and engine-specific fields live under `clickfixed.*`. **See [`docs/sample-alert.json`](sample-alert.json)** for the full schema (a clipboard event and the execution that followed it). Each alert carries:

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

## Outputs

Enable outputs in `config.toml` (annotated in [`clickfixed.example.toml`](../clickfixed.example.toml)). Each one has a `min_severity` (a band name).

| output | config | what | env vars |
|---|---|---|---|
| stdout | `[outputs.stdout] enabled = true` | ECS JSON lines on stdout (logs go to stderr) | none |
| file | `[outputs.file] enabled = true`, `path` | Same JSON lines appended to a 0600 file; reopened on rotation. Wazuh, Filebeat or the Splunk UF tail it | none |
| syslog | `[outputs.syslog]`: `transport` unix/udp/tcp, `address`, `facility`, `format` | CEF (`CEF:0\|clickfixed\|…`): score, features, dampens, hashes and dedupe key in `cfp1`/`cs1`–`cs6`, decoded command in `msg` | none |
| webhook | `[[outputs.webhook]]`: `name`, `url`, `template`, `headers`, `timeout_secs`, `retries` | HTTP POST of a **template file** ([`templates/slack.json`](../templates/slack.json), [`templates/generic.json`](../templates/generic.json)). Adding Teams or PagerDuty means adding a template, not rebuilding | whatever `url`/`headers` reference, e.g. `CFX_SLACK_WEBHOOK_URL`, `CFX_GENERIC_WEBHOOK_TOKEN` |
| jira | `[outputs.jira]`: `base_url`, `project`, `issue_type`, `auth`, `user`, `token`, `template`, `on_duplicate` | One issue per host + command (see below). Field mapping = [`templates/jira.json`](../templates/jira.json) | `CFX_JIRA_USER`, `CFX_JIRA_API_TOKEN` |
| Wazuh | file output + [`wazuh/`](../wazuh/) | No API calls: `localfile` block, decoder, and rules generated from the mapping. See [`wazuh/README.md`](../wazuh/README.md) | none |

**Templates** are JSON with `{{field.path}}` placeholders that resolve against the alert, plus `fmt.*` helpers and `jira.*` for Jira. A string that is exactly one placeholder keeps the value's type (`"{{clickfixed.score}}"` renders a number, `"{{alert}}"` the whole alert). Substitution happens on parsed JSON, so decoded attacker text can't break out of a string. The `|slack` and `|jira` filters escape each platform's markup. Every placeholder is checked at startup, so a typo stops the daemon instead of sending blank fields.

**Jira deduplicates.** The dedupe key is stored on the issue as a label (`clickfixed-<32 hex>`). Before creating an issue, clickfixed searches for an open issue (status category not Done) with that label. If one exists, it adds a comment. If the new alert maps to a higher band, it also raises the priority, and it never lowers one. A re-copy, a later execution of the same pasted command, and the same command seen from a worse context all land on one ticket. Project, issue type, `search_path` (Cloud: `/rest/api/2/search/jql`; Data Center: `/rest/api/2/search`) and `on_duplicate` (`comment` / `skip`) are set in the config. Fields, including custom fields, are set in the template. Separately from Jira, `[alerts.dedupe] suppress_window_secs` drops an identical (dedupe key, action) pair before any output sees it, unless its severity is higher.

**Failure isolation.** Each output runs on its own thread with its own bounded queue. The detection threads only `try_send`. A webhook timeout or a Jira 500 affects that output alone (retries with backoff on transport errors, 429 and 5xx), and stdout, file and syslog keep flowing. Delivery errors are logged with the output name and dedupe-key prefix, never with URLs or response bodies.

## Secrets

Secrets live in **environment variables only**, never in `config.toml` and never in the repo. The config names each variable with `${VAR}`. At startup the loader resolves every reference for enabled outputs. If any are missing, the daemon exits with code 2 and lists every missing variable by name and the field that needs it. The loader also rejects a literal `token`, a literal credential header (`Authorization`, `*token*`, `*key*`, …) and a literal URL that embeds a credential (Slack/Teams hooks, `token=`, userinfo).

| variable | needed when |
|---|---|
| `CFX_SLACK_WEBHOOK_URL` | the `slack` webhook is enabled (the Slack URL is the credential) |
| `CFX_GENERIC_WEBHOOK_TOKEN` | the `generic` webhook is enabled (sent as `Authorization: Bearer …`) |
| `CFX_JIRA_USER` | Jira is enabled with `auth = "basic"` (Cloud account email) |
| `CFX_JIRA_API_TOKEN` | Jira is enabled (Cloud API token, or Data Center PAT with `auth = "bearer"`) |

You can rename them freely; the config is the source of truth. [`.env.example`](../.env.example) lists them with placeholder values. For local development, `--dotenv .env` loads a file (git-ignored, dev only, and real environment variables win). In production, use real environment variables, e.g. `EnvironmentFile=` in the systemd unit.

```sh
clickfixed alerts check --config config.toml          # validate env vars, templates, mapping; sends nothing
clickfixed alerts test  --config config.toml          # send one marked test alert to every enabled output
clickfixed alerts wazuh-rules --config config.toml    # Wazuh rules for this mapping
UPDATE_SAMPLES=1 cargo test -p cfx-alert              # regenerate docs/sample-alert.json(l) + wazuh rules
```
