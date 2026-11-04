# Threat model

## What clickfixed is for

It catches a user pasting an attacker-supplied command into a shell (T1204.004) **at paste time**, and it alerts when such a command runs. MITRE's three listed mitigations (execution prevention, network IPS, restricting web content) don't act at the moment of paste. That gap is the target.

## Assets and trust boundaries

| Thing | Who controls it |
|---|---|
| Command text, encoding, decoy prose | **Attacker** |
| Attacker's domains and hosting (incl. github.com, raw.githubusercontent.com, compromised sites) | **Attacker** |
| Which site the user actually visited (origin) | Not the attacker |
| Which app wrote the clipboard (source app) | Not the attacker |
| Structural facts (is it a JWT, does the pipeline end at `base64 -d`) | Not the attacker, without making the payload benign |
| Target (terminal vs Run dialog) and victim role | Partially the attacker (they choose the lure and the audience) |

Allowlist entries may only depend on the "not the attacker" rows. The loader enforces this.

## What is caught

- **Run-dialog / Win+X lures**: mshta, regsvr32, rundll32, msiexec, certutil and finger abuse; PowerShell fetch-and-execute; hidden windows; `conhost --headless`. Context multipliers make these the highest-scoring class.
- **Terminal lures** (Linux/macOS): `curl | sh`, `bash -c "$(curl …)"`, `| python3 -`, base64 or hex decoded into a shell, download-then-execute, LaunchAgent/crontab/rc persistence.
- **Shallow obfuscation**, resolved inline: base64 (incl. PowerShell UTF-16LE), gzip/deflate+base64, hex, percent, char codes, literal concatenation, caret/quote/backtick insertion, reversed literals. The wrapper keeps its weight when the inner layer resolves.
- **The RunMRU evasions** (Win+X; typing `cmd.exe` into Win+R first). The clipboard still holds the real command, and the engine scores the clipboard, not the registry.
- **Clipboard managers**: a re-write of known content inherits its first origin, and correlation is by content hash rather than recency, so pasting from history still matches.

## What is missed (accepted v1 limitations)

- **Identical command, unclassified origin.** A fake "Claude Code installer" is byte-for-byte the Homebrew shape. With a browser origin outside the vendor list it **warns**. With no origin at all (typed, or lost through the Wayland bridge) it scores 0.8 and does **not** warn. Only origin separates the two.
- **Typed commands.** No clipboard match means no origin. They fall to Signal 2 heuristics, which are weaker: detection drops from 100% to 85% on the corpus in no-context mode.
- **The deobfuscation boundary.** We resolve pure encodings and literal concatenation only. Anything that needs runtime state is not resolved: environment variables, `$var` indirection, PowerShell automatic variables, aliases, fetched second stages, format operators. The encoding-marker signal still fires, because detecting obfuscation is free, but the decoded content is not seen. **This is deliberate.** The engine is not an interpreter.
- **Deep nesting.** Past 2 decode layers or 5 ms, the fast path stops and flags `needs_deep_analysis`. Signal 3 goes to 5 layers / 500 ms. Past that, nothing more is resolved.
- **Synthetic paste.** Clipboard managers that *type* text fire no paste hook. Signal 2 still sees the exec.
- **Short-lived processes** with the `/proc` exec backend. Use auditd.
- **Wayland-native sources.** Origin is lost through the compositor bridge (see README).
- **Large clipboard content.** X11 INCR transfers are skipped, and content over 256 KB is truncated.
- **Allowlisted domains are an evasion surface.** A compromised vendor-docs or internal page would get its fetch-and-execute dampened. Dampening is per feature and partial, so hidden windows, persistence, encoding or decoy prose still score. Keep both domain lists short.
- **Platforms.** No Windows or macOS collectors in v1. Windows needs a clipboard listener plus ETW process creation (AN0962). macOS needs pasteboard polling plus `eslogger` under Full Disk Access (AN0964); the Endpoint Security entitlement requires Apple sign-off that individuals rarely get, and that problem is not solved here.

## Privacy

- Clipboard text is held in memory only while it is scored. The correlation buffer stores SHA-256 hashes of the full content and of each command segment, never the text.
- Logs contain a hash prefix, the verdict, feature ids and the source-app name. They never contain content.
- Password-manager sources are skipped before scoring and never logged.
- Signal 3 reports (which include decoded content) are written only for warn+ verdicts, locally, mode 0600.
- **Alerts** (stdout, file, syslog, webhook, Jira) are built by one schema that never receives the raw text: they carry the command's SHA-256, the deobfuscator's decoded layer when one resolved, feature ids and weights, and the sanitized origin URL (no userinfo, query or fragment). Feature evidence snippets are not included, and password-manager sources are refused at the schema. Webhook and Jira outputs do send that alert off the machine, but only to the endpoints you configure. Note that a decoded layer keeps the parts of the command that were not encoded, so it can still show some command structure.
- Alerting secrets come only from environment variables; the config references them by name.
- Employee-monitoring objections are real: a tool that observes all clipboard writes is surveillance-shaped even when it discards content. OS vendors are also tightening background clipboard access (Wayland already does). Both constrain deployment.

## Safety of this repo

Corpus commands are stored as text with `.invalid` hosts. The engine never executes anything. The demo lure runs only on 127.0.0.1, and its payload prints a message.
