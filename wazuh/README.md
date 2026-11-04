# Wazuh integration

clickfixed doesn't call the Wazuh API. It writes ECS JSON lines to a file, the Wazuh agent tails that file, and the manager decodes the lines and assigns rule levels from the same severity mapping every other output uses.

| file | goes to | what |
|---|---|---|
| `ossec.conf.localfile.xml` | agent: `/var/ossec/etc/ossec.conf` | `<localfile>` block, `log_format json` |
| `decoders/clickfixed_decoders.xml` | manager: `/var/ossec/etc/decoders/` | JSON decoder scoped to clickfixed events |
| `rules/clickfixed_rules.xml` | manager: `/var/ossec/etc/rules/` | rule ids 100800–100899; one rule per severity band |

## Deploy

1. **clickfixed:** enable the file output and point it at a stable path:

   ```toml
   [outputs.file]
   enabled = true
   path = "/var/log/clickfixed/alerts.json"
   ```

   Rotate it with logrotate (`create` or `copytruncate` both work). clickfixed reopens the file when it's rotated.

2. **Agent** (each endpoint): paste `ossec.conf.localfile.xml` inside `<ossec_config>`. Make sure the `location` matches the path from step 1. Then run `systemctl restart wazuh-agent`.

3. **Manager:**

   ```sh
   cp decoders/clickfixed_decoders.xml /var/ossec/etc/decoders/
   cp rules/clickfixed_rules.xml       /var/ossec/etc/rules/
   chown wazuh:wazuh /var/ossec/etc/{decoders,rules}/clickfixed_*.xml
   systemctl restart wazuh-manager
   ```

4. **Verify** on the manager with a line from `../docs/sample-alert.jsonl`:

   ```sh
   /var/ossec/bin/wazuh-logtest
   # paste one line; expect rule 100811 (band "high") or 100812 ("critical"), level 12/14
   ```

## Rule levels come from the mapping

`rules/clickfixed_rules.xml` is **generated** from `[[alerts.severity]]`. Don't hand-edit the levels. If you change the mapping, regenerate the rules and redeploy:

```sh
clickfixed alerts wazuh-rules --config /etc/clickfixed/config.toml > rules/clickfixed_rules.xml
```

With the default mapping, the generated rules are:

| rule id | band | engine verdict | Wazuh level |
|---|---|---|---|
| 100810 | medium | suspicious | 7 |
| 100811 | high | malicious | 12 |
| 100812 | critical | malicious, score ≥ 3.0 | 14 |

A test (`committed_wazuh_rules_match_default_mapping`) fails if the committed file drifts from the default mapping.

## Useful fields in rules and dashboards

- `event.action`: `clipboard-command-flagged`, `pasted-command-executed` or `suspicious-command-executed`.
- `clickfixed.dedupe_key`: groups every sighting of one command on one host.
- `clickfixed.command.sha256` and `clickfixed.command.decoded`: the raw command is never in the log.
- `url.domain`: the page the command was copied from.
- `clickfixed.origin.source_app`: the app that wrote the clipboard.
- `clickfixed.analytic.id`: AN0963 on Linux.

A pasted-command-executed event shares the dedupe key with the earlier clipboard event. A Wazuh correlation rule (`if_matched_sid` + `same_field`) can escalate on it if you want that.

## Not verified here

These files follow the Wazuh 4.x decoder and rule syntax, but they were not loaded into a live Wazuh manager in this repo's CI. Run `wazuh-logtest` (step 4) before relying on them.
