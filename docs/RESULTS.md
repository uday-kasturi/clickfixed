# clickfixed evaluation

malicious: 25 rows (corpus/malicious.csv), benign: 400 rows (corpus/benign.csv)

## Detection / false positives (fast path)

| config | detected | blocked | FP (warn+) | FP block |
|---|---|---|---|---|
| full | 25/25 (100.0%) | 15 | 1/400 (0.2%) | 0 |
| no_allowlist | 25/25 (100.0%) | 15 | 4/400 (1.0%) | 0 |
| no_deobfuscation | 25/25 (100.0%) | 15 | 1/400 (0.2%) | 0 |
| no_context (typed / Signal 2) | 20/25 (80.0%) | 7 | 0/400 (0.0%) | 0 |

## Misses (full config)

none

## False positives (full config)

- B003 Pipe-to-shell installer Warn score=1.04 features=["fetch_and_execute"] dampened_by=[]

## Per-feature contribution (full config)

| feature | malicious hits | benign hits | benign dampened | malicious weight | benign weight |
|---|---|---|---|---|---|
| binary_reconstruction | 1 | 0 | 0 | 1.00 | 0.00 |
| certutil_decode_exec | 0 | 0 | 0 | 0.00 | 0.00 |
| certutil_download | 1 | 0 | 0 | 1.00 | 0.00 |
| conhost_headless | 1 | 0 | 0 | 0.60 | 0.00 |
| decode_and_execute | 2 | 0 | 0 | 1.60 | 0.00 |
| download_then_execute | 8 | 3 | 3 | 4.80 | 0.00 |
| encoding_marker | 0 | 4 | 3 | 0.00 | 0.40 |
| execution_policy_bypass | 2 | 4 | 4 | 0.40 | 0.00 |
| fetch_and_execute | 13 | 40 | 39 | 10.40 | 1.00 |
| finger_pipe | 1 | 0 | 0 | 1.20 | 0.00 |
| hidden_window | 9 | 0 | 0 | 3.60 | 0.00 |
| interpreter_entropy | 0 | 2 | 0 | 0.00 | 0.60 |
| lolbin_chain | 1 | 0 | 0 | 0.50 | 0.00 |
| media_ext_as_code | 4 | 0 | 0 | 3.60 | 0.00 |
| mshta_remote | 2 | 0 | 0 | 2.40 | 0.00 |
| msiexec_remote | 0 | 1 | 1 | 0.00 | 0.50 |
| obfuscation_layers | 0 | 0 | 0 | 0.00 | 0.00 |
| persistence_write | 2 | 2 | 0 | 1.40 | 1.40 |
| regsvr32_remote | 1 | 0 | 0 | 1.20 | 0.00 |
| remote_script_host | 0 | 0 | 0 | 0.00 | 0.00 |
| rundll32_user_path | 1 | 0 | 0 | 1.00 | 0.00 |
| staging_path_write | 7 | 0 | 0 | 2.80 | 0.00 |
| trailing_decoy_prose | 2 | 1 | 0 | 1.60 | 0.80 |
| webdav_exec | 0 | 0 | 0 | 0.00 | 0.00 |

## Fast-path latency

85000 samples: p50 45.3 µs, p95 83.0 µs, p99 108.0 µs, max 630.7 µs, over 5 ms budget: 0

## Allowlist regression

PASS: no malicious row's verdict is lowered by any allowlist entry (as recorded and in attacker-best-case context).
