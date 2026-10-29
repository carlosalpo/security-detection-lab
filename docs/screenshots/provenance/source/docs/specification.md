# Replay specification — v0.1.0

## Events

UTF-8 JSONL, one object per nonblank line. Unknown fields, duplicate JSON keys, non-finite numbers and byte-order marks are rejected. Blank lines are ignored. Maximum 2,000 raw records (including duplicates), 2,000,000 bytes per events file and 8,192 bytes per nonblank line.

Authentication event:

```json
{"id":"fail-one","timestamp":"2026-10-29T12:00:00Z","type":"auth","src_ip":"192.0.2.10","user":"alice","service":"vpn-lab","outcome":"failure"}
```

Network event:

```json
{"id":"deny-one","timestamp":"2026-10-29T12:00:00Z","type":"network","src_ip":"192.0.2.10","dst_ip":"198.51.100.20","dst_port":443,"transport":"tcp","action":"deny"}
```

Fields are required exactly as shown for each type. `outcome` is `failure` or `success`; `action` is `allow` or `deny`; `transport` is `tcp` or `udp`. Ports are JSON integers 1–65535, never booleans or strings. IDs, users and services match `[a-z][a-z0-9-]{0,47}`. Use synthetic aliases, not passwords or personal identifiers. Include the authentication realm in the service alias when combining data from different realms.

Timestamps require exact UTC `YYYY-MM-DDTHH:MM:SSZ`, whole seconds, valid calendar dates and years 2000–2100. IPv4 must be canonical, with no leading zeros. Multicast, loopback, unspecified, link-local, reserved and 0/8 addresses are rejected. Documentation and private unicast addresses are accepted; IPv6 is unsupported.

Identical event objects sharing an ID collapse to one event; conflicting payloads with the same ID reject the entire input. Distinct IDs count as distinct events even when their other fields match. There is no heuristic deduplication. Counts separately report raw records, unique events and duplicates removed.

## Rules and timing

`rules.json` has exactly `schema_version: 1` and `rules`, containing all four rule IDs. Each definition has exactly `id`, `enabled` (boolean), `threshold` (integer 2–100) and `window_seconds` (integer 1–3600). Disable a detector explicitly rather than omitting it. Rule documents are limited to 65,536 bytes. Default definitions are in every example directory.

Replay sorts unique events by timestamp and then ID. Input arrival order does not affect detection. This is a complete offline replay, not streaming processing with watermarks or late-event correction.

Rolling windows are `[t-window_seconds, t]`: an event on the lower boundary remains eligible. Burst counts failures, multi-account counts distinct users, and port fanout counts distinct destination ports. All matching events in the window become evidence, including repeated accounts or ports when their IDs differ. Allowed traffic never contributes to denied-port fanout. Authentication success does not reset the burst detector's rolling failure count.

For success-after-failures, failures must also be strictly earlier than the triggering success and strictly later than the previous success for the same key. Evidence includes the successful triggering event. Every success resets this sequence, even below threshold or during cooldown. Failures in the same second as either success do not belong to that preceding sequence. Multiple successes in one second use the lexicographically first success ID as the representative that consumes prior failures. The ID tie-break ensures reproducibility; it does not infer subsecond causality.

Each rule/group has a cooldown equal to that rule's window. A qualifying trigger is suppressed while `t-last_emitted < window_seconds`. Exactly at the boundary it may emit. Suppressed triggers do not extend cooldown. Different groups and detectors have independent state. Success resets still apply when its qualifying trigger is suppressed.

Metrics distinguish matched events, qualifying triggers, emitted alerts and suppressed triggers. Matched events are failures for burst/multi-account, all authentication events for success-after-failures, and denied network events for fanout. Disabled detectors report zero counts. Suppressed triggers are counted but do not create individual alert records.

## Expected-alert contract

```json
{"schema_version":1,"scenario":"auth-burst","alerts":[{"rule_id":"auth-failure-burst","trigger_id":"fail-5","evidence_ids":["fail-1","fail-2","fail-3","fail-4","fail-5"]}]}
```

Only these fields are accepted. Maximum 512,000 bytes, 8,000 expected alerts and 2,000 evidence IDs per alert. Trigger and evidence references must exist in the unique input events. Duplicate rule/trigger pairs or evidence IDs are invalid.

Evaluation compares `(rule_id, trigger_id)` identity and the complete unordered evidence-ID set. It reports missing alerts, unexpected alerts and evidence mismatches separately. Reordering expected evidence has no effect. Threshold, severity and descriptions are not fields in the expectation contract; their implementation is covered separately by tests and their values are retained in replay output.

## Package and determinism

With expectations, a package contains nine files: normalized `events.jsonl`, canonical `rules.json`, canonical `expected.json`, `replay.json`, `evaluation.json`, `alerts.csv`, `rule-metrics.csv`, `report.md` and `manifest.json`. Without expectations there are eight. JSON and CSV use stable ordering; no execution time or machine path is embedded.

Alert IDs hash rule ID, grouping values and triggering event ID. They identify a signal, not the full alert contents or configuration. A changed threshold can retain the same alert ID. Use the manifest's source and artifact hashes to compare configurations and content.

The manifest hashes each other package file and preserves hashes of the exact original inputs. Normalized events are sorted and deduplicated; their hash can differ from the source file hash. A full package is reproducible byte for byte for identical source bytes and configuration. Reordering inputs or adding duplicates can change provenance hashes/counts even when alert semantics remain the same.

The manifest is written last, does not hash itself, and is not signed. File modes on POSIX are 0700 for the new output directory and 0600 for files. No overwrite or parent-directory creation is attempted by the product CLI. Use a trusted local directory; this is not a hardened multiuser service.
