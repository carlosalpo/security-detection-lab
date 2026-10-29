# Interpretation and limits

This is a defensive, offline detection engineering lab. `generate` creates synthetic files; `replay` reads local files and creates a local evidence package. Neither command opens network connections or executes attacks. The repository and published examples contain no customer configurations, production telemetry or credentials.

## Review signals in context

Repeated failures may be ordinary retries or a misconfigured client. Multiple accounts behind a shared source address may reflect NAT, a proxy or a shared gateway. A successful login after failures may be a user correcting a password. Denied traffic across ports may come from authorized diagnostics. These detectors alone cannot attribute intent or establish compromise.

[MITRE ATT&CK Brute Force (T1110)](https://attack.mitre.org/techniques/T1110/) and [Network Service Discovery (T1046)](https://attack.mitre.org/techniques/T1046/) provide conceptual background. The lab does not implement a complete technique evaluation or claim ATT&CK certification or coverage. Multi-account failures do not prove password spraying: password reuse across attempts is not present in this schema. Denied-port fanout does not prove successful service discovery or that any port is open.

Thresholds and severity labels are fixed lab defaults that can be studied, not production risk scores. Eight synthetic fixtures do not establish production precision, recall, detection rates or absence of false positives. `no_signals` means these detectors did not meet thresholds on the supplied records. It says nothing about omitted events or other attack patterns.

## Data boundaries

Inputs must already use the documented normalized schema. There are no native Windows, syslog, firewall or SIEM parsers. There is no persistent state across replays, stream ingestion, tenant field, IPv6, distributed correlation or automated response. Account and service aliases need to preserve identity boundaries; mixing realms can create misleading correlations. Source IP does not identify a person, host or tenant reliably behind shared infrastructure.

Input and output are **not anonymized**. Output intentionally retains normalized events, source addresses, aliases and evidence references. Substitute public synthetic fixtures before publishing evidence. Do not put raw credentials or customer telemetry in this repository. The schema does not need passwords, tokens or message bodies.

The CLI bounds file sizes and counts and rejects ambiguous payloads. Output exclusivity reduces accidental overwrites. It does not make an untrusted shared filesystem safe. A filesystem failure can leave an incomplete directory. Verify all manifest entries before relying on a package; unsigned hashes provide integrity comparison, not proof of origin or protection against an attacker rewriting files and hashes together.

## Reporting a problem

For non-sensitive reproducible bugs, open an issue using a minimal synthetic fixture and the tool version. Avoid including secrets or production data. Do not use a public issue to disclose sensitive security details.
