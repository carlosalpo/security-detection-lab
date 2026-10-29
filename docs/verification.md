# Verification — v0.1.0

Tested source: [`dc31cf4c138123775185c41612e139082d383070`](https://github.com/carlosalpo/security-detection-lab/tree/dc31cf4c138123775185c41612e139082d383070). Subsequent release changes add documentation and capture evidence without changing executable source, tests, scenarios or CI configuration.

## Automated checks

- 126 tests passed locally on Python 3.12.14.
- Nine installed-CLI scenarios passed their expected outcomes: seven successful expectation checks, one deliberate expectation mismatch (exit 1), and one conflicting-event-ID rejection (exit 2, no output).
- Ruff lint and format checks passed.
- [GitHub Actions run 40961113379](https://github.com/carlosalpo/security-detection-lab/actions/runs/40961113379) passed the same checks on Python 3.11, 3.12 and 3.13.

The tests exercise inclusive and expired time boundaries, cooldown behavior, per-group isolation, distinct users and ports, authentication sequence resets, same-second ambiguity, stable event ordering, exact duplicates, conflicting IDs, schema limits, manifest hashes and CLI exits. They also verify that runtime replay and fixture generation do not use sockets or DNS.

Scenario expectations are authored independently of the detection engine. Evaluation compares the rule/trigger identity and full evidence set; counts alone cannot pass a wrong evidence chain. The deliberate mismatch fixture expects zero alerts while the engine emits one. This is a passing test of failure reporting, not a successful expected-alert evaluation.

## Inspectable evidence

[The screenshot gallery](screenshots/README.md) includes fresh executions, raw outputs, captured views and provenance. Its static viewer presents evidence; it is not a product dashboard or a SIEM integration. See its manifest for the source revision, capture mapping and individual file hashes.

The [release](https://github.com/carlosalpo/security-detection-lab/releases/tag/v0.1.0) includes a ZIP with three complete replay packages (27 files): auth-burst, benign and expectation-mismatch. Each package contains the normalized inputs, full results, report, CSV exports and artifact manifest. The separate SHA256SUMS file checks the ZIP. Hashes are unsigned integrity checks, not attestation of origin.

Archive SHA-256:

```text
2be2827db8da4d6b212a60010de22c875e6d8f19448405e49dd77bc6d6b67393
```

## Reproduce

Install the package and development dependencies, then run the commands in the [README](../README.md). Use a new output directory each time. The CLI matrix compares generated fixtures byte for byte with committed examples, verifies package/source hashes and checks alert evidence references.

This evidence covers the documented offline schema and synthetic fixtures. It does not establish production precision/recall, complete ATT&CK coverage, native SIEM compatibility, attack execution or the security of any live environment.
