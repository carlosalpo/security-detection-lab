# Security Detection Lab

[![CI](https://github.com/carlosalpo/security-detection-lab/actions/workflows/ci.yml/badge.svg)](https://github.com/carlosalpo/security-detection-lab/actions/workflows/ci.yml)

**Reproducible detections with synthetic events, precise time windows and traceable evidence.**

A detection that produces an alert is only half the story. This offline Python lab makes its behavior reviewable: which events contributed, how grouping and timing affected the result, and whether the alert matches an independently written expectation.

Built by **Carlos Alvarado** as a public security engineering project. Runtime uses the Python standard library; examples contain only synthetic documentation addresses and account aliases.

![Conceptual project illustration](docs/illustrations/cover.png)

*Conceptual artwork; not a screenshot of execution.*

## What it does

- Generates eight deterministic datasets without generating traffic or executing attacks.
- Replays normalized JSONL events through four configurable detectors.
- Removes exact duplicate event IDs and rejects conflicting payloads.
- Records triggering events, complete evidence IDs, thresholds, windows and suppression counts.
- Compares the exact rule/trigger/evidence contract; missing and unexpected alerts fail explicitly.
- Exports JSON, CSV, a Markdown report and an unsigned SHA-256 manifest.

| Detector | Group | Threshold / window defaults | Signal |
| --- | --- | --- | --- |
| `auth-failure-burst` | Source, user, service | 5 / 300 s | Repeated failed authentication |
| `multi-account-failures` | Source, service | 5 distinct users / 300 s | Failures across accounts |
| `success-after-failures` | Source, user, service | 3 preceding failures / 300 s | Success after failures since the previous success |
| `denied-port-fanout` | Source, destination, transport | 5 distinct ports / 60 s | Denied traffic across ports |

These signals are investigation leads. They do not establish compromise, password spraying, open ports or malicious intent. This release is an offline lab, with no native SIEM integration, log collection, network scanning or response automation.

## Run a complete example

Requires Python 3.11 or newer; CI checks 3.11, 3.12 and 3.13.

```sh
python3 -m venv .venv
. .venv/bin/activate
python -m pip install .
sdl generate --scenario auth-burst --output synthetic-data
sdl replay --events synthetic-data/events.jsonl \
  --rules synthetic-data/rules.json \
  --expect synthetic-data/expected.json \
  --output replay-package
```

The example yields **one expected alert**, with `fail-5` as trigger and `fail-1` through `fail-5` as evidence. The sixth qualifying failure is suppressed by the cooldown. Read `replay-package/report.md`, then follow the IDs back to `events.jsonl`.

Output directories must be new, and their parent must exist. Input validation happens before output creation. A later filesystem failure can leave partial output; require the complete manifest and matching file hashes before use.

| Exit | Meaning |
| --- | --- |
| 0 | Replay completed; expectations passed or were not supplied |
| 1 | Replay completed; expected alerts and actual evidence disagree |
| 2 | Invalid input, command usage or filesystem failure |

Without `--expect`, evaluation is **`not_evaluated`**, never a passing test. An expected alert can coexist with a passing evaluation. `no_signals` is not a statement that a system is secure.

## Reproducible scenarios

| Scenario | Purpose | Alerts | Expected CLI exit |
| --- | --- | ---: | ---: |
| `benign` | Retries below thresholds and allowed traffic | 0 | 0 |
| `auth-burst` | Repeated failures and suppression | 1 | 0 |
| `multi-account` | Count distinct accounts | 1 | 0 |
| `success-after-failures` | Sequence evidence includes the successful trigger | 1 | 0 |
| `denied-ports` | Count distinct denied ports | 1 | 0 |
| `window-boundary` | Include the lower time boundary; expire older events | 1 | 0 |
| `duplicate-replay` | Seven records become six unique events | 1 | 0 |
| `expectation-mismatch` | Deliberately expect zero alerts while one is emitted | 1 | 1 |

The ninth CLI check supplies conflicting payloads with one event ID: it must exit 2 and create no output directory. The mismatch fixture is deliberately wrong to demonstrate a regression gate that can fail.

```sh
python -m pip install '.[dev]'
ruff check src tests scripts
ruff format --check src tests scripts
pytest -q
python scripts/check_examples.py --output reports/example-matrix
```

Expectations in `examples/*/expected.json` are authored independently of the detection engine. Tests cover timestamp boundaries, per-key isolation, distinct counts, sequence resets, tie handling, suppression, deduplication, strict inputs and CLI behavior. They do not measure real-world detection precision or recall.

## Documentation

- [Event, rule and expectation specification](docs/specification.md)
- [Interpretation, privacy and operational limits](docs/security-and-scope.md)
- [Verification and provenance](docs/verification.md)
- [Releases and downloadable replay packages](https://github.com/carlosalpo/security-detection-lab/releases)

## Why this belongs in an engineering portfolio

The work demonstrates detection logic as a testable contract: event normalization, explicit identity boundaries, deterministic replay, edge-case tests and evidence that another engineer can inspect. The complete source is small enough to review and the fixtures are safe to publish.

MIT license. See [LICENSE](LICENSE).
