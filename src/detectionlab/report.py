import csv
import html
import io
import json
import re

from . import __version__
from .engine import detect, evaluate
from .model import digest, json_bytes, jsonl_bytes, normalize, validate_expected, validate_rules


def md(value):
    return re.sub(r"([\\`*{}\[\]()#+.!_|-])", r"\\\1", html.escape(str(value), quote=False))


def csv_bytes(rows, headers):
    out = io.StringIO(newline="")
    writer = csv.DictWriter(out, fieldnames=headers, lineterminator="\n")
    writer.writeheader()
    for row in rows:
        values = {}
        for key in headers:
            value = row[key]
            value = (
                json.dumps(value, sort_keys=True) if isinstance(value, (dict, list)) else str(value)
            )
            values[key] = "'" + value if value.lstrip().startswith(("=", "+", "-", "@")) else value
        writer.writerow(values)
    return out.getvalue().encode()


def markdown(result):
    lines = [
        "# Security Detection Lab — replay report",
        "",
        f"Signals: **{result['status']}** · expectation check: "
        f"**{result['evaluation']['status']}**",
        "",
        "Scope: offline replay of supplied normalized events. No attack execution, "
        "live collection, "
        "SIEM integration, network scan or response action. Signals are review "
        "leads, not proof of compromise.",
        "",
        f"Input records: {result['counts']['input_records']} · unique events: "
        f"{result['counts']['unique_events']} · "
        f"exact duplicates removed: {result['counts']['duplicates_removed']} · "
        f"alerts: {len(result['alerts'])}",
        "",
        "## Rule execution",
        "",
        "| Rule | Enabled | Window seconds | Threshold | Qualifying triggers | "
        "Emitted | Suppressed |",
        "| --- | --- | ---: | ---: | ---: | ---: | ---: |",
    ]
    for row in result["rules"]:
        lines.append(
            "| "
            + " | ".join(
                md(row[k])
                for k in (
                    "rule_id",
                    "enabled",
                    "window_seconds",
                    "threshold",
                    "qualifying_triggers",
                    "emitted_alerts",
                    "suppressed_triggers",
                )
            )
            + " |"
        )
    lines += ["", "## Alerts", ""]
    if not result["alerts"]:
        lines.append(
            "No signals from these detectors and inputs; this is not a security assessment."
        )
    for alert in result["alerts"]:
        lines += [
            f"### {alert['rule_id']} — {alert['timestamp']}",
            "",
            md(alert["description"]),
            "",
            f"Trigger: `{alert['trigger_id']}` · severity: {alert['severity']} · "
            f"{alert['metric']}: {alert['value']} (threshold {alert['threshold']})",
            "",
            "```json",
            json_bytes(
                dict(
                    group=alert["group"],
                    window_start=alert["window_start"],
                    evidence_ids=alert["evidence_ids"],
                )
            )
            .decode()
            .rstrip(),
            "```",
            "",
        ]
    lines += [
        "",
        "## Expected-alert comparison",
        "",
        "```json",
        json_bytes(result["evaluation"]).decode().rstrip(),
        "```",
        "",
        "## Timing and interpretation",
        "",
        "- Rolling windows include the lower boundary. Events are sorted by UTC time and ID; "
        "ID order is a deterministic tie-break, not proof of ordering within a second.",
        "- Success-after-failures uses only failures strictly before the success "
        "and strictly after "
        "the previous success for that key. A success resets that sequence even below threshold.",
        "- Each rule/key suppresses qualifying triggers until one window has "
        "elapsed since its last "
        "emitted alert. A trigger exactly at the cooldown boundary may emit; "
        "suppressed triggers do not extend it.",
        "- Counts refer to supplied unique event records. Distinct-account/port "
        "rules use unique values "
        "inside a window; exact duplicate IDs never inflate thresholds.",
        "- Expected checks compare rule, triggering event and complete evidence ID sets. Missing, "
        "unexpected and evidence-mismatched alerts fail separately. No expectation "
        "means not evaluated.",
        "- Authentication signals may reflect retries, shared source addresses or "
        "maintenance. Denied "
        "port fanout may reflect authorized diagnostics; it does not establish "
        "that ports are open.",
        "- Thresholds and severities are lab choices. Native log normalization, data completeness, "
        "tenant identity, production tuning and response decisions require separate engineering.",
        "- Input and output are not anonymized. The hash manifest is unsigned.",
        "",
    ]
    return "\n".join(lines).encode()


def compile_replay(events, config, expected=None, source_hashes=None, input_counts=None):
    events, counts = normalize(events)
    config = validate_rules(config)
    if expected is not None:
        expected = validate_expected(expected, events)
    alerts, metrics = detect(events, config)
    evaluation = evaluate(alerts, expected, events)
    if input_counts is not None:
        counts = input_counts
    result = dict(
        schema_version=1,
        scope="offline-normalized-event-replay",
        status="signals_detected" if alerts else "no_signals",
        counts=counts,
        alerts=alerts,
        rules=metrics,
        evaluation=evaluation,
    )
    files = {
        "events.jsonl": jsonl_bytes(events),
        "rules.json": json_bytes(config),
        "replay.json": json_bytes(result),
        "alerts.csv": csv_bytes(
            alerts,
            [
                "id",
                "rule_id",
                "timestamp",
                "trigger_id",
                "severity",
                "group",
                "metric",
                "value",
                "threshold",
                "window_seconds",
                "window_start",
                "evidence_ids",
            ],
        ),
        "rule-metrics.csv": csv_bytes(
            metrics,
            [
                "rule_id",
                "enabled",
                "threshold",
                "window_seconds",
                "matched_events",
                "qualifying_triggers",
                "emitted_alerts",
                "suppressed_triggers",
            ],
        ),
        "evaluation.json": json_bytes(evaluation),
        "report.md": markdown(result),
    }
    if expected is not None:
        files["expected.json"] = json_bytes(expected)
    files["manifest.json"] = json_bytes(
        dict(
            schema_version=1,
            tool="security-detection-lab",
            version=__version__,
            scope=result["scope"],
            counts=counts,
            evaluation_status=evaluation["status"],
            source_sha256=source_hashes or {},
            normalized_events_sha256=digest(files["events.jsonl"]),
            files={
                name: dict(bytes=len(raw), sha256=digest(raw))
                for name, raw in sorted(files.items())
            },
        )
    )
    return files, result
