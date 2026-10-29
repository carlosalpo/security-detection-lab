"""Deterministic event-time detection, explicit grouping and suppression."""

from collections import defaultdict, deque

from .model import (
    digest,
    format_time,
    json_bytes,
    normalize,
    timestamp,
    validate_expected,
    validate_rules,
)

DESCRIPTIONS = {
    "auth-failure-burst": (
        "medium",
        "failure_count",
        "Repeated authentication failures for one source, account and service.",
    ),
    "multi-account-failures": (
        "high",
        "distinct_users",
        "Failures for multiple accounts from one source and service; not proof of "
        "password spraying.",
    ),
    "success-after-failures": (
        "high",
        "preceding_failures",
        "A success follows failures since the previous success for the same key; "
        "not proof of compromise.",
    ),
    "denied-port-fanout": (
        "medium",
        "distinct_ports",
        "Denied traffic reaches multiple destination ports for one source, "
        "destination and transport.",
    ),
}


def detect(events, config):
    events, _ = normalize(events)
    config = validate_rules(config)
    times = {e["id"]: timestamp(e["timestamp"]) for e in events}
    alerts = []
    metrics = []
    for rule in config["rules"]:
        rid = rule["id"]
        window = rule["window_seconds"]
        threshold = rule["threshold"]
        state = defaultdict(deque)
        last_emitted = {}
        last_success = {}
        metric = dict(
            rule_id=rid,
            enabled=rule["enabled"],
            threshold=threshold,
            window_seconds=window,
            matched_events=0,
            qualifying_triggers=0,
            emitted_alerts=0,
            suppressed_triggers=0,
        )
        metrics.append(metric)
        if not rule["enabled"]:
            continue
        for event in events:
            if rid == "denied-port-fanout":
                if event["type"] != "network" or event["action"] != "deny":
                    continue
                group = {k: event[k] for k in ("src_ip", "dst_ip", "transport")}
            else:
                if event["type"] != "auth":
                    continue
                if rid != "success-after-failures" and event["outcome"] != "failure":
                    continue
                fields = (
                    ("src_ip", "service")
                    if rid == "multi-account-failures"
                    else ("src_ip", "user", "service")
                )
                group = {k: event[k] for k in fields}
            metric["matched_events"] += 1
            key = tuple(group.values())
            queue = state[key]
            now = times[event["id"]]
            while queue and times[queue[0]["id"]] < now - window:
                queue.popleft()
            if rid == "success-after-failures":
                if event["outcome"] == "failure":
                    queue.append(event)
                    continue
                prior = last_success.get(key, float("-inf"))
                evidence = [e for e in queue if prior < times[e["id"]] < now]
                score = len(evidence)
                evidence.append(event)
                queue.clear()
                last_success[key] = now
            else:
                queue.append(event)
                score = (
                    len({e["user"] for e in queue})
                    if rid == "multi-account-failures"
                    else len({e["dst_port"] for e in queue})
                    if rid == "denied-port-fanout"
                    else len(queue)
                )
                evidence = queue
            if score < threshold:
                continue
            metric["qualifying_triggers"] += 1
            if key in last_emitted and now - last_emitted[key] < window:
                metric["suppressed_triggers"] += 1
                continue
            last_emitted[key] = now
            metric["emitted_alerts"] += 1
            severity, measure, description = DESCRIPTIONS[rid]
            signature = dict(rule_id=rid, group=group, trigger_id=event["id"])
            alerts.append(
                dict(
                    id=digest(json_bytes(signature)),
                    **signature,
                    severity=severity,
                    timestamp=event["timestamp"],
                    window_start=format_time(now - window),
                    window_seconds=window,
                    threshold=threshold,
                    metric=measure,
                    value=score,
                    evidence_ids=[e["id"] for e in evidence],
                    description=description,
                )
            )
    alerts.sort(key=lambda a: (a["timestamp"], a["rule_id"], a["trigger_id"]))
    return alerts, metrics


def evaluate(alerts, expected, events):
    if expected is None:
        return {"status": "not_evaluated", "reason": "No expected-alert contract supplied."}
    expected = validate_expected(expected, events)
    actual = {(a["rule_id"], a["trigger_id"]): a for a in alerts}
    wanted = {(a["rule_id"], a["trigger_id"]): a for a in expected["alerts"]}
    missing = [wanted[k] for k in sorted(wanted.keys() - actual.keys())]
    unexpected = [
        dict(
            rule_id=actual[k]["rule_id"],
            trigger_id=actual[k]["trigger_id"],
            evidence_ids=actual[k]["evidence_ids"],
        )
        for k in sorted(actual.keys() - wanted.keys())
    ]
    mismatches = []
    matched = 0
    for key in sorted(actual.keys() & wanted.keys()):
        if set(actual[key]["evidence_ids"]) == set(wanted[key]["evidence_ids"]):
            matched += 1
        else:
            mismatches.append(
                dict(
                    rule_id=key[0],
                    trigger_id=key[1],
                    expected_evidence_ids=wanted[key]["evidence_ids"],
                    actual_evidence_ids=actual[key]["evidence_ids"],
                )
            )
    return dict(
        status="failed" if missing or unexpected or mismatches else "passed",
        scenario=expected["scenario"],
        expected_alerts=len(wanted),
        actual_alerts=len(actual),
        matched_alerts=matched,
        missing_alerts=missing,
        unexpected_alerts=unexpected,
        evidence_mismatches=mismatches,
    )
