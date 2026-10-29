"""Hand-authored deterministic synthetic cases; expectations do not call detectors."""

from .model import format_time, timestamp

SCENARIOS = (
    "benign",
    "auth-burst",
    "multi-account",
    "success-after-failures",
    "denied-ports",
    "window-boundary",
    "duplicate-replay",
    "expectation-mismatch",
)
BASE = timestamp("2026-10-29T12:00:00Z")


def auth(
    identifier, seconds, user="alice", outcome="failure", source="192.0.2.10", service="vpn-lab"
):
    return dict(
        id=identifier,
        timestamp=format_time(BASE + seconds),
        type="auth",
        src_ip=source,
        user=user,
        service=service,
        outcome=outcome,
    )


def network(identifier, seconds, port, action="deny", transport="tcp", destination="198.51.100.20"):
    return dict(
        id=identifier,
        timestamp=format_time(BASE + seconds),
        type="network",
        src_ip="192.0.2.10",
        dst_ip=destination,
        dst_port=port,
        transport=transport,
        action=action,
    )


def defaults():
    return dict(
        schema_version=1,
        rules=[
            dict(id=rid, enabled=True, threshold=threshold, window_seconds=window)
            for rid, threshold, window in [
                ("auth-failure-burst", 5, 300),
                ("multi-account-failures", 5, 300),
                ("success-after-failures", 3, 300),
                ("denied-port-fanout", 5, 60),
            ]
        ],
    )


def scenario(name):
    if name not in SCENARIOS:
        raise ValueError("Unknown synthetic scenario.")
    rules = defaults()
    expected = dict(schema_version=1, scenario=name, alerts=[])

    def alert(rule, trigger, ids):
        expected["alerts"].append(dict(rule_id=rule, trigger_id=trigger, evidence_ids=ids))

    if name in ("auth-burst", "duplicate-replay", "expectation-mismatch"):
        events = [auth(f"fail-{i}", i * 10) for i in range(1, 7)]
        if name != "expectation-mismatch":
            alert("auth-failure-burst", "fail-5", [f"fail-{i}" for i in range(1, 6)])
        if name == "duplicate-replay":
            events.insert(0, dict(events[-1]))
    elif name == "multi-account":
        events = [auth(f"account-{i}", i * 10, user=f"user-{i}") for i in range(1, 6)]
        alert("multi-account-failures", "account-5", [f"account-{i}" for i in range(1, 6)])
    elif name == "success-after-failures":
        events = [auth(f"failure-{i}", i * 10) for i in range(1, 4)] + [
            auth("login-success", 40, outcome="success")
        ]
        alert(
            "success-after-failures",
            "login-success",
            ["failure-1", "failure-2", "failure-3", "login-success"],
        )
    elif name == "denied-ports":
        events = [
            network(f"deny-{i}", i * 5, port) for i, port in enumerate([22, 80, 443, 445, 3389], 1)
        ]
        alert("denied-port-fanout", "deny-5", [f"deny-{i}" for i in range(1, 6)])
    elif name == "window-boundary":
        rules["rules"][0]["threshold"] = 2
        events = [auth("edge-first", 0), auth("edge-inclusive", 300), auth("edge-outside", 601)]
        alert("auth-failure-burst", "edge-inclusive", ["edge-first", "edge-inclusive"])
    else:
        events = [
            auth("retry-one", 0),
            auth("retry-two", 10),
            auth("normal-success", 20, outcome="success"),
        ]
        events += [
            network(f"allowed-{i}", i * 5, port, action="allow")
            for i, port in enumerate([22, 80, 443, 445, 3389], 1)
        ]
    return events, rules, expected
