import copy
import csv
import io
import json
import os
import random
import socket
from pathlib import Path

import pytest

from detectionlab.cli import main
from detectionlab.engine import detect
from detectionlab.fixtures import SCENARIOS, auth, defaults, network, scenario
from detectionlab.model import (
    MAX_EVENT_BYTES,
    MAX_EVENTS,
    InputError,
    digest,
    json_bytes,
    jsonl_bytes,
    load_events,
    normalize,
    timestamp,
    validate_event,
    validate_expected,
    validate_rules,
)
from detectionlab.report import compile_replay

ROOT = Path(__file__).resolve().parents[1]


def only(rid, threshold=2, window=60):
    config = defaults()
    for r in config["rules"]:
        r.update(enabled=r["id"] == rid, threshold=threshold, window_seconds=window)
    return config


def metrics(rows, rid):
    return next(r for r in rows if r["rule_id"] == rid)


@pytest.mark.parametrize("name", SCENARIOS)
def test_synthetic_contracts(name):
    events, rules, expected = scenario(name)
    files, result = compile_replay(events, rules, expected)
    assert result["evaluation"]["status"] == (
        "failed" if name == "expectation-mismatch" else "passed"
    )
    assert len(result["alerts"]) == (0 if name == "benign" else 1)
    assert len(files) == 9
    folder = ROOT / "examples" / name
    assert (folder / "events.jsonl").read_bytes() == jsonl_bytes(events)
    assert (folder / "rules.json").read_bytes() == json_bytes(rules)
    assert (folder / "expected.json").read_bytes() == json_bytes(expected)


@pytest.mark.parametrize("second,alerts", [(59, 1), (60, 1), (61, 0)])
def test_inclusive_window_boundary(second, alerts):
    result, _ = detect([auth("first", 0), auth("second", second)], only("auth-failure-burst"))
    assert len(result) == alerts
    if alerts:
        assert result[0]["evidence_ids"] == ["first", "second"]


def test_cooldown_boundary_and_suppression_do_not_slide():
    events = [auth(f"e{i}", sec) for i, sec in enumerate([0, 1, 30, 60, 61])]
    alerts, rows = detect(events, only("auth-failure-burst"))
    assert [a["trigger_id"] for a in alerts] == ["e1", "e4"]
    assert alerts[-1]["evidence_ids"] == ["e1", "e2", "e3", "e4"]
    row = metrics(rows, "auth-failure-burst")
    assert (row["qualifying_triggers"], row["emitted_alerts"], row["suppressed_triggers"]) == (
        4,
        2,
        2,
    )


@pytest.mark.parametrize(
    "field,value", [("src_ip", "192.0.2.11"), ("user", "bob"), ("service", "ssh-lab")]
)
def test_auth_burst_key_isolation(field, value):
    second = auth("second", 1)
    second[field] = value
    assert not detect([auth("first", 0), second], only("auth-failure-burst"))[0]


def test_multi_account_counts_distinct_users_not_failures():
    events = [auth("first", 0), auth("retry", 1)]
    assert not detect(events, only("multi-account-failures"))[0]
    events.append(auth("second-account", 2, user="bob"))
    alert = detect(events, only("multi-account-failures"))[0][0]
    assert alert["value"] == 2 and alert["evidence_ids"] == ["first", "retry", "second-account"]


@pytest.mark.parametrize("field,value", [("src_ip", "192.0.2.11"), ("service", "ssh-lab")])
def test_multi_account_isolation(field, value):
    e = auth("second", 1, user="bob")
    e[field] = value
    assert not detect([auth("first", 0), e], only("multi-account-failures"))[0]


def test_multi_account_distinct_count_expires():
    events = [
        auth("alice-old", 0),
        auth("bob-one", 61, user="bob"),
        auth("bob-two", 62, user="bob"),
    ]
    assert not detect(events, only("multi-account-failures"))[0]


def test_success_rule_evidence_includes_success():
    events = [auth("first", 0), auth("second", 1), auth("success", 2, outcome="success")]
    alert = detect(events, only("success-after-failures"))[0][0]
    assert alert["value"] == 2
    assert alert["evidence_ids"] == ["first", "second", "success"]


def test_success_resets_sequence_even_below_threshold():
    events = [
        auth("first", 0),
        auth("reset", 1, outcome="success"),
        auth("second", 2),
        auth("success", 3, outcome="success"),
    ]
    assert not detect(events, only("success-after-failures"))[0]


@pytest.mark.parametrize(
    "failure_id,success_id", [("a-fail", "z-success"), ("z-fail", "a-success")]
)
def test_same_second_is_not_strictly_preceding(failure_id, success_id):
    events = [auth("old", 0), auth(failure_id, 1), auth(success_id, 1, outcome="success")]
    assert not detect(events, only("success-after-failures"))[0]


@pytest.mark.parametrize(
    "failure_id,success_id", [("a-fail", "z-success"), ("z-fail", "a-success")]
)
def test_failure_at_previous_success_second_is_not_reused(failure_id, success_id):
    events = [
        auth(failure_id, 0),
        auth(success_id, 0, outcome="success"),
        auth("later", 1),
        auth("next-success", 2, outcome="success"),
    ]
    assert not detect(events, only("success-after-failures"))[0]


def test_same_second_successes_have_deterministic_representative():
    events = [
        auth("first", 0),
        auth("second", 1),
        auth("z-success", 2, outcome="success"),
        auth("a-success", 2, outcome="success"),
    ]
    alerts, _ = detect(events, only("success-after-failures"))
    assert [a["trigger_id"] for a in alerts] == ["a-success"]


def test_success_window_includes_lower_boundary():
    events = [auth("first", 0), auth("second", 1), auth("success", 60, outcome="success")]
    assert len(detect(events, only("success-after-failures"))[0]) == 1
    events[-1]["timestamp"] = auth("ignored", 61)["timestamp"]
    assert not detect(events, only("success-after-failures"))[0]


def test_success_cooldown_still_resets_sequence():
    events = [
        auth("f1", 0),
        auth("f2", 1),
        auth("s1", 2, outcome="success"),
        auth("f3", 3),
        auth("f4", 4),
        auth("s2", 5, outcome="success"),
        auth("s3", 62, outcome="success"),
    ]
    alerts, rows = detect(events, only("success-after-failures"))
    assert [a["trigger_id"] for a in alerts] == ["s1"]
    assert metrics(rows, "success-after-failures")["suppressed_triggers"] == 1


def test_burst_is_rolling_failures_even_across_success():
    events = [auth("f1", 0), auth("s1", 1, outcome="success"), auth("f2", 2)]
    assert detect(events, only("auth-failure-burst"))[0][0]["trigger_id"] == "f2"


def test_denied_port_distinctness_and_allowed_exclusion():
    events = [
        network("first", 0, 22),
        network("repeat", 1, 22),
        network("allowed", 2, 80, action="allow"),
    ]
    assert not detect(events, only("denied-port-fanout"))[0]
    events.append(network("second-port", 3, 80))
    alert = detect(events, only("denied-port-fanout"))[0][0]
    assert alert["value"] == 2 and alert["evidence_ids"] == ["first", "repeat", "second-port"]


@pytest.mark.parametrize(
    "field,value", [("src_ip", "192.0.2.11"), ("dst_ip", "198.51.100.21"), ("transport", "udp")]
)
def test_port_fanout_key_isolation(field, value):
    e = network("second", 1, 80)
    e[field] = value
    assert not detect([network("first", 0, 22), e], only("denied-port-fanout"))[0]


def test_disabled_detectors_still_report_zero_metrics():
    events, rules, _ = scenario("auth-burst")
    for rule in rules["rules"]:
        rule["enabled"] = False
    alerts, rows = detect(events, rules)
    assert not alerts and len(rows) == 4
    assert all(not r["enabled"] and r["matched_events"] == 0 for r in rows)


def test_shuffled_input_is_deterministic_and_not_mutated():
    events, rules, expected = scenario("auth-burst")
    before = copy.deepcopy(events)
    files, result = compile_replay(events, rules, expected)
    random.Random(42).shuffle(events)
    assert compile_replay(events, rules, expected) == (files, result)
    assert sorted(events, key=lambda e: e["id"]) == sorted(before, key=lambda e: e["id"])
    rules["rules"].reverse()
    assert compile_replay(events, rules, expected) == (files, result)


def test_exact_duplicates_do_not_inflate_thresholds():
    e = auth("same", 0)
    normalized, counts = normalize([e, dict(e)])
    assert len(normalized) == 1 and counts["duplicates_removed"] == 1
    assert not detect([e, dict(e)], only("auth-failure-burst"))[0]


def test_conflicting_id_rejected():
    with pytest.raises(InputError):
        normalize([auth("same", 0), auth("same", 1)])


def test_duplicate_replay_preserves_alerts_but_records_quality():
    a = compile_replay(*scenario("auth-burst"))[1]
    b = compile_replay(*scenario("duplicate-replay"))[1]
    assert a["alerts"] == b["alerts"]
    assert b["counts"] == dict(input_records=7, unique_events=6, duplicates_removed=1)


def test_empty_data_and_absent_expectations():
    files, result = compile_replay([], defaults())
    assert result["status"] == "no_signals" and result["evaluation"]["status"] == "not_evaluated"
    assert len(files) == 8 and "expected.json" not in files
    expected = dict(schema_version=1, scenario="empty", alerts=[])
    assert compile_replay([], defaults(), expected)[1]["evaluation"]["status"] == "passed"


def test_exact_evidence_mismatch_not_just_alert_count():
    events, rules, expected = scenario("auth-burst")
    expected["alerts"][0]["evidence_ids"].pop()
    result = compile_replay(events, rules, expected)[1]["evaluation"]
    assert result["status"] == "failed" and len(result["evidence_mismatches"]) == 1
    assert (
        result["matched_alerts"] == 0
        and not result["unexpected_alerts"]
        and not result["missing_alerts"]
    )


def test_missing_and_unexpected_alerts_are_distinct():
    events, rules, expected = scenario("auth-burst")
    expected["alerts"][0]["trigger_id"] = "fail-6"
    result = compile_replay(events, rules, expected)[1]["evaluation"]
    assert result["status"] == "failed"
    assert result["missing_alerts"][0]["trigger_id"] == "fail-6"
    assert result["unexpected_alerts"][0]["trigger_id"] == "fail-5"


def test_evidence_expectation_order_is_not_semantic():
    events, rules, expected = scenario("auth-burst")
    expected["alerts"][0]["evidence_ids"].reverse()
    assert compile_replay(events, rules, expected)[1]["evaluation"]["status"] == "passed"


@pytest.mark.parametrize("value", [True, 1.0, "1", None, 2])
def test_rules_version_strict(value):
    rules = defaults()
    rules["schema_version"] = value
    with pytest.raises(InputError):
        validate_rules(rules)


@pytest.mark.parametrize("value", [True, 1, 101, 0, 2.5, "5", None])
def test_threshold_bounds(value):
    rules = defaults()
    rules["rules"][0]["threshold"] = value
    with pytest.raises(InputError):
        validate_rules(rules)


@pytest.mark.parametrize("value", [True, 0, 3601, 1.5, "60", None])
def test_window_bounds(value):
    rules = defaults()
    rules["rules"][0]["window_seconds"] = value
    with pytest.raises(InputError):
        validate_rules(rules)


@pytest.mark.parametrize("value", [1, 0, "true", None, {}])
def test_enabled_boolean(value):
    rules = defaults()
    rules["rules"][0]["enabled"] = value
    with pytest.raises(InputError):
        validate_rules(rules)


def test_rule_set_exact_and_unique():
    rules = defaults()
    rules["rules"].pop()
    with pytest.raises(InputError):
        validate_rules(rules)
    rules = defaults()
    rules["rules"][1] = copy.deepcopy(rules["rules"][0])
    with pytest.raises(InputError):
        validate_rules(rules)


@pytest.mark.parametrize(
    "value",
    [
        "2026-10-29T12:00:00+00:00",
        "2026-10-29T12:00:00.1Z",
        "2026-02-30T00:00:00Z",
        "2026-10-29T12:00:60Z",
        "1999-12-31T23:59:59Z",
        "2101-01-01T00:00:00Z",
        "2026-1-1T00:00:00Z",
        None,
        42,
    ],
)
def test_timestamp_contract(value):
    with pytest.raises(InputError):
        timestamp(value)


@pytest.mark.parametrize(
    "value",
    [
        "::1",
        "192.000.2.1",
        "224.0.0.1",
        "0.1.2.3",
        "127.0.0.1",
        "169.254.1.1",
        "240.0.0.1",
        None,
        42,
    ],
)
def test_unicast_ipv4_contract(value):
    event = auth("first", 0)
    event["src_ip"] = value
    with pytest.raises(InputError):
        validate_event(event)


@pytest.mark.parametrize("value", [True, 0, 65536, 22.5, "22", None])
def test_port_bounds(value):
    with pytest.raises(InputError):
        validate_event(network("first", 0, value))


@pytest.mark.parametrize("value", ["", "A", "a b", "a\nb", "a" * 49, "=cmd", None])
def test_alias_and_id_contract(value):
    event = auth("first", 0)
    event["user"] = value
    with pytest.raises(InputError):
        validate_event(event)


@pytest.mark.parametrize("target", ["event", "rules", "rule", "expected", "expected-alert"])
def test_unknown_fields_fail_closed(target):
    events, rules, expected = scenario("auth-burst")
    obj = {
        "event": events[0],
        "rules": rules,
        "rule": rules["rules"][0],
        "expected": expected,
        "expected-alert": expected["alerts"][0],
    }[target]
    obj["unsupported"] = True
    with pytest.raises(InputError):
        compile_replay(events, rules, expected)


@pytest.mark.parametrize("change", ["trigger", "evidence", "duplicate-alert", "duplicate-evidence"])
def test_expectation_reference_contract(change):
    events, rules, expected = scenario("auth-burst")
    if change == "trigger":
        expected["alerts"][0]["trigger_id"] = "missing"
    if change == "evidence":
        expected["alerts"][0]["evidence_ids"] = ["missing"]
    if change == "duplicate-alert":
        expected["alerts"] *= 2
    if change == "duplicate-evidence":
        expected["alerts"][0]["evidence_ids"] *= 2
    with pytest.raises(InputError):
        validate_expected(expected, events)


@pytest.mark.parametrize(
    "raw",
    [
        b'{"id":1,"id":2}\n',
        b"NaN\n",
        b"{\n",
        b"\xff\n",
        b"\xef\xbb\xbf{}\n",
        b"[" * 2000 + b"]" * 2000,
        b"x" * 8193,
        b" " * (MAX_EVENT_BYTES + 1),
    ],
)
def test_jsonl_rejection(tmp_path, raw):
    path = tmp_path / "events.jsonl"
    path.write_bytes(raw)
    with pytest.raises(InputError):
        load_events(path)


def test_record_bound_counts_duplicates_too():
    with pytest.raises(InputError):
        normalize([auth("same", 0)] * (MAX_EVENTS + 1))


def test_jsonl_blanks_and_exact_source_hash(tmp_path):
    raw = b"\n" + jsonl_bytes([auth("first", 0), auth("first", 0)]) + b"  \n"
    p = tmp_path / "events.jsonl"
    p.write_bytes(raw)
    events, counts, source_hash = load_events(p)
    assert len(events) == 1 and counts["duplicates_removed"] == 1 and source_hash == digest(raw)


def test_manifest_evidence_and_csv_consistency():
    events, rules, expected = scenario("auth-burst")
    files, result = compile_replay(events, rules, expected)
    manifest = json.loads(files["manifest.json"])
    assert list(files)[-1] == "manifest.json"
    assert set(manifest["files"]) == set(files) - {"manifest.json"}
    for name, meta in manifest["files"].items():
        assert meta == dict(bytes=len(files[name]), sha256=digest(files[name]))
    rows = list(csv.DictReader(io.StringIO(files["alerts.csv"].decode())))
    assert json.loads(rows[0]["evidence_ids"]) == result["alerts"][0]["evidence_ids"]
    assert json.loads(rows[0]["group"]) == result["alerts"][0]["group"]
    assert all(
        eid in {e["id"] for e in events} for a in result["alerts"] for eid in a["evidence_ids"]
    )


def test_runtime_and_generator_need_no_network(monkeypatch):
    def fail(*args, **kwargs):
        pytest.fail("Unexpected network activity")

    monkeypatch.setattr(socket, "socket", fail)
    monkeypatch.setattr(socket, "getaddrinfo", fail)
    assert compile_replay(*scenario("auth-burst"))[1]["evaluation"]["status"] == "passed"


@pytest.mark.parametrize(
    "case,exit_code",
    [("auth-burst", 0), ("benign", 0), ("expectation-mismatch", 1), ("duplicate-replay", 0)],
)
def test_installed_workflow_via_entry_function(tmp_path, case, exit_code):
    data = tmp_path / "data"
    output = tmp_path / "out"
    assert main(["generate", "--scenario", case, "--output", str(data)]) == 0
    assert (
        main(
            [
                "replay",
                "--events",
                str(data / "events.jsonl"),
                "--rules",
                str(data / "rules.json"),
                "--expect",
                str(data / "expected.json"),
                "--output",
                str(output),
            ]
        )
        == exit_code
    )
    assert len(list(output.iterdir())) == 9
    if os.name == "posix":
        assert output.stat().st_mode & 0o077 == 0
        assert all(p.stat().st_mode & 0o077 == 0 for p in output.iterdir())


def test_invalid_input_no_output(tmp_path):
    source = tmp_path / "bad.jsonl"
    source.write_text("{}\n")
    out = tmp_path / "out"
    assert (
        main(
            [
                "replay",
                "--events",
                str(source),
                "--rules",
                str(ROOT / "examples/benign/rules.json"),
                "--output",
                str(out),
            ]
        )
        == 2
    )
    assert not out.exists()


def test_replay_without_expected_is_not_evaluated(tmp_path):
    out = tmp_path / "out"
    assert (
        main(
            [
                "replay",
                "--events",
                str(ROOT / "examples/auth-burst/events.jsonl"),
                "--rules",
                str(ROOT / "examples/auth-burst/rules.json"),
                "--output",
                str(out),
            ]
        )
        == 0
    )
    assert json.loads((out / "evaluation.json").read_text())["status"] == "not_evaluated"


def test_output_never_overwritten(tmp_path):
    marker = tmp_path / "keep"
    marker.write_text("keep")
    assert main(["generate", "--scenario", "benign", "--output", str(tmp_path)]) == 2
    assert list(tmp_path.iterdir()) == [marker] and marker.read_text() == "keep"


def test_partial_write_no_manifest(tmp_path, monkeypatch):
    original = os.open

    def fail(path, *args, **kwargs):
        if Path(path).name == "alerts.csv":
            raise OSError("simulated disk failure")
        return original(path, *args, **kwargs)

    monkeypatch.setattr(os, "open", fail)
    out = tmp_path / "out"
    assert (
        main(
            [
                "replay",
                "--events",
                str(ROOT / "examples/auth-burst/events.jsonl"),
                "--rules",
                str(ROOT / "examples/auth-burst/rules.json"),
                "--output",
                str(out),
            ]
        )
        == 2
    )
    assert out.exists() and not (out / "manifest.json").exists()
