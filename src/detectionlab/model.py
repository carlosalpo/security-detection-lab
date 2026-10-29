"""Strict schemas, exact duplicate handling and explicit UTC event time."""

import hashlib
import json
import re
from datetime import datetime, timezone
from ipaddress import IPv4Address
from pathlib import Path

RULE_IDS = (
    "auth-failure-burst",
    "multi-account-failures",
    "success-after-failures",
    "denied-port-fanout",
)
ID = re.compile(r"[a-z][a-z0-9-]{0,47}\Z")
MAX_EVENTS = 2000
MAX_EVENT_BYTES = 2_000_000


class InputError(ValueError):
    """Unsupported or ambiguous input; no replay package should be emitted."""


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def json_bytes(value):
    return (json.dumps(value, sort_keys=True, indent=2, ensure_ascii=True) + "\n").encode()


def jsonl_bytes(events):
    return "".join(
        json.dumps(e, sort_keys=True, separators=(",", ":")) + "\n" for e in events
    ).encode()


def fields(obj, names, where):
    if not isinstance(obj, dict) or set(obj) != set(names.split()):
        raise InputError(f"{where}: fields must match the specification exactly.")


def identifier(value):
    if not isinstance(value, str) or not ID.fullmatch(value):
        raise InputError("IDs require a lowercase letter and up to 47 letters, digits or hyphens.")


def choice(value, values, where):
    if not isinstance(value, str) or value not in values:
        raise InputError(f"{where}: unsupported value.")


def integer(value, low, high, where):
    if type(value) is not int or not low <= value <= high:
        raise InputError(f"{where}: expected integer {low}..{high}.")


def timestamp(value):
    if not isinstance(value, str) or not re.fullmatch(
        r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z", value
    ):
        raise InputError("Timestamp must use UTC YYYY-MM-DDTHH:MM:SSZ with second precision.")
    try:
        parsed = datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    except ValueError as exc:
        raise InputError("Invalid calendar timestamp.") from exc
    if not 2000 <= parsed.year <= 2100:
        raise InputError("Event timestamp year must be 2000..2100.")
    return int(parsed.timestamp())


def format_time(seconds):
    return datetime.fromtimestamp(seconds, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def ipv4(value):
    if not isinstance(value, str):
        raise InputError("Expected canonical unicast IPv4.")
    try:
        ip = IPv4Address(value)
        if (
            str(ip) != value
            or ip.is_multicast
            or ip.is_unspecified
            or ip.is_loopback
            or ip.is_link_local
            or ip.is_reserved
            or int(ip) < 2**24
        ):
            raise ValueError
    except ValueError as exc:
        raise InputError("Expected canonical unicast IPv4.") from exc


def validate_event(event):
    if not isinstance(event, dict):
        raise InputError("Event must be an object.")
    choice(event.get("type"), ("auth", "network"), "event.type")
    common = "id timestamp type src_ip "
    fields(
        event,
        common
        + (
            "user service outcome"
            if event["type"] == "auth"
            else "dst_ip dst_port transport action"
        ),
        "event",
    )
    identifier(event["id"])
    timestamp(event["timestamp"])
    ipv4(event["src_ip"])
    if event["type"] == "auth":
        identifier(event["user"])
        identifier(event["service"])
        choice(event["outcome"], ("failure", "success"), "auth.outcome")
    else:
        ipv4(event["dst_ip"])
        integer(event["dst_port"], 1, 65535, "network.dst_port")
        choice(event["transport"], ("tcp", "udp"), "network.transport")
        choice(event["action"], ("allow", "deny"), "network.action")


def normalize(events):
    if not isinstance(events, list) or len(events) > MAX_EVENTS:
        raise InputError("At most 2000 input event records are accepted.")
    by_id = {}
    for event in events:
        validate_event(event)
        if event["id"] in by_id and by_id[event["id"]] != event:
            raise InputError("Conflicting payloads share an event ID.")
        by_id[event["id"]] = dict(event)
    ordered = sorted(by_id.values(), key=lambda e: (e["timestamp"], e["id"]))
    return ordered, dict(
        input_records=len(events),
        unique_events=len(ordered),
        duplicates_removed=len(events) - len(ordered),
    )


def validate_rules(config):
    fields(config, "schema_version rules", "rules document")
    integer(config["schema_version"], 1, 1, "schema_version")
    if not isinstance(config["rules"], list) or len(config["rules"]) != 4:
        raise InputError(
            "Exactly four detector definitions are required; disable explicitly if needed."
        )
    seen = set()
    for rule in config["rules"]:
        fields(rule, "id enabled threshold window_seconds", "rule")
        choice(rule["id"], RULE_IDS, "rule.id")
        if rule["id"] in seen:
            raise InputError("Duplicate rule ID.")
        seen.add(rule["id"])
        if type(rule["enabled"]) is not bool:
            raise InputError("rule.enabled must be a JSON boolean.")
        integer(rule["threshold"], 2, 100, "rule.threshold")
        integer(rule["window_seconds"], 1, 3600, "rule.window_seconds")
    return {
        "schema_version": 1,
        "rules": sorted((dict(r) for r in config["rules"]), key=lambda r: r["id"]),
    }


def validate_expected(expected, events):
    fields(expected, "schema_version scenario alerts", "expectations")
    integer(expected["schema_version"], 1, 1, "schema_version")
    identifier(expected["scenario"])
    if not isinstance(expected["alerts"], list) or len(expected["alerts"]) > 8000:
        raise InputError("Expected alerts must be a list of at most 8000 items.")
    ids = {e["id"] for e in events}
    seen = set()
    rows = []
    for row in expected["alerts"]:
        fields(row, "rule_id trigger_id evidence_ids", "expected alert")
        choice(row["rule_id"], RULE_IDS, "expected.rule_id")
        identifier(row["trigger_id"])
        if row["trigger_id"] not in ids:
            raise InputError("Expected trigger references an unknown event.")
        pair = (row["rule_id"], row["trigger_id"])
        if pair in seen:
            raise InputError("Duplicate expected rule/trigger pair.")
        seen.add(pair)
        evidence = row["evidence_ids"]
        if not isinstance(evidence, list) or not 1 <= len(evidence) <= MAX_EVENTS:
            raise InputError("Expected evidence requires 1..2000 event IDs.")
        for value in evidence:
            identifier(value)
            if value not in ids:
                raise InputError("Expected evidence references an unknown event.")
        if len(set(evidence)) != len(evidence):
            raise InputError("Duplicate expected evidence ID.")
        rows.append(
            dict(
                rule_id=row["rule_id"], trigger_id=row["trigger_id"], evidence_ids=sorted(evidence)
            )
        )
    return dict(
        schema_version=1,
        scenario=expected["scenario"],
        alerts=sorted(rows, key=lambda r: (r["rule_id"], r["trigger_id"])),
    )


def _pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise InputError("Duplicate JSON keys are not accepted.")
        result[key] = value
    return result


def _constant(value):
    raise InputError("Non-finite JSON values are not accepted.")


def parse(raw):
    try:
        return json.loads(raw.decode("utf-8"), object_pairs_hook=_pairs, parse_constant=_constant)
    except (ValueError, UnicodeError, RecursionError) as exc:
        raise InputError("Expected UTF-8 JSON with unique keys and finite values.") from exc


def read(path: Path, limit):
    with path.open("rb") as handle:
        raw = handle.read(limit + 1)
    if len(raw) > limit:
        raise InputError("Input file exceeds its byte limit.")
    return raw


def load_events(path):
    raw = read(path, MAX_EVENT_BYTES)
    events = []
    for number, line in enumerate(raw.splitlines(), 1):
        if not line.strip():
            continue
        if len(line) > 8192:
            raise InputError(f"Event line {number} exceeds 8192 bytes.")
        try:
            events.append(parse(line))
        except InputError as exc:
            raise InputError(f"Invalid JSON event at line {number}.") from exc
        if len(events) > MAX_EVENTS:
            raise InputError("At most 2000 input event records are accepted.")
    ordered, counts = normalize(events)
    return ordered, counts, digest(raw)


def load_rules(path):
    raw = read(path, 65536)
    return validate_rules(parse(raw)), digest(raw)


def load_expected(path, events):
    raw = read(path, 512000)
    return validate_expected(parse(raw), events), digest(raw)
