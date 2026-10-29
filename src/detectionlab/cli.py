import argparse
import os
import sys
from pathlib import Path

from . import __version__
from .fixtures import SCENARIOS, scenario
from .model import InputError, json_bytes, jsonl_bytes, load_events, load_expected, load_rules
from .report import compile_replay


def write_new(output, files):
    output.mkdir(mode=0o700, parents=False, exist_ok=False)
    for name, raw in files.items():
        fd = os.open(output / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as handle:
            handle.write(raw)


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Replay normalized security events with exact evidence checks."
    )
    parser.add_argument(
        "--version", action="version", version=f"security-detection-lab {__version__}"
    )
    commands = parser.add_subparsers(dest="command", required=True)
    generate = commands.add_parser(
        "generate", help="Write deterministic synthetic data; no attacks are executed."
    )
    generate.add_argument("--scenario", choices=SCENARIOS, required=True)
    generate.add_argument("--output", type=Path, required=True)
    replay = commands.add_parser("replay", help="Create a replay package in a new directory.")
    replay.add_argument("--events", type=Path, required=True)
    replay.add_argument("--rules", type=Path, required=True)
    replay.add_argument("--expect", type=Path)
    replay.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        if args.command == "generate":
            events, rules, expected = scenario(args.scenario)
            write_new(
                args.output,
                {
                    "events.jsonl": jsonl_bytes(events),
                    "rules.json": json_bytes(rules),
                    "expected.json": json_bytes(expected),
                },
            )
            print("SYNTHETIC DATA | 3 files | no attack or network activity")
            return 0
        events, counts, event_hash = load_events(args.events)
        rules, rule_hash = load_rules(args.rules)
        hashes = {"events": event_hash, "rules": rule_hash}
        expected = None
        if args.expect:
            expected, hashes["expected"] = load_expected(args.expect, events)
        files, result = compile_replay(events, rules, expected, hashes, counts)
        write_new(args.output, files)
        print(
            f"{result['status'].upper()} | {len(result['alerts'])} alerts | "
            f"{counts['unique_events']} unique events | "
            f"{counts['duplicates_removed']} duplicates removed | "
            f"expectations={result['evaluation']['status']} | offline-normalized-event-replay"
        )
        return 1 if result["evaluation"]["status"] == "failed" else 0
    except InputError as exc:
        print(f"Input error: {exc}", file=sys.stderr)
    except FileExistsError:
        print("Output exists; choose a new directory. No files overwritten.", file=sys.stderr)
    except OSError:
        print(
            "File operation failed. Partial output may remain; require a complete manifest "
            "and matching hashes before use.",
            file=sys.stderr,
        )
    return 2


if __name__ == "__main__":
    sys.exit(main())
