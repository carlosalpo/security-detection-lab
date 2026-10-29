"""Exercise the installed CLI; expectations are committed independently of the engine."""

import argparse
import csv
import hashlib
import json
import shutil
import subprocess
from pathlib import Path

from detectionlab.fixtures import SCENARIOS


def run(args, code):
    result = subprocess.run(args, capture_output=True, text=True, check=False)
    if result.returncode != code:
        raise RuntimeError(f"Expected exit {code}, got {result.returncode}: {result.stderr}")
    return result.stdout.strip() or result.stderr.strip()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, required=True)
    output = parser.parse_args().output
    output.mkdir(parents=True, exist_ok=False)
    cli = shutil.which("sdl")
    if cli is None:
        raise RuntimeError("Install the package and activate its environment first.")
    root = Path(__file__).resolve().parents[1]
    results = []
    for name in SCENARIOS:
        source = output / (name + "-input")
        package = output / name
        run([cli, "generate", "--scenario", name, "--output", str(source)], 0)
        for file in source.iterdir():
            assert file.read_bytes() == (root / "examples" / name / file.name).read_bytes()
        code = 1 if name == "expectation-mismatch" else 0
        message = run(
            [
                cli,
                "replay",
                "--events",
                str(source / "events.jsonl"),
                "--rules",
                str(source / "rules.json"),
                "--expect",
                str(source / "expected.json"),
                "--output",
                str(package),
            ],
            code,
        )
        manifest = json.loads((package / "manifest.json").read_text())
        assert len(manifest["files"]) == 8
        for file, info in manifest["files"].items():
            raw = (package / file).read_bytes()
            assert info == {"bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}
        for key, file in [
            ("events", "events.jsonl"),
            ("rules", "rules.json"),
            ("expected", "expected.json"),
        ]:
            assert (
                manifest["source_sha256"][key]
                == hashlib.sha256((source / file).read_bytes()).hexdigest()
            )
        replay = json.loads((package / "replay.json").read_text())
        ids = {
            json.loads(line)["id"] for line in (package / "events.jsonl").read_text().splitlines()
        }
        for alert in replay["alerts"]:
            assert alert["trigger_id"] in ids
            assert set(alert["evidence_ids"]) <= ids
        with (package / "alerts.csv").open(newline="") as handle:
            assert len(list(csv.DictReader(handle))) == len(replay["alerts"])
        assert replay["evaluation"]["status"] == ("failed" if code else "passed")
        results.append({"scenario": name, "exit_code": code, "output": message})
        print(f"PASS {name} | exit={code} | {message}")
    bad = output / "conflicting-id.jsonl"
    events = [
        json.loads(line)
        for line in (output / "auth-burst-input/events.jsonl").read_text().splitlines()
    ]
    conflict = dict(events[0], outcome="success")
    bad.write_text(json.dumps(events[0]) + "\n" + json.dumps(conflict) + "\n")
    target = output / "invalid-output"
    message = run(
        [
            cli,
            "replay",
            "--events",
            str(bad),
            "--rules",
            str(output / "auth-burst-input/rules.json"),
            "--output",
            str(target),
        ],
        2,
    )
    assert not target.exists()
    results.append({"scenario": "conflicting-id", "exit_code": 2, "output": message})
    print(f"PASS conflicting-id | exit=2 | {message}")
    (output / "verification.json").write_text(json.dumps(results, indent=2) + "\n")
    print("9 CLI scenarios verified; deliberate mismatch and invalid-input exits are expected.")


if __name__ == "__main__":
    main()
