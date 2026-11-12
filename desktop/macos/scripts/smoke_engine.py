#!/usr/bin/env python3
"""Exercise the frozen engine from an unrelated working directory, using temporary data only."""
import argparse
import json
from pathlib import Path
import subprocess
import sys

SELF_TEST_SCHEMA = "boxcop.self-test.v1"
STATUS_SCHEMA = "boxcop.protection-status.v1"


def smoke_self_test(engine, cwd, env):
    """Run the engine's offline self-test: one JSON line with ok true, exit status 0."""
    result = subprocess.run([str(engine), "--self-test"], cwd=cwd, env=env,
                            capture_output=True, text=True, timeout=60)
    lines = result.stdout.splitlines()
    try:
        report = json.loads(lines[0]) if len(lines) == 1 else None
    except ValueError:
        report = None
    if (result.returncode != 0 or not isinstance(report, dict) or report.get("ok") is not True
            or report.get("schema") != SELF_TEST_SCHEMA):
        raise RuntimeError("Bundled engine failed its offline self-test")
    return report


def smoke_protection_status(engine, data, cwd, env):
    """One-shot status must report every field as a boolean, and no routing in a scratch home."""
    result = subprocess.run([str(engine), "--protection-status", "--data-dir", str(data)], cwd=cwd, env=env,
                            capture_output=True, text=True, timeout=30)
    try:
        report = json.loads(result.stdout)
    except ValueError:
        report = None
    expected = {"package": ("configured", "routed", "listening"), "scripts": ("routed", "listening")}
    if (result.returncode != 0 or not isinstance(report, dict) or report.get("schema") != STATUS_SCHEMA
            or any(type(report.get(section, {}).get(key)) is not bool
                   for section, keys in expected.items() for key in keys)):
        raise RuntimeError("Bundled engine returned an invalid protection status")
    # The scratch home has no npm configuration, so nothing can be routed. "listening"
    # is not checked: it probes fixed local ports, which an installed BoxCop may hold.
    if report["package"]["routed"] or report["scripts"]["routed"]:
        raise RuntimeError("Bundled engine reported routing in an empty home directory")
    return report


def smoke(engine: Path, scratch: Path):
    engine = engine.resolve(strict=True)
    scratch.mkdir(parents=True, exist_ok=False, mode=0o700)
    data = scratch / "private-data"
    cwd = scratch / "unrelated-cwd"
    cwd.mkdir(mode=0o700)
    # No PYTHONPATH and no installed Python: the frozen engine must be self-contained.
    env = {"PATH": "/usr/bin:/bin", "HOME": str(scratch), "LANG": "en_US.UTF-8"}
    self_test = smoke_self_test(engine, cwd, env)
    requests = [
        {"version": 1, "id": "status", "op": "status"},
        {"version": 1, "id": "events", "op": "security_events", "limit": 5},
        {"version": 1, "id": "shutdown", "op": "shutdown"},
    ]
    result = subprocess.run([str(engine), "--data-dir", str(data)], cwd=cwd, env=env,
                            input="".join(json.dumps(item) + "\n" for item in requests),
                            capture_output=True, text=True, timeout=30)
    if result.returncode != 0:
        raise RuntimeError("Bundled engine failed from an unrelated working directory")
    lines = result.stdout.splitlines()
    if len(lines) != len(requests):
        raise RuntimeError("Unexpected JSONL response count")
    responses = [json.loads(line) for line in lines]
    for request, response in zip(requests, responses):
        if response.get("id") != request["id"] or response.get("ok") is not True:
            raise RuntimeError("Protocol validation or request correlation failed")
    status = responses[0].get("result", responses[0])
    if status.get("ready") is not True or status.get("protocol") != 1 or status.get("engine") != "rules":
        raise RuntimeError("Engine status does not match the app contract")
    if status.get("network_listener") is not False:
        raise RuntimeError("Engine incorrectly advertises a network listener")
    events = responses[1].get("events", responses[1].get("result", {}).get("events"))
    if events != []:
        raise RuntimeError("A fresh data directory must have an empty security event list")
    if data.stat().st_mode & 0o077:
        raise RuntimeError("Engine data directory is not private")
    protection = smoke_protection_status(engine, data, cwd, env)
    report = {"platform": sys.platform, "engine": str(engine), "responses": len(responses),
              "self_test": self_test, "protection_status": protection,
              "cwd_independence": True, "native_app_ui_tested": False}
    print(json.dumps(report, indent=2))
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--engine", required=True, type=Path)
    parser.add_argument("--scratch", required=True, type=Path)
    args = parser.parse_args()
    smoke(args.engine, args.scratch)


if __name__ == "__main__":
    main()
