#!/usr/bin/env python3
"""Exercise an actual frozen helper from an unrelated cwd, using fake data only."""
import argparse
import json
import os
from pathlib import Path
import subprocess
import sys


def smoke_classifier(engine, cwd, env):
    # Exercise the actual frozen ONNX, tokenizer, NumPy, pinned model and head.
    # This entrypoint has fixed fake input and cannot reach Ollama or user data.
    result = subprocess.run([str(engine), "--classifier-self-test"], cwd=cwd, env=env,
                            capture_output=True, text=True, timeout=20)
    expected = {"ready": True, "backend": "minilm-head-v1", "shadow_only": True}
    if result.returncode != 0 or result.stderr.strip() or json.loads(result.stdout) != expected:
        raise RuntimeError("Bundled MiniLM classifier failed its local inference self-test")
    return expected


def smoke(engine: Path, scratch: Path):
    engine = engine.resolve(strict=True)
    scratch.mkdir(parents=True, exist_ok=False, mode=0o700)
    data = scratch / "private-data"
    cwd = scratch / "unrelated-cwd"
    cwd.mkdir(mode=0o700)
    marker = "FAKE_MACOS_SMOKE_NOT_A_REAL_KEY_123456"
    def event(kind, content):
        return {"kind": kind, "content": content, "app_bundle_id": "com.apple.TextEdit", "app_pid": 123, "role": "engineering"}
    requests = [
        {"version": 1, "id": "status", "op": "status"},
        {"version": 1, "id": "clean", "op": "evaluate", "event": event("paste_attempt", "hello from the standalone runtime")},
        {"version": 1, "id": "copy", "op": "evaluate", "event": event("clipboard_copy", "api_key=" + marker)},
        {"version": 1, "id": "paste", "op": "evaluate", "event": event("paste_attempt", "api_key=" + marker)},
        {"version": 1, "id": "recent", "op": "recent", "limit": 30},
        {"version": 1, "id": "shutdown", "op": "shutdown"},
    ]
    env = {"PATH": "/usr/bin:/bin", "HOME": str(scratch), "LANG": "en_US.UTF-8"}
    classifier = smoke_classifier(engine, cwd, env)
    result = subprocess.run([str(engine), "--data-dir", str(data)], cwd=cwd, env=env,
                            input="".join(json.dumps(item) + "\n" for item in requests),
                            capture_output=True, text=True, timeout=15)
    if result.returncode != 0:
        raise RuntimeError("Bundled engine failed from an unrelated working directory")
    if marker in result.stdout or marker in result.stderr:
        raise RuntimeError("Raw fake clipboard marker leaked through process output")
    lines = result.stdout.splitlines()
    if len(lines) != len(requests):
        raise RuntimeError("Unexpected JSONL response count")
    responses = [json.loads(line) for line in lines]
    for request, response in zip(requests, responses):
        if response.get("version") != 1 or response.get("id") != request["id"] or response.get("ok") is not True:
            raise RuntimeError("Protocol validation or request correlation failed")
    if responses[0]["result"]["network_listener"] is not False:
        raise RuntimeError("Sidecar incorrectly advertises a network listener")
    expected = ["allow", "warn", "block"]
    actual = [response["result"]["record"]["decision"]["action"] for response in responses[1:4]]
    if actual != expected:
        raise RuntimeError(f"Unexpected real-engine decisions: {actual}")
    recent = responses[4]["result"]
    if recent["total"] != 3 or len(recent["items"]) != 3:
        raise RuntimeError("Durable audit readback did not match evaluated records")
    for record in recent["items"]:
        if record["event"]["content"] != "[not retained]" or record["decision"]["redacted_content"] != "[not retained]":
            raise RuntimeError("Raw preview retention was enabled unexpectedly")
    for file in data.rglob("*"):
        if file.is_file() and marker.encode() in file.read_bytes():
            raise RuntimeError("Raw fake clipboard marker leaked into durable storage")
    if data.stat().st_mode & 0o077:
        raise RuntimeError("Sidecar data directory is not private")
    report = {"platform": sys.platform, "engine": str(engine), "responses": len(responses), "decisions": actual,
              "audit_records": recent["total"], "raw_marker_retained": False,
              "cwd_independence": True, "classifier": classifier, "native_app_ui_tested": False}
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
