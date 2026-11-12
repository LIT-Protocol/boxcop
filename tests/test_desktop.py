"""Real pipe/Engine/SQLite tests; only disposable fake data, never the lab API."""
from contextlib import contextmanager
import json
import os
from pathlib import Path
import select
import sqlite3
import stat
import subprocess
import sys
import time
from uuid import UUID

import pytest
from server.classifier_usage import MINILM_BACKEND, QWEN_BACKEND, empty_counts

ROOT = Path(__file__).resolve().parents[1]
MAX_LINE = 262144
DATABASE = "events.sqlite3"
NOT_RETAINED = "[not retained]"
MESSAGES = {
    "invalid_request": "Invalid request.",
    "line_too_large": "Request line too large.",
    "internal_error": "Internal engine error.",
}


def child_env():
    # Copy, never mutate the caller's environment or umask.
    env = dict(os.environ, PYTHONDONTWRITEBYTECODE="1")
    env.pop("PYTHONPATH", None)
    env.pop("PYTHONHOME", None)
    return env


def request(op, identifier="r1", **fields):
    return {"version": 1, "id": identifier, "op": op, **fields}


def event(kind="paste_attempt", content="FAKE_ORDINARY_CLIPBOARD_BODY", **updates):
    return {
        "kind": kind, "content": content, "app_bundle_id": "com.apple.TextEdit",
        "app_pid": 123, "role": "engineering", **updates,
    }


def frame(payload):
    return (json.dumps(payload, ensure_ascii=True, separators=(",", ":")) + "\n").encode()


def run_sidecar(data_dir, payload=b"", *, arguments=None):
    args = ["--data-dir", str(data_dir)] if arguments is None else arguments
    return subprocess.run(
        [sys.executable, "-m", "server.desktop", *args], input=payload,
        capture_output=True, timeout=8, cwd=ROOT, env=child_env(),
    )


class PipeClient:
    def __init__(self, process):
        self.process = process
        self.transcript = bytearray()
        self.pending = bytearray()

    def read(self, timeout=5):
        deadline = time.monotonic() + timeout
        while b"\n" not in self.pending:
            remaining = deadline - time.monotonic()
            assert remaining > 0, "Sidecar response deadline exceeded"
            ready, _, _ = select.select([self.process.stdout], [], [], remaining)
            assert ready, "Sidecar response deadline exceeded"
            chunk = os.read(self.process.stdout.fileno(), MAX_LINE + 1)
            assert chunk, "Sidecar exited without a protocol response"
            self.transcript.extend(chunk)
            self.pending.extend(chunk)
        raw, _, rest = self.pending.partition(b"\n")
        self.pending = bytearray(rest)
        assert len(raw) + 1 <= MAX_LINE
        return json.loads(raw)

    def send(self, payload):
        self.process.stdin.write(frame(payload))
        self.process.stdin.flush()
        return self.read()


@contextmanager
def sidecar(data_dir, *, launcher=None):
    args = [sys.executable, "-m", "server.desktop"] if launcher is None else [sys.executable, "-c", launcher]
    process = subprocess.Popen(
        [*args, "--data-dir", str(data_dir)], stdin=subprocess.PIPE,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, bufsize=0,
        cwd=ROOT, env=child_env(),
    )
    try:
        yield PipeClient(process)
    finally:
        if process.poll() is None:
            process.terminate()
        process.wait(timeout=5)
        process.stdin.close()
        process.stdout.close()
        process.stderr.close()


def assert_error(payload, code="invalid_request", identifier=None):
    assert payload == {
        "version": 1, "id": identifier, "ok": False,
        "error": {"code": code, "message": MESSAGES[code]},
    }


def test_model_usage_survives_real_sidecar_restart(tmp_path):
    # Only inference is substituted; exercise real pipes, worker and SQLite.
    launcher = """
from server.classification import LocalAdvisor, Observation
from server.classifier_usage import MINILM_BACKEND
LocalAdvisor._classify = lambda self, text: Observation('ready', 'public', MINILM_BACKEND)
from server.desktop import main
raise SystemExit(main())
"""
    data = tmp_path / 'data'
    with sidecar(data, launcher=launcher) as client:
        assert client.send(request('evaluate', event=event()))['ok'] is True
        deadline = time.monotonic() + 3
        while True:
            classification = client.send(request('status'))['result']['classification']
            if classification['completed'] == 1:
                break
            assert time.monotonic() < deadline
            time.sleep(.01)
        assert classification['model_usage']['persistence_ok'] is True
        assert classification['model_usage']['backends'][MINILM_BACKEND]['attempts'] == 1
        client.send(request('shutdown'))
        assert client.process.wait(timeout=3) == 0
    with sidecar(data, launcher=launcher) as client:
        restarted = client.send(request('status'))['result']['classification']
        assert restarted['model_usage'] == classification['model_usage']
        assert restarted['hits'] == restarted['misses'] == restarted['cached'] == 0


def test_import_is_inert_and_exposes_frozen_launcher_main():
    script = """
import os, sys
before_env = dict(os.environ)
before_cwd = os.getcwd()
before_mask = os.umask(0o077)
os.umask(before_mask)
def guard(name, args):
    if name in {'sqlite3.connect', 'os.mkdir', 'socket.__new__', 'subprocess.Popen'}:
        raise AssertionError('Import performed forbidden work')
    if name == 'import' and args[0] in {'server.app', 'server.semantic', 'uvicorn'}:
        raise AssertionError('Import crossed the desktop boundary')
sys.addaudithook(guard)
from server.desktop import main
assert callable(main)
assert dict(os.environ) == before_env
assert os.getcwd() == before_cwd
mask = os.umask(before_mask)
assert mask == before_mask
assert not {'server.app', 'server.semantic', 'uvicorn'}.intersection(sys.modules)
"""
    result = subprocess.run([sys.executable, "-c", script], cwd=ROOT, env=child_env(),
                            capture_output=True, timeout=8)
    assert result.returncode == 0, result.stderr.decode()
    assert result.stdout == result.stderr == b""


def test_status_policies_recent_shutdown_use_only_inherited_pipes(tmp_path):
    from server.models import POLICIES

    data = tmp_path / "private"
    launcher = """
import sys
def guard(name, args):
    if name.startswith('socket.') or name == 'subprocess.Popen':
        raise AssertionError('Desktop attempted network or child collection')
    if name == 'import' and args[0] in {'server.app', 'server.semantic', 'uvicorn'}:
        raise AssertionError('Desktop imported a network or semantic service')
sys.addaudithook(guard)
from server.desktop import main
raise SystemExit(main())
"""
    with sidecar(data, launcher=launcher) as client:
        assert client.send(request("status")) == {
            "version": 1, "id": "r1", "ok": True,
            "result": {"ready": True, "protocol": 1, "engine": "rules+sequence",
                       "monitoring": False, "network_listener": False,
                       "classification": {"hits": 0, "misses": 0, "coalesced": 0, "dropped": 0,
                                          "completed": 0, "failures": 0, "queued": 0, "cached": 0,
                                          "active": False, "shadow_only": True, "ready": 0,
                                          "unavailable": 0, "uncertain": 0,
                                          "model_usage": {"persistence_ok": True, "backends": empty_counts()}}},
        }
        assert client.send(request("policies", "p1")) == {
            "version": 1, "id": "p1", "ok": True,
            "result": {"items": [{**p, "enabled": True} for p in POLICIES]},
        }
        assert client.send(request("recent", "recent1", limit=30)) == {
            "version": 1, "id": "recent1", "ok": True, "result": {"items": [], "total": 0},
        }
        # Exercise the real classifier and persistence under the same no-socket
        # audit hook, not just the control operations.
        for kind in ("clipboard_copy", "paste_attempt"):
            assert client.send(request("evaluate", kind, event=event(kind)))["ok"] is True
        if sys.platform == "linux":
            assert not any(p.readlink().as_posix().startswith("socket:")
                           for p in Path(f"/proc/{client.process.pid}/fd").iterdir())
        assert client.send(request("shutdown", "bye")) == {
            "version": 1, "id": "bye", "ok": True, "result": {"stopped": True},
        }
        assert client.process.wait(timeout=5) == 0
        assert client.process.stdout.read() == client.process.stderr.read() == b""
    assert stat.S_IMODE(data.stat().st_mode) == 0o700
    # A daemon inference worker may be interrupted during a usage-counter write.
    # SQLite's recovery files are legitimate; no unrelated persistence is allowed.
    assert DATABASE in {p.name for p in data.iterdir()}
    assert {p.name for p in data.iterdir()} <= {DATABASE, DATABASE + '-wal', DATABASE + '-shm'}
    assert stat.S_IMODE((data / DATABASE).stat().st_mode) == 0o600


def test_actual_engine_decisions_fixed_metadata_and_db_wal_privacy(tmp_path):
    from server.models import Record

    data = tmp_path / "private"
    marker = "FAKE_DESKTOP_CREDENTIAL_123456789"
    body = f"api_key={marker}"
    before_env = dict(os.environ)
    with sidecar(data) as client:
        assert client.send(request("status"))["ok"] is True
        # A real reader keeps the WAL observable while the child writes.
        keeper = sqlite3.connect(data / DATABASE)
        try:
            keeper.execute("BEGIN")
            keeper.execute("SELECT COUNT(*) FROM events").fetchone()
            copied_response = client.send(request("evaluate", "copy1", event=event(
                "clipboard_copy", body, app_bundle_id="com.example.editor", role="hr")))
            assert set(copied_response) == {"version", "id", "ok", "result"}
            assert copied_response["id"] == "copy1" and copied_response["ok"] is True
            assert set(copied_response["result"]) == {"record"}
            copied = copied_response["result"]["record"]
            pasted = client.send(request("evaluate", "paste1", event=event(
                content=body, app_bundle_id="com.example.browser", role="finance")))["result"]["record"]
            clean_marker = "FAKE_UNCLASSIFIED_PRIVATE_DESKTOP_BODY"
            clean = client.send(request("evaluate", "clean1", event=event(content=clean_marker)))["result"]["record"]
            for item in (copied, pasted, clean):
                Record.model_validate(item)
                assert item["synthetic"] is item["event"]["synthetic"] is False
                assert item["event"]["actor"] == "human"
                assert item["event"]["content"] == item["decision"]["redacted_content"] == NOT_RETAINED
                assert "app_pid" not in item["event"]
                assert UUID(item["event"]["session_id"]).version == 4
            assert copied["event"] == {
                "session_id": copied["event"]["session_id"], "actor": "human", "role": "hr",
                "action": "copy", "app": "com.example.editor", "source": "app://com.example.editor",
                "destination": "", "content": NOT_RETAINED, "synthetic": False,
                "declared_intent": "Clipboard change observed while this app was frontmost; copy origin is not verified.",
            }
            assert pasted["event"]["role"] == "finance"
            assert pasted["event"]["action"] == "paste"
            assert pasted["event"]["source"] == ""
            assert pasted["event"]["destination"] == "app://com.example.browser"
            assert pasted["event"]["declared_intent"] == "Paste shortcut attempted for this app; insertion and network egress are not confirmed."
            assert copied["decision"]["action"] == "warn"
            assert pasted["decision"]["action"] == "block"
            assert pasted["decision"]["context_event_ids"] == [copied["id"]]
            assert "secret-egress" in pasted["decision"]["policy_ids"]
            assert "sensitive-lineage" in pasted["decision"]["policy_ids"]
            assert clean["decision"]["action"] == "allow"
            assert clean["decision"]["context_event_ids"] == []
            assert client.send(request("recent", "recent1", limit=2))["result"] == {
                "items": [clean, pasted], "total": 3,
            }
            wal = data / (DATABASE + "-wal")
            assert wal.is_file() and wal.stat().st_size > 0
            for path in data.iterdir():
                assert stat.S_IMODE(path.stat().st_mode) == 0o600
                for secret in (marker, clean_marker, body):
                    assert secret.encode() not in path.read_bytes()
            for secret in (marker, clean_marker, body):
                assert secret.encode() not in client.transcript
        finally:
            keeper.close()
        client.send(request("shutdown"))
        assert client.process.wait(timeout=5) == 0
        assert client.process.stderr.read() == b""
    assert dict(os.environ) == before_env
    with sqlite3.connect(data / DATABASE) as db:
        durable = [json.loads(row[0]) for row in db.execute("SELECT record FROM events ORDER BY sequence")]
        assert durable == [copied, pasted, clean]
        assert db.execute("PRAGMA integrity_check").fetchone() == ("ok",)
        assert not {"content_hash", "session_hash"}.intersection(
            row[1] for row in db.execute("PRAGMA table_info(events)"))


def test_restart_rotates_session_and_lineage_but_keeps_sanitized_audit(tmp_path):
    data = tmp_path / "private"
    body = "api_key=FAKE_DESKTOP_RESTART_123456789"
    with sidecar(data) as client:
        copied = client.send(request("evaluate", event=event("clipboard_copy", body)))["result"]["record"]
        client.send(request("shutdown"))
        assert client.process.wait(timeout=5) == 0
    with sidecar(data) as client:
        pasted = client.send(request("evaluate", event=event(content=body)))["result"]["record"]
        assert pasted["event"]["session_id"] != copied["event"]["session_id"]
        assert pasted["decision"]["context_event_ids"] == []
        assert pasted["decision"]["action"] == "block"
        assert client.send(request("recent", limit=30))["result"] == {
            "items": [pasted, copied], "total": 2,
        }


def test_eof_exits_without_unsolicited_output_and_shutdown_ignores_tail(tmp_path):
    empty = run_sidecar(tmp_path / "empty")
    assert empty.returncode == 0
    assert empty.stdout == empty.stderr == b""
    result = run_sidecar(tmp_path / "tail", frame(request("shutdown", "bye")) + frame(request("evaluate", event=event())))
    assert result.returncode == 0
    assert result.stderr == b""
    assert result.stdout == frame({"version": 1, "id": "bye", "ok": True, "result": {"stopped": True}})
    with sqlite3.connect(tmp_path / "tail" / DATABASE) as db:
        assert db.execute("SELECT COUNT(*) FROM events").fetchone() == (0,)


INVALID_REQUESTS = [
    pytest.param({}, None, id="empty-object"),
    pytest.param([], None, id="array"),
    pytest.param(None, None, id="null"),
    pytest.param(request("status", version=True), "r1", id="boolean-version"),
    pytest.param(request("status", version=1.0), "r1", id="float-version"),
    pytest.param(request("status", version=2), "r1", id="unknown-version"),
    pytest.param(request("status", version="1"), "r1", id="string-version"),
    pytest.param(request("unknown"), "r1", id="unknown-operation"),
    pytest.param(request(["status"]), "r1", id="array-operation"),
    pytest.param(request(None), "r1", id="null-operation"),
    *[pytest.param(request("status", identifier), None, id=f"bad-id-{index}") for index, identifier in enumerate(
        ("", "a" * 65, "has space", "r\n1", "hello.1", "é", "FAKE_PRIVATE/request", 12, True, None, []))],
    *[pytest.param({key: value for key, value in request("status").items() if key != missing},
                   None if missing == "id" else "r1", id=f"missing-{missing}")
      for missing in ("version", "id", "op")],
    *[pytest.param(request(op, injected="FAKE_FORBIDDEN_METADATA"), "r1", id=f"extra-{op}")
      for op in ("status", "policies", "recent", "evaluate", "shutdown")],
    pytest.param(request("status", event=event()), "r1", id="status-event"),
    pytest.param(request("shutdown", limit=1), "r1", id="shutdown-limit"),
    pytest.param(request("policies", enabled=False), "r1", id="policy-mutation"),
    pytest.param(request("recent"), "r1", id="missing-limit"),
    *[pytest.param(request("recent", limit=limit), "r1", id=f"bad-limit-{index}")
      for index, limit in enumerate((True, 0, -1, 501, 1.0, "30", None))],
    pytest.param(request("evaluate"), "r1", id="missing-event"),
    pytest.param(request("evaluate", event=[]), "r1", id="array-event"),
    pytest.param(request("evaluate", event=None), "r1", id="null-event"),
    *[pytest.param(request("evaluate", event={key: value for key, value in event().items() if key != missing}),
                   "r1", id=f"missing-event-{missing}") for missing in event()],
    *[pytest.param(request("evaluate", event=event(**{field: value})), "r1", id=f"bad-event-{index}")
      for index, (field, value) in enumerate((
          ("kind", "command"), ("kind", []), ("role", "administrator"), ("role", None),
          ("role", []), ("app_pid", True), ("app_pid", 0), ("app_pid", -1),
          ("app_pid", 1.0), ("app_pid", "123"), ("app_pid", None),
          ("content", None), ("content", []), ("content", "a" * 4097),
          ("content", "🦉" * 4097), ("content", "\ud800"), ("content", "\udfff"),
          ("app_bundle_id", ""), ("app_bundle_id", "é.com.app"), ("app_bundle_id", "com.app/x"),
          ("app_bundle_id", "com.app\n"), ("app_bundle_id", ".com.app"),
          ("app_bundle_id", "-com.app"), ("app_bundle_id", "a" * 256),
          ("app_bundle_id", "http://example.invalid"), ("app_bundle_id", 12),
          ("app_bundle_id", "com_app"), ("app_bundle_id", None),
      ))],
    *[pytest.param(request("evaluate", event=event(**{key: value})), "r1", id=f"forbidden-{key}")
      for key, value in {
          "session_id": "caller-session", "synthetic": True, "actor": "agent",
          "source": "Workday", "destination": "local", "declared_intent": "FAKE_INJECTED_INTENT",
          "retain_preview": True, "title": "FAKE_WINDOW_TITLE", "url": "https://example.invalid",
      }.items()],
]


@pytest.mark.parametrize("payload,identifier", INVALID_REQUESTS)
def test_exact_operation_shapes_reject_without_audit_and_keep_correlation(tmp_path, payload, identifier):
    result = run_sidecar(tmp_path / "private", frame(payload) + frame(request("recent", "after", limit=30)))
    assert result.returncode == 0
    assert result.stderr == b""
    replies = [json.loads(line) for line in result.stdout.splitlines()]
    assert len(replies) == 2
    assert_error(replies[0], identifier=identifier)
    assert replies[1] == {"version": 1, "id": "after", "ok": True, "result": {"items": [], "total": 0}}
    assert b"FAKE_FORBIDDEN_METADATA" not in result.stdout


@pytest.mark.parametrize("raw", [
    b"\n", b"not JSON FAKE_MALFORMED_BODY\n", b'{"id":"r1"\n',
    b'{"version":1,"id":"r1","id":"r2","op":"status"}\n',
    b'{"version":1,"id":"r1","op":"status","op":"shutdown"}\n',
    frame(request("evaluate", event=event())).replace(b'"role":"engineering"', b'"role":"engineering","role":"hr"'),
    b'{"version":NaN,"id":"r1","op":"status"}\n',
    b'{"version":Infinity,"id":"r1","op":"status"}\n',
    b'{"version":-Infinity,"id":"r1","op":"status"}\n',
    b'\xff\n', b'\xef\xbb\xbf' + frame(request("status")),
    (json.dumps(request("status")) + "\n").encode("utf-16") + b"\n",
    b'[' * 2000 + b'0' + b']' * 2000 + b'\n',
    b'{"version":' + b'9' * 5000 + b',"id":"r1","op":"status"}\n',
], ids=["blank", "not-json", "unfinished-json", "duplicate-id", "duplicate-op", "nested-duplicate",
        "nan", "infinity", "negative-infinity", "invalid-utf8", "bom", "utf16", "deep-json", "huge-number"])
def test_strict_utf8_json_errors_are_fixed_and_recover_on_next_frame(tmp_path, raw):
    result = run_sidecar(tmp_path / "private", raw + frame(request("status", "after")))
    assert result.returncode == 0
    assert result.stderr == b""
    replies = [json.loads(line) for line in result.stdout.splitlines()]
    # UTF-16 contains an embedded LF followed by NUL: both invalid frames are refused.
    invalid_count = 2 if raw.startswith(b"\xff\xfe") else 1
    assert len(replies) == invalid_count + 1
    for reply in replies[:-1]:
        assert_error(reply)
    assert replies[-1]["id"] == "after" and replies[-1]["ok"] is True
    assert b"FAKE_MALFORMED_BODY" not in result.stdout


@pytest.mark.parametrize("content", ["", "a" * 4096, "🦉" * 4096, "a\u0301" * 2048, "\x00\n\t"])
def test_content_is_bounded_by_unicode_scalars_not_utf8_or_utf16_units(tmp_path, content):
    result = run_sidecar(tmp_path / "private", frame(request("evaluate", "Z_" + "9" * 61 + "-", event=event(content=content, app_bundle_id="a" * 255))))
    assert result.returncode == 0
    assert result.stderr == b""
    reply = json.loads(result.stdout)
    assert reply["ok"] is True
    assert reply["id"] == "Z_" + "9" * 61 + "-"
    assert reply["result"]["record"]["event"]["content"] == NOT_RETAINED


def test_exact_frame_limit_and_crlf_are_accepted(tmp_path):
    wire = frame(request("status", "boundary"))
    padded = wire[:-1] + b" " * (MAX_LINE - len(wire)) + b"\n"
    assert len(padded) == MAX_LINE
    result = run_sidecar(tmp_path / "private", padded + frame(request("status", "crlf"))[:-1] + b"\r\n")
    assert result.returncode == 0 and result.stderr == b""
    assert [item["id"] for item in map(json.loads, result.stdout.splitlines())] == ["boundary", "crlf"]


def test_oversize_frame_exits_before_newline_or_eof_without_draining(tmp_path):
    with sidecar(tmp_path / "private") as client:
        assert client.send(request("status"))["ok"] is True
        wire = b'{"id":"FAKE_PRIVATE_OVERSIZE",' + b"x" * MAX_LINE
        client.process.stdin.write(wire[:MAX_LINE + 1])
        client.process.stdin.flush()
        # stdin intentionally remains open, with no delimiter or EOF supplied.
        assert_error(client.read(), "line_too_large")
        assert client.process.wait(timeout=5) != 0
        assert client.process.stdout.read() == client.process.stderr.read() == b""
        assert b"FAKE_PRIVATE_OVERSIZE" not in client.transcript


def test_unterminated_frame_is_never_evaluated_at_eof(tmp_path):
    result = run_sidecar(tmp_path / "private", frame(request("evaluate", event=event()))[:-1])
    assert result.returncode == 0 and result.stderr == b""
    assert_error(json.loads(result.stdout))
    with sqlite3.connect(tmp_path / "private" / DATABASE) as db:
        assert db.execute("SELECT COUNT(*) FROM events").fetchone() == (0,)


def assert_startup_refused(result):
    assert result.returncode != 0
    assert result.stdout == b""
    assert result.stderr == b"BoxCop engine could not start.\n"


@pytest.mark.parametrize("arguments", [[], ["--help"], ["--data-dir"], ["--FAKE_PRIVATE_FLAG"],
                                       ["--data-dir", "a", "--data-dir", "b"]])
def test_cli_usage_never_echoes_arguments_or_defaults_to_lab(tmp_path, arguments):
    arguments = [str(tmp_path / arg) if arg in {"a", "b"} else arg for arg in arguments]
    assert_startup_refused(run_sidecar(tmp_path / "unused", arguments=arguments))


def test_relative_data_directory_is_refused_without_creation(tmp_path):
    relative = os.path.relpath(tmp_path / "private", ROOT)
    assert_startup_refused(run_sidecar(relative))
    assert not (tmp_path / "private").exists()


@pytest.mark.parametrize("case", ["public-directory", "symlink-directory", "symlink-parent", "file-directory", "writable-parent", "parent-traversal"])
def test_unsafe_directory_paths_are_refused_without_chmod_or_writes(tmp_path, case):
    target = tmp_path / "FAKE_UNRELATED_TARGET"
    target.mkdir(mode=0o700)
    path = target
    if case == "public-directory":
        target.chmod(0o755)
    elif case == "symlink-directory":
        path = tmp_path / "linked"
        path.symlink_to(target, target_is_directory=True)
    elif case == "symlink-parent":
        linked = tmp_path / "linked"
        linked.symlink_to(target, target_is_directory=True)
        path = linked / "private"
    elif case == "file-directory":
        path = tmp_path / "FAKE_PRIVATE_FILE"
        path.write_bytes(b"FAKE_DO_NOT_CHANGE")
    elif case == "writable-parent":
        target.chmod(0o777)
        path = target / "private"
    elif case == "parent-traversal":
        path = str(target / ".." / "private")
    before = target.stat()
    assert_startup_refused(run_sidecar(path))
    assert target.stat().st_mode == before.st_mode
    assert list(target.iterdir()) == []
    if case == "file-directory":
        assert path.read_bytes() == b"FAKE_DO_NOT_CHANGE"
    assert not (tmp_path / "private").exists()


@pytest.mark.parametrize("suffix", ["", "-wal", "-shm", "-journal"])
@pytest.mark.parametrize("kind", ["symlink", "hardlink", "public-file", "directory", "fifo"])
def test_unsafe_database_and_sqlite_companions_are_refused_before_store(tmp_path, suffix, kind):
    data = tmp_path / "private"
    data.mkdir(mode=0o700)
    unrelated = tmp_path / "FAKE_UNRELATED_FILE"
    unrelated.write_bytes(b"FAKE_UNRELATED_FILE_CONTENT")
    unrelated.chmod(0o600)
    path = data / (DATABASE + suffix)
    if kind == "symlink":
        path.symlink_to(unrelated)
    elif kind == "hardlink":
        path.hardlink_to(unrelated)
    elif kind == "public-file":
        path.write_bytes(b"")
        path.chmod(0o644)
    elif kind == "directory":
        path.mkdir(mode=0o700)
    else:
        os.mkfifo(path, mode=0o600)
    before = path.lstat()
    assert_startup_refused(run_sidecar(data, frame(request("status"))))
    assert unrelated.read_bytes() == b"FAKE_UNRELATED_FILE_CONTENT"
    assert path.lstat().st_mode == before.st_mode
    if kind == "public-file":
        assert path.read_bytes() == b""


@pytest.mark.parametrize("suffix", ["-wal", "-shm", "-journal"])
@pytest.mark.parametrize("replacement", ["missing", "private", "public", "hardlink", "unlinked"])
def test_database_companion_unlink_race_rechecks_replacement(monkeypatch, suffix, replacement):
    from types import SimpleNamespace
    from server.desktop import _check_database_files
    calls = []

    def racing_stat(path, *, dir_fd, follow_symlinks):
        assert dir_fd == 123 and follow_symlinks is False
        if path != DATABASE + suffix:
            raise FileNotFoundError
        calls.append(path)
        if len(calls) == 1 or replacement == "unlinked":
            return SimpleNamespace(st_mode=stat.S_IFREG | 0o600, st_uid=os.getuid(), st_nlink=0)
        if replacement == "missing":
            raise FileNotFoundError
        return SimpleNamespace(st_mode=stat.S_IFREG | (0o644 if replacement == "public" else 0o600),
                               st_uid=os.getuid(), st_nlink=2 if replacement == "hardlink" else 1)

    with monkeypatch.context() as patch:
        patch.setattr(os, "stat", racing_stat)
        if replacement in {"missing", "private"}:
            _check_database_files(123)
        else:
            with pytest.raises(ValueError):
                _check_database_files(123)
    assert len(calls) == (3 if replacement == "unlinked" else 2)


def test_unlinked_main_database_is_still_rejected(monkeypatch):
    from types import SimpleNamespace
    from server.desktop import _check_database_files
    with monkeypatch.context() as patch:
        patch.setattr(os, "stat", lambda *a, **kw: SimpleNamespace(
            st_mode=stat.S_IFREG | 0o600, st_uid=os.getuid(), st_nlink=0))
        with pytest.raises(ValueError, match="Unsafe database file"):
            _check_database_files(123)


@pytest.mark.parametrize("mask", [0, 0o777])
def test_nested_private_creation_preserves_existing_parent_and_caller_state(tmp_path, mask):
    parent = tmp_path / "existing-parent"
    parent.mkdir(mode=0o755)
    parent.chmod(0o755)
    data = parent / "new-parent" / "private"
    launcher = f"""
import os
from server.desktop import main
os.umask({mask})
before_env = dict(os.environ)
before_cwd = os.getcwd()
code = main()
assert dict(os.environ) == before_env
assert os.getcwd() == before_cwd
assert os.umask({mask}) == {mask}
raise SystemExit(code)
"""
    try:
        with sidecar(data, launcher=launcher) as client:
            assert client.send(request("status"))["ok"] is True
            client.send(request("shutdown"))
            assert client.process.wait(timeout=5) == 0
            assert client.process.stderr.read() == b""
        assert stat.S_IMODE(parent.stat().st_mode) == 0o755
        for directory in (data.parent, data):
            assert stat.S_IMODE(directory.stat().st_mode) == 0o700
        assert stat.S_IMODE((data / DATABASE).stat().st_mode) == 0o600
    finally:
        # A genuine RED against hostile umask can leave mode-000 fixtures.
        # Restore only these test-owned directories so pytest can clean them.
        for directory in (data.parent, data):
            if directory.exists():
                directory.chmod(0o700)


@pytest.mark.parametrize("foreign", ["directory", "database", "wal"])
def test_foreign_owner_refusal_with_simulated_kernel_uid_only(tmp_path, foreign):
    # Unprivileged tests cannot chown. Only stat's UID is fault-injected;
    # the launcher, path traversal, Store, filesystem and pipes remain real.
    data = tmp_path / "private"
    data.mkdir(mode=0o700)
    target = data if foreign == "directory" else data / (DATABASE + ("-wal" if foreign == "wal" else ""))
    if foreign != "directory":
        target.touch(mode=0o600)
    launcher = f"""
import os
from server.desktop import main
original_stat, original_fstat = os.stat, os.fstat
identity = original_stat({str(target)!r})
def foreign(info):
    if (info.st_ino, info.st_dev) == (identity.st_ino, identity.st_dev):
        fields = list(info)
        fields[4] = os.getuid() + 1
        return os.stat_result(fields)
    return info
os.stat = lambda *a, **kw: foreign(original_stat(*a, **kw))
os.fstat = lambda *a, **kw: foreign(original_fstat(*a, **kw))
raise SystemExit(main())
"""
    result = subprocess.run([sys.executable, "-c", launcher, "--data-dir", str(data)],
                            input=frame(request("status")), capture_output=True,
                            timeout=8, cwd=ROOT, env=child_env())
    assert_startup_refused(result)


def test_database_failure_is_correlated_fixed_error_not_raw_exception(tmp_path):
    data = tmp_path / "private"
    marker = "FAKE_PRIVATE_SQLITE_ERROR"
    body = "api_key=FAKE_REJECTED_COPY_12345678"
    with sidecar(data) as client:
        assert client.send(request("status"))["ok"] is True
        with sqlite3.connect(data / DATABASE) as db:
            db.execute(f"CREATE TRIGGER reject_copy BEFORE INSERT ON events BEGIN SELECT RAISE(ABORT, '{marker}'); END")
        assert_error(client.send(request("evaluate", "failed-copy", event=event("clipboard_copy", body))),
                     "internal_error", "failed-copy")
        with sqlite3.connect(data / DATABASE) as db:
            assert db.execute("SELECT COUNT(*) FROM events").fetchone() == (0,)
            db.execute("DROP TRIGGER reject_copy")
        pasted = client.send(request("evaluate", "after-error", event=event(content=body)))["result"]["record"]
        assert pasted["decision"]["context_event_ids"] == []
        assert pasted["decision"]["action"] == "block"
        assert marker.encode() not in client.transcript
        assert body.encode() not in client.transcript
        client.send(request("shutdown"))
        assert client.process.wait(timeout=5) == 0
        assert client.process.stderr.read() == b""


def test_corrupt_database_startup_error_never_echoes_path_or_database_bytes(tmp_path):
    data = tmp_path / "FAKE_PRIVATE_DIRECTORY"
    data.mkdir(mode=0o700)
    path = data / DATABASE
    path.write_bytes(b"FAKE_INVALID_SQLITE_DATABASE_CONTENT")
    path.chmod(0o600)
    assert_startup_refused(run_sidecar(data, frame(request("status"))))


def test_recent_cannot_exceed_response_frame_limit_or_silently_truncate(tmp_path):
    data = tmp_path / "private"
    with sidecar(data) as client:
        for index in range(500):
            assert client.send(request("evaluate", f"r{index}", event=event()))["ok"] is True
        assert_error(client.send(request("recent", "too-many", limit=500)), "internal_error", "too-many")
        page = client.send(request("recent", "one", limit=1))["result"]
        assert len(page["items"]) == 1 and page["total"] == 500


def test_closed_response_pipe_exits_quietly_without_shutdown_traceback(tmp_path):
    with sidecar(tmp_path / "private") as client:
        assert client.send(request("status"))["ok"] is True
        client.process.stdout.close()
        client.process.stdin.write(frame(request("status")))
        client.process.stdin.flush()
        assert client.process.wait(timeout=5) != 0
        assert client.process.stderr.read() == b""


def test_partial_request_timeout_caller_can_terminate_and_restart_cleanly(tmp_path):
    data = tmp_path / "private"
    with sidecar(data) as client:
        assert client.send(request("status"))["ok"] is True
        client.process.stdin.write(frame(request("evaluate", event=event()))[:-1])
        client.process.stdin.flush()
        assert select.select([client.process.stdout], [], [], 0.05)[0] == []
        client.process.terminate()
        assert client.process.wait(timeout=5) != 0
        assert client.process.stdout.read() == client.process.stderr.read() == b""
    with sidecar(data) as client:
        assert client.send(request("recent", limit=1))["result"] == {"items": [], "total": 0}


# Preservation controls for already-implemented strict framing / Store behavior.
@pytest.mark.parametrize("number", ["1e999", "-1e999"])
def test_overflowing_json_number_is_not_a_finite_number(tmp_path, number):
    wire = b'{"version":' + number.encode() + b',"id":"r1","op":"status"}\n'
    result = run_sidecar(tmp_path / "private", wire)
    assert result.returncode == 0 and result.stderr == b""
    assert_error(json.loads(result.stdout))


def test_actual_utf8_content_uses_same_scalar_limit(tmp_path):
    payload = request("evaluate", event=event(content="🦉" * 4096))
    result = run_sidecar(tmp_path / "private", (json.dumps(payload, ensure_ascii=False) + "\n").encode("utf-8"))
    assert result.returncode == 0 and result.stderr == b""
    assert json.loads(result.stdout)["ok"] is True


def test_nonfinite_stored_result_never_emits_nonstandard_json(tmp_path):
    data = tmp_path / "private"
    with sidecar(data) as client:
        record = client.send(request("evaluate", event=event()))["result"]["record"]
        record["decision"]["latency_ms"] = float("nan")
        with sqlite3.connect(data / DATABASE) as db:
            db.execute("UPDATE events SET record=?", (json.dumps(record),))
        assert_error(client.send(request("recent", "nonfinite", limit=1)), "internal_error", "nonfinite")
        assert b"NaN" not in client.transcript
        assert client.send(request("status"))["ok"] is True


def test_complete_request_blocked_by_real_sqlite_lock_can_be_cancelled_by_caller(tmp_path):
    data = tmp_path / "private"
    with sidecar(data) as client:
        assert client.send(request("status"))["ok"] is True
        locked = sqlite3.connect(data / DATABASE)
        try:
            locked.execute("BEGIN IMMEDIATE")
            client.process.stdin.write(frame(request("evaluate", "blocked", event=event())))
            client.process.stdin.flush()
            assert select.select([client.process.stdout], [], [], 0.1)[0] == []
            assert client.process.poll() is None
            client.process.terminate()
            assert client.process.wait(timeout=5) != 0
            assert client.process.stdout.read() == client.process.stderr.read() == b""
        finally:
            locked.rollback()
            locked.close()
    with sidecar(data) as client:
        assert client.send(request("recent", limit=1))["result"] == {"items": [], "total": 0}
        assert client.send(request("evaluate", event=event()))["ok"] is True


def test_native_policy_catalog_accepts_every_packaged_engine_policy():
    # A new engine policy otherwise rejects startup's policies response and stops the guard.
    import re
    from pathlib import Path
    from server.models import POLICIES
    wire = (Path(__file__).resolve().parents[1] / 'desktop/macos/Sources/BoxCopCore/WireProtocol.swift').read_text()
    declaration = re.search(r'public static let known: Set<String> = \[([^\]]+)\]', wire)
    assert declaration is not None
    native_ids = set(re.findall(r'"([a-z-]+)"', declaration.group(1)))
    assert native_ids == {policy['id'] for policy in POLICIES}


def test_workflow_context_pipe_is_advisory_and_does_not_persist_private_evidence(tmp_path):
    from test_workflow_context import fixture
    context = fixture()
    launcher = '''
from server import desktop
from server.workflow_judgment import WorkflowJudge
desktop.WorkflowJudge = lambda **kwargs: WorkflowJudge(lambda packet: {}, **kwargs)
raise SystemExit(desktop.main())
'''
    with sidecar(tmp_path, launcher=launcher) as client:
        reply = client.send(request('workflow_context', context=context))
        assert reply['ok']
        assert reply['result']['workflow']['shadowOnly'] is True
        assert reply['result']['workflow']['eventCount'] == 2
        assert 'SYNTHETIC_PRIVATE_TEXT' not in json.dumps(reply)
        recent = client.send(request('recent', limit=10))
        assert recent['result']['total'] == 0
        assert client.send(request('workflow_clear'))['result'] == {'workflowCleared': True}
        invalid = dict(context, enforcement='allow')
        assert client.send(request('workflow_context', context=invalid))['error']['code'] == 'invalid_request'
        assert client.send(request('status'))['ok']
    for path in tmp_path.rglob('*'):
        if path.is_file():
            assert b'SYNTHETIC_PRIVATE_TEXT' not in path.read_bytes()


def test_holistic_review_flows_through_real_pipe_and_clear_invalidates_it(tmp_path):
    from test_workflow_context import fixture
    launcher = '''
from server import desktop
from server.workflow_judgment import WorkflowJudge

def model(packet):
    return dict(intent='Summarize a synthetic report', risk='needs_review',
        findings=[dict(summary='Requested action differs from the task', recommendation='Review the request', evidence=[packet['events'][0]['ref']])],
        uncertainties=['Tool execution is unconfirmed'])
desktop.WorkflowJudge = lambda **kwargs: WorkflowJudge(model, interval=0, **kwargs)
raise SystemExit(desktop.main())
'''
    context = fixture()
    with sidecar(tmp_path, launcher=launcher) as client:
        for _ in range(20):
            reply = client.send(request('workflow_context', context=context))
            judgment = reply['result']['workflow']['judgment']
            if judgment['state'] == 'ready': break
            time.sleep(.01)
        assert judgment['state'] == 'ready'
        assert judgment['advisoryOnly'] is True
        counts = judgment['modelUsage']['backends'][QWEN_BACKEND]
        assert counts['attempts'] == counts['ready'] == 1
        assert judgment['modelUsage']['persistence_ok'] is True
        assert judgment['result']['contextID'] == context['contextID']
        assert judgment['result']['findings'][0]['eventIDs'] == [context['events'][0]['id']]
        assert client.send(request('workflow_clear'))['ok']
        empty = fixture(0)
        cleared = client.send(request('workflow_context', context=empty))['result']['workflow']['judgment']
        assert cleared['state'] == 'insufficient_evidence'
        assert 'result' not in cleared
        assert cleared['modelUsage']['backends'][QWEN_BACKEND] == counts
        assert client.send(request('recent', limit=10))['result']['total'] == 0
    with sidecar(tmp_path, launcher=launcher) as restarted:
        persisted = restarted.send(request('status'))['result']['classification']['model_usage']
        assert persisted['backends'][QWEN_BACKEND] == counts
    for path in tmp_path.rglob('*'):
        if path.is_file():
            assert b'SYNTHETIC_PRIVATE_TEXT' not in path.read_bytes()
            assert b'Requested action differs' not in path.read_bytes()


def test_package_setup_is_async_on_existing_pipe_and_stops_with_engine(tmp_path):
    from server.package_intelligence import build_payload, datadog_records, now, sign
    from tools.package_service import provision
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    import base64
    import httpx
    import socket
    key = Ed25519PrivateKey.generate()
    home = tmp_path / 'package-home'
    home.mkdir()
    state = home / 'state'
    provision(state, sign(build_payload(list(datadog_records({'bad-pipe-fixture': ['1.0.0']}, 'npm')), 1,
                                      {'fixture': {'fetched_at': now()}}), key), key.public_key().public_bytes_raw())
    with socket.socket() as sock:
        sock.bind(('127.0.0.1', 0))
        port = sock.getsockname()[1]
    channel = dict(schema='boxcop.package-channel.v1', url='https://fixture.invalid/policy',
                   public_key=base64.b64encode(key.public_key().public_bytes_raw()).decode(), minimum_sequence=1)
    launcher = f'''
from server import package_runtime
original = package_runtime.PackageRuntime
package_runtime.refresh = lambda *_: None
package_runtime.PackageRuntime = lambda: original(home={str(home)!r}, directory={str(state)!r}, channel={channel!r}, port={port}, migrate=lambda _: None)
from server.desktop import main
raise SystemExit(main())
'''
    with sidecar(tmp_path / 'engine', launcher=launcher) as client:
        reply = client.send(request('package_protection', action='enable'))
        assert reply['ok']
        deadline = time.monotonic() + 5
        while True:
            status = client.send(request('package_protection', action='status'))['result']['packageProtection']
            if not status['busy']:
                break
            assert time.monotonic() < deadline
            time.sleep(.01)
        assert status['active']
        assert client.send(request('status'))['result']['package_registry_listener']
        with httpx.Client(trust_env=False) as browser:
            assert browser.get(f'http://127.0.0.1:{port}/npm/bad-pipe-fixture/1.0.0').status_code == 403
        assert client.send(request('shutdown'))['ok']
        client.process.wait(timeout=5)
    assert (home / '.npmrc').exists()
    with httpx.Client(trust_env=False, timeout=.2) as browser:
        with pytest.raises(httpx.ConnectError):
            browser.get(f'http://127.0.0.1:{port}/status')


def test_install_script_protection_runs_on_existing_pipe_and_stops_with_engine(tmp_path):
    import httpx
    import shutil
    import socket
    import tempfile
    # Unix socket paths are short; pytest's tmp_path is not.
    root = Path(os.path.realpath(tempfile.mkdtemp(prefix='boxcop-', dir='/tmp')))
    home, state = root / 'home', root / 'state'
    home.mkdir()
    with socket.socket() as sock:
        sock.bind(('127.0.0.1', 0))
        port = sock.getsockname()[1]
    launcher = f'''
from server import package_scripts
original = package_scripts.ScriptRuntime
package_scripts.ScriptRuntime = lambda: original(home={str(home)!r}, directory={str(state)!r}, port={port}, available=lambda: True, initiator=lambda pid: None)
from server.desktop import main
raise SystemExit(main())
'''
    try:
        with sidecar(tmp_path / 'engine', launcher=launcher) as client:
            idle = client.send(request('script_protection', action='status', package='', host=''))['result']['scriptProtection']
            assert not idle['routed'] and not idle['active'] and not (home / '.npmrc').exists()
            assert 'install_script_listener' not in client.send(request('status'))['result']
            status = client.send(request('script_protection', action='enable', package='', host=''))['result']['scriptProtection']
            assert status['active'] and status['blocked'] == []
            assert client.send(request('status'))['result']['install_script_listener']
            with httpx.Client(proxy=f'http://boxcop:unregistered@127.0.0.1:{port}', trust_env=False) as script:
                assert script.get('http://collector.example/secret').status_code == 403
            status = client.send(request('script_protection', action='allow', package='left-pad', host='downloads.example'))['result']['scriptProtection']
            assert status['exceptions'] == [{'package': 'left-pad', 'host': 'downloads.example'}]
            assert [item['host'] for item in status['blocked']] == ['collector.example']
            assert not client.send(request('script_protection', action='enable'))['ok']
            assert client.send(request('shutdown'))['ok']
            client.process.wait(timeout=5)
        # Quitting keeps routing; the proxy is gone, so contained scripts have no network.
        assert 'script-shell=' in (home / '.npmrc').read_text()
        with httpx.Client(trust_env=False, timeout=.2) as script:
            with pytest.raises(httpx.ConnectError):
                script.get(f'http://127.0.0.1:{port}/')
    finally:
        shutil.rmtree(root, ignore_errors=True)
