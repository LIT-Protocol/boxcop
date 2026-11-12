"""Inherited-pipe desktop policy service; importing never starts a service."""
import json
import math
import os
from pathlib import Path
import re
import stat
import sys
from uuid import uuid4

from .engine import Engine
from .classification import ContentClassifier, LocalAdvisor
from .models import EventInput
from .store import Store
from .workflow_context import validate_context, WorkflowContextStore
from .workflow_judgment import WorkflowJudge


MAX_LINE_BYTES = 262144  # Includes the terminating LF, on both pipes.
REQUEST_ID = re.compile(r"[A-Za-z0-9_-]{1,64}")
BUNDLE_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9.-]{0,254}")
ERROR_MESSAGES = {
    "invalid_request": "Invalid request.",
    "line_too_large": "Request line too large.",
    "internal_error": "Internal engine error.",
}
COPY_INTENT = "Clipboard change observed while this app was frontmost; copy origin is not verified."
PASTE_INTENT = "Paste shortcut attempted for this app; insertion and network egress are not confirmed."


def _error(code, identifier=None):
    return {"version": 1, "id": identifier, "ok": False,
            "error": {"code": code, "message": ERROR_MESSAGES[code]}}


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate key")
        result[key] = value
    return result


def _finite_float(text):
    value = float(text)
    if not math.isfinite(value):
        raise ValueError("Nonfinite number")
    return value


def _reject_constant(_value):
    raise ValueError("Nonfinite constant")


def _request_id(request):
    value = request.get("id") if isinstance(request, dict) else None
    return value if isinstance(value, str) and REQUEST_ID.fullmatch(value) else None


def _validate(request):
    if not isinstance(request, dict) or _request_id(request) is None:
        raise ValueError("Invalid envelope")
    if type(request.get("version")) is not int or request["version"] != 1:
        raise ValueError("Invalid version")
    operation = request.get("op")
    shapes = {
        "status": set(), "policies": set(), "shutdown": set(), "package_protection": {"action"},
        "script_protection": {"action", "package", "host"},
        "recent": {"limit"}, "evaluate": {"event"}, "workflow_context": {"context"}, "workflow_clear": set(),
    }
    if not isinstance(operation, str) or operation not in shapes:
        raise ValueError("Invalid operation")
    if set(request) != {"version", "id", "op"} | shapes[operation]:
        raise ValueError("Invalid fields")
    if operation == "package_protection" and request["action"] not in ("status", "enable", "disable"):
        raise ValueError("Invalid package action")
    if operation == "script_protection":
        if request["action"] not in ("status", "enable", "disable", "allow", "revoke"):
            raise ValueError("Invalid install-script action")
        if any(not isinstance(request[key], str) or len(request[key]) > 255 for key in ("package", "host")):
            raise ValueError("Invalid install-script rule")
    if operation == "workflow_context":
        validate_context(request["context"])
    if operation == "recent":
        if type(request["limit"]) is not int or not 1 <= request["limit"] <= 500:
            raise ValueError("Invalid limit")
    if operation == "evaluate":
        event = request["event"]
        if not isinstance(event, dict) or set(event) != {"kind", "content", "app_bundle_id", "app_pid", "role"}:
            raise ValueError("Invalid event fields")
        if event["kind"] not in ("clipboard_copy", "paste_attempt", "paste_prepare") or event["role"] not in ("engineering", "hr", "finance"):
            raise ValueError("Invalid event enum")
        bundle = event["app_bundle_id"]
        if not isinstance(bundle, str) or not BUNDLE_ID.fullmatch(bundle):
            raise ValueError("Invalid bundle identifier")
        if type(event["app_pid"]) is not int or event["app_pid"] <= 0:
            raise ValueError("Invalid process identifier")
        content = event["content"]
        if not isinstance(content, str) or len(content) > 4096 or any("\ud800" <= c <= "\udfff" for c in content):
            raise ValueError("Invalid Unicode scalar content")


def _dispatch(request, engine, session_id):
    operation = request["op"]
    if operation == "package_protection":
        if not hasattr(engine, 'package_runtime'):
            from .package_runtime import PackageRuntime
            engine.package_runtime = PackageRuntime()
        return {'packageProtection': engine.package_runtime.command(request['action'])}
    if operation == "script_protection":
        if not hasattr(engine, 'script_runtime'):
            from .package_scripts import ScriptRuntime
            engine.script_runtime = ScriptRuntime()
        return {'scriptProtection': engine.script_runtime.command(request['action'], request['package'], request['host'])}
    if operation == "workflow_clear":
        engine.workflow_context.clear()
        engine.classifier.clear()
        return {"workflowCleared": True}
    if operation == "workflow_context":
        workflow = engine.workflow_context.accept(request["context"], engine.classifier)
        outbox = getattr(engine, "team_outbox", None)
        if outbox is not None:
            # Queues allowlisted activity only for an active v2 enrollment; never raises.
            outbox.observe(request["context"])
        return {"workflow": workflow}
    if operation == "status":
        registry = bool(getattr(getattr(engine, "package_runtime", None), "server", None))
        scripts = bool(getattr(getattr(engine, "script_runtime", None), "proxy", None))
        return {"ready": True, "protocol": 1, "engine": "rules+sequence",
                "monitoring": False, "network_listener": registry or scripts, **({"package_registry_listener": True} if registry else {}),
                **({"install_script_listener": True} if scripts else {}), "classification": engine.classifier.stats()}
    if operation == "policies":
        return {"items": engine.store.policies()}
    if operation == "recent":
        return engine.store.list_events(limit=request["limit"], desktop_only=True)
    if operation == "shutdown":
        return {"stopped": True}
    event = request["event"]
    copied = event["kind"] == "clipboard_copy"
    bundle = event["app_bundle_id"]
    record = engine.evaluate(EventInput(
        session_id=session_id, actor="human", role=event["role"],
        action="copy" if copied else "paste", app=bundle,
        source="app://" + bundle if copied else "",
        destination="" if copied else "app://" + bundle,
        content=event["content"], declared_intent=COPY_INTENT if copied else ("Prospective paste policy prepared; no shortcut or transfer observed." if event["kind"] == "paste_prepare" else PASTE_INTENT),
        synthetic=False,
    ), retain_preview=False)
    return {"record": record.model_dump(mode="json")}


def _handle_line(line, engine, session_id):
    identifier = None
    try:
        if not line.endswith(b"\n"):
            raise ValueError("Incomplete frame")
        request = json.loads(line.decode("utf-8"), object_pairs_hook=_unique_object,
                             parse_constant=_reject_constant, parse_float=_finite_float)
        identifier = _request_id(request)
        _validate(request)
    except (ValueError, RecursionError):
        return _error("invalid_request", identifier), False
    try:
        result = _dispatch(request, engine, session_id)
    except Exception:
        # Neither validation details nor underlying SQLite/engine messages are safe.
        return _error("internal_error", identifier), False
    return {"version": 1, "id": identifier, "ok": True, "result": result}, request["op"] == "shutdown"


def _write(response):
    try:
        wire = (json.dumps(response, ensure_ascii=True, allow_nan=False, separators=(",", ":")) + "\n").encode("utf-8")
        if len(wire) > MAX_LINE_BYTES:
            raise ValueError("Response exceeds frame bound")
    except (ValueError, TypeError, RecursionError):
        wire = (json.dumps(_error("internal_error", response["id"]), separators=(",", ":")) + "\n").encode("ascii")
    # Unbuffered writes cannot leave sensitive diagnostics or a second flush
    # traceback behind when the owning app closes its pipe. Handle short writes.
    remaining = memoryview(wire)
    while remaining:
        written = os.write(sys.stdout.fileno(), remaining)
        if written <= 0:
            raise OSError("Response pipe closed")
        remaining = remaining[written:]


def _check_directory(info, *, final=False):
    mode = stat.S_IMODE(info.st_mode)
    if not stat.S_ISDIR(info.st_mode):
        raise ValueError("Not a directory")
    if final:
        if info.st_uid != os.getuid() or mode != 0o700:
            raise ValueError("Data directory is not private and owned")
    elif info.st_uid not in (0, os.getuid()) or (
        mode & 0o022 and not (info.st_uid == 0 and mode & stat.S_ISVTX)
    ):
        raise ValueError("Untrusted parent directory")


def _check_database_files(directory_fd):
    for suffix in ("", "-wal", "-shm", "-journal"):
        for _ in range(3):
            try:
                info = os.stat("events.sqlite3" + suffix, dir_fd=directory_fd, follow_symlinks=False)
            except FileNotFoundError:
                break
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
                    or stat.S_IMODE(info.st_mode) != 0o600):
                raise ValueError("Unsafe database file")
            if info.st_nlink == 1:
                break
            # SQLite removes companion files when its last connection closes.
            # A concurrent stat can return the now-unlinked inode. Recheck the
            # path so a replacement must still pass every safety check.
            if not suffix or info.st_nlink != 0:
                raise ValueError("Unsafe database file")
        else:
            raise ValueError("Unstable database file")


def _private_store(raw_path, *, timeout=10):
    path = Path(raw_path)
    if not path.is_absolute() or path.anchor != "/" or len(path.parts) < 2 or ".." in path.parts:
        raise ValueError("An absolute private data directory is required")
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    directory_fd = os.open("/", flags)
    try:
        _check_directory(os.fstat(directory_fd))
        for index, part in enumerate(path.parts[1:], 1):
            try:
                os.mkdir(part, mode=0o700, dir_fd=directory_fd)
            except FileExistsError:
                pass
            next_fd = os.open(part, flags, dir_fd=directory_fd)
            os.close(directory_fd)
            directory_fd = next_fd
            _check_directory(os.fstat(directory_fd), final=index == len(path.parts) - 1)
        # Refuse links, devices, foreign owners and public files BEFORE Store's
        # chmod/open or SQLite's WAL recovery can affect another file.
        _check_database_files(directory_fd)
        try:
            fd = os.open("events.sqlite3", os.O_CREAT | os.O_EXCL | os.O_RDWR | os.O_NOFOLLOW,
                         0o600, dir_fd=directory_fd)
        except FileExistsError:
            pass
        else:
            os.close(fd)
        _check_database_files(directory_fd)
        store = Store(path / "events.sqlite3", timeout=timeout)
        _check_database_files(directory_fd)
        return store
    finally:
        os.close(directory_fd)


def _serve(engine):
    session_id = str(uuid4())
    while True:
        line = sys.stdin.buffer.readline(MAX_LINE_BYTES + 1)
        if not line:
            return 0
        if len(line) > MAX_LINE_BYTES:
            _write(_error("line_too_large"))
            return 2  # Do not drain an unbounded or unterminated hostile frame.
        response, stopped = _handle_line(line, engine, session_id)
        del line  # Do not retain clipboard text while waiting for the next request.
        _write(response)
        if stopped:
            return 0


class _CorrectionStartup(BaseException):
    """Bounds the advisory correction entry's import; ordinary handlers cannot catch it."""


def _correction(arguments):
    """Opt-in advisory end-of-turn entry. The deadline is armed before the import,
    and every failure, including an import failure, prints {} and exits 0."""
    import signal
    import time
    started = time.monotonic()

    def expired(*_):
        raise _CorrectionStartup()
    try:
        try:
            signal.signal(signal.SIGALRM, expired)
            signal.setitimer(signal.ITIMER_REAL, 3)
            from .agent_corrections import main as corrections_main
            return corrections_main(arguments, started=started)
        finally:
            signal.setitimer(signal.ITIMER_REAL, 0)
    except BaseException:
        print("{}")
        return 0


def main(argv=None):
    """Frozen launchers call this directly; no HTTP server or implicit data path."""
    arguments = sys.argv[1:] if argv is None else argv
    if arguments[:1] == ['--human-review']:
        from .human_review import main as review_main
        return review_main(arguments[1:])
    if arguments[:1] == ['--package-setup']:
        from tools.package_service import management_main
        return management_main(arguments[1:])
    if arguments[:1] == ['--package-protection']:
        from .package_proxy import main as package_main
        return package_main(arguments[1:])
    if arguments == ["--classifier-self-test"]:
        from .classification import self_test
        return self_test()
    if arguments and arguments[0] == "--reviewed-transfer":
        from .reviewed_transfer import main as transfer_main
        return transfer_main(arguments[1:])
    if arguments and arguments[0] == "--provider-integrations":
        from .provider_cli import main as provider_main
        return provider_main(arguments[1:])
    if arguments and arguments[0] == "--software-remediation":
        from .software_remediation import main as remediation_main
        return remediation_main(arguments[1:])
    if arguments and arguments[0] == "--software-inventory":
        from .software_inventory import main as inventory_main
        return inventory_main(arguments[1:])
    if arguments and arguments[0] in {"--host-agent-hook", "--host-agent-integrations"}:
        from .host_agents import main as host_agents_main
        return host_agents_main(arguments)
    if arguments and arguments[0] == "--host-agent-correction":
        return _correction(arguments)
    if arguments and arguments[0] == "--agent-corrections":
        from .agent_corrections import main as corrections_main
        return corrections_main(arguments)
    if arguments and arguments[0] == "--team-desktop":
        from .team.desktop import main as team_desktop
        return team_desktop(arguments[1:])
    if arguments and arguments[0] == "--team-reporting":
        # Explicitly invoked company-managed reporting; never started by the pipe service.
        from .team.reporter import main as team_main
        return team_main(arguments[1:])
    previous_mask = os.umask(0o077)
    try:
        try:
            args = sys.argv[1:] if argv is None else argv
            if len(args) != 2 or args[0] != "--data-dir":
                raise ValueError("Invalid startup arguments")
            from .classifier_usage import ClassifierUsage
            store = _private_store(args[1])
            usage = ClassifierUsage(store)
            engine = Engine(store, classifier=ContentClassifier(LocalAdvisor(usage)))
            from .team.activity import ActivityOutbox, team_reporting_root
            # Enrollment lives in the main data directory, even for the dedicated reviewer engine.
            engine.team_outbox = ActivityOutbox(team_reporting_root(args[1]))
            engine.workflow_context = WorkflowContextStore(WorkflowJudge(usage=usage, on_result=engine.team_outbox.observe_review))
        except Exception:
            sys.stderr.write("BoxCop engine could not start.\n")
            return 2
        try:
            return _serve(engine)
        except (OSError, KeyboardInterrupt):
            return 1
        finally:
            if hasattr(engine, 'package_runtime'):
                engine.package_runtime.close()
            if hasattr(engine, 'script_runtime'):
                engine.script_runtime.close()
            engine.classifier.close()
            engine.workflow_context.judge.close()
    finally:
        os.umask(previous_mask)


if __name__ == "__main__":
    raise SystemExit(main())
