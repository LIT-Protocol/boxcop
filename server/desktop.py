"""The BoxCop engine entry point: one-shot argv modes and the app's pipe service.

Importing this module never starts a service.
"""
import json
import math
import os
from pathlib import Path
import re
import stat
import sys

from .engine import Engine
from .store import Store
from .workflow_context import validate_context, WorkflowContextStore
from .workflow_judgment import WorkflowJudge


MAX_LINE_BYTES = 262144  # Includes the terminating LF, on both pipes.
REQUEST_ID = re.compile(r"[A-Za-z0-9_-]{1,64}")
# The app runs a second engine with this data folder name to review linked activity.
REVIEWER_DIRECTORY = "workflow-review"
ERROR_MESSAGES = {
    "invalid_request": "Invalid request.",
    "line_too_large": "Request line too large.",
    "internal_error": "Internal engine error.",
}


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
        "status": set(), "shutdown": set(), "package_protection": {"action"},
        "script_protection": {"action", "package", "host"}, "security_events": {"limit"}, "approve_command": {"event_id"},
        "workflow_context": {"context"}, "workflow_clear": set(),
    }
    if not isinstance(operation, str) or operation not in shapes:
        raise ValueError("Invalid operation")
    fields = shapes[operation]
    release = operation == "package_protection" and request.get("action") in ("allow", "revoke")
    if release:
        # Allowing or revoking names one exact release; the other actions take nothing.
        # `version` is the protocol version of every request, so the release's is `package_version`.
        fields = fields | {"ecosystem", "package", "package_version"}
    if operation == "workflow_clear" and "remove_model" in request:
        fields = fields | {"remove_model"}
        if type(request["remove_model"]) is not bool:
            raise ValueError("Invalid model removal flag")
    if set(request) != {"version", "id", "op"} | fields:
        raise ValueError("Invalid fields")
    if operation == "package_protection" and not release and request["action"] not in ("status", "enable", "disable"):
        raise ValueError("Invalid package action")
    if release:
        if request["ecosystem"] not in ("npm", "PyPI"):
            raise ValueError("Invalid ecosystem")
        if (not isinstance(request["package"], str) or not 0 < len(request["package"]) <= 214
                or not isinstance(request["package_version"], str) or not 0 < len(request["package_version"]) <= 128):
            raise ValueError("Invalid release")
    if operation == "script_protection":
        if request["action"] not in ("status", "enable", "disable", "allow", "revoke"):
            raise ValueError("Invalid install-script action")
        if any(not isinstance(request[key], str) or len(request[key]) > 255 for key in ("package", "host")):
            raise ValueError("Invalid install-script rule")
    if operation == "workflow_context":
        validate_context(request["context"])
    if operation == "approve_command" and (not isinstance(request["event_id"], str) or len(request["event_id"]) != 36):
        raise ValueError("Invalid event id")
    if operation == "security_events":
        if type(request["limit"]) is not int or not 1 <= request["limit"] <= 200:
            raise ValueError("Invalid limit")


def _package_runtime(engine):
    if not hasattr(engine, 'package_runtime'):
        from .package_runtime import PackageRuntime
        engine.package_runtime = PackageRuntime()
    return engine.package_runtime


def _script_runtime(engine):
    if not hasattr(engine, 'script_runtime'):
        from .package_scripts import ScriptRuntime
        engine.script_runtime = ScriptRuntime()
    return engine.script_runtime


def _dispatch(request, engine):
    operation = request["op"]
    if operation == "package_protection":
        return {'packageProtection': _package_runtime(engine).command(
            request['action'], *(request.get(key) for key in ('ecosystem', 'package', 'package_version')))}
    if operation == "script_protection":
        return {'scriptProtection': _script_runtime(engine).command(request['action'], request['package'], request['host'])}
    if operation == "approve_command":
        return {"commandApproved": engine.store.approve_command(request["event_id"])}
    if operation == "security_events":
        from .local_package_policy import state_directory
        from .package_scripts import state_directory as script_directory
        from .security_events import security_events
        package = getattr(engine, 'package_runtime', None)
        scripts = getattr(engine, 'script_runtime', None)
        return {"events": security_events(
            request["limit"], store=engine.store,
            package_directory=package.directory if package else state_directory(),
            script_directory=scripts.directory if scripts else script_directory())}
    if operation == "workflow_clear":
        engine.workflow_context.clear()  # Stops this engine's model runtime, if it has one.
        engine.classifier.clear()
        if not request.get("remove_model"):
            return {"workflowCleared": True}
        from .local_inference import remove_model
        freed = remove_model(getattr(engine, "model_directory", None))
        return {"workflowCleared": True, "modelRemoved": freed is not None, "freedBytes": freed or 0}
    if operation == "workflow_context":
        return {"workflow": engine.workflow_context.accept(request["context"], engine.classifier)}
    if operation == "status":
        registry = bool(getattr(getattr(engine, "package_runtime", None), "server", None))
        scripts = bool(getattr(getattr(engine, "script_runtime", None), "proxy", None))
        return {"ready": True, "protocol": 1, "engine": "rules",
                "monitoring": False, "network_listener": registry or scripts, **({"package_registry_listener": True} if registry else {}),
                **({"install_script_listener": True} if scripts else {})}
    return {"stopped": True}  # shutdown; _validate admits no other operation.


def _handle_line(line, engine):
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
        result = _dispatch(request, engine)
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
    while True:
        line = sys.stdin.buffer.readline(MAX_LINE_BYTES + 1)
        if not line:
            return 0
        if len(line) > MAX_LINE_BYTES:
            _write(_error("line_too_large"))
            return 2  # Do not drain an unbounded or unterminated hostile frame.
        response, stopped = _handle_line(line, engine)
        del line  # Do not retain request text while waiting for the next request.
        _write(response)
        if stopped:
            return 0


def main(argv=None):
    """Frozen launchers call this directly. There is no HTTP server and no implicit data path."""
    arguments = sys.argv[1:] if argv is None else argv
    if arguments[:1] == ['--package-setup']:
        from tools.package_service import management_main
        return management_main(arguments[1:])
    if arguments == ["--self-test"]:
        from .self_test import main as self_test
        return self_test()
    if arguments[:1] == ["--protection-status"]:
        from .self_test import protection_status
        return protection_status(arguments[1:])
    if arguments[:1] == ["--contain"]:
        from .containment import main as contain_main
        return contain_main(arguments[1:])
    if arguments and arguments[0] == "--software-remediation":
        from .software_remediation import main as remediation_main
        return remediation_main(arguments[1:])
    if arguments and arguments[0] == "--software-inventory":
        from .software_inventory import main as inventory_main
        return inventory_main(arguments[1:])
    if arguments and arguments[0] in {"--host-agent-hook", "--host-agent-integrations"}:
        from .host_agents import main as host_agents_main
        return host_agents_main(arguments)
    previous_mask = os.umask(0o077)
    try:
        try:
            if len(arguments) != 2 or arguments[0] != "--data-dir":
                raise ValueError("Invalid startup arguments")
            from .classifier_usage import ClassifierUsage
            store = _private_store(arguments[1])
            engine = Engine(store)
            # One model runtime: only the reviewer sidecar gets a judge. The main engine
            # keeps the default context store, which has none and can start nothing.
            if Path(arguments[1]).name == REVIEWER_DIRECTORY:
                engine.workflow_context = WorkflowContextStore(WorkflowJudge(usage=ClassifierUsage(store)))
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
            if engine.workflow_context.judge is not None:
                engine.workflow_context.judge.close()
    finally:
        os.umask(previous_mask)


if __name__ == "__main__":
    raise SystemExit(main())
