"""Pre-action hooks for coding agents, and their reversible user-level registration.

The agent's harness calls the hook before a shell command or file action and
honors its answer. These cooperative hooks are not an OS sandbox and do not
authenticate the agent.
"""
from datetime import datetime, timezone
import fcntl
import hashlib
import json
import os
from pathlib import Path
import shlex
import signal
import stat
import sys
import tempfile
import time

from server.host_agent_verification import verification

CURSOR_READ_EVENTS = ('beforeReadFile', 'beforeTabFileRead')
MAX_BYTES = 65536
MARKER = '--host-agent-hook'
CONFIGS = {'claude': '.claude/settings.json', 'codex': '.codex/hooks.json', 'cursor': '.cursor/hooks.json'}
# Fixed keys bound receipt cardinality and prevent untrusted tool names becoming paths.
ACTIONS = {
    'claude': {'Bash': 'PreToolUse', 'Read': 'PreToolUse', 'Write': 'PreToolUse', 'Edit': 'PreToolUse'},
    'codex': {'Bash': 'PreToolUse'},
    'cursor': {event: event for event in ('beforeShellExecution', *CURSOR_READ_EVENTS)},
}
MESSAGE = 'BoxCop blocked this action. Revise it to avoid sensitive data or unsafe execution, then submit the revised action. Do not retry through a different tool.'


def unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('duplicate key')
        result[key] = value
    return result


def read_object(path):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as f:
        info = os.fstat(f.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_nlink != 1:
            raise ValueError('unsafe file')
        raw = f.read(1024 * 1024 + 1)
    if len(raw) > 1024 * 1024:
        raise ValueError('oversized configuration')
    value = json.loads(raw, object_pairs_hook=unique)
    if not isinstance(value, dict):
        raise ValueError('object required')
    return value, raw


def atomic(path, value):
    data = (json.dumps(value, indent=2, ensure_ascii=True) + '\n').encode()
    fd, temporary = tempfile.mkstemp(prefix='.boxcop-', dir=path.parent)
    try:
        with os.fdopen(fd, 'wb') as f:
            f.write(data); f.flush(); os.fsync(f.fileno())
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def private_directory(path):
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    st = path.lstat()
    if not stat.S_ISDIR(st.st_mode) or st.st_uid != os.getuid() or st.st_mode & 0o077:
        raise ValueError('unsafe private directory')


def response(harness, allowed, explanation=None):
    message = explanation or MESSAGE
    if harness == 'cursor':
        return {'permission': 'allow'} if allowed else {'permission': 'deny', 'user_message': message, 'agent_message': message}
    return {} if allowed else {'hookSpecificOutput': {'hookEventName': 'PreToolUse', 'permissionDecision': 'deny', 'permissionDecisionReason': message}}


def normalize(harness, payload):
    if not isinstance(payload, dict):
        raise ValueError('object required')
    cursor_read = harness == 'cursor' and payload.get('hook_event_name') in CURSOR_READ_EVENTS
    native = cursor_read or (harness == 'claude' and payload.get('tool_name') in {'Read', 'Write', 'Edit'})
    destination = 'local-shell'
    action = 'command'
    if native:
        if not cursor_read and payload.get('hook_event_name') != 'PreToolUse':
            raise ValueError('unsupported hook')
        fields = payload if cursor_read else payload.get('tool_input')
        cwd = payload.get('cwd', '') if cursor_read else payload.get('cwd')
        if not isinstance(fields, dict) or not isinstance(cwd, str) or (not cursor_read and not Path(cwd).is_absolute()):
            raise ValueError('invalid native input')
        path = fields.get('file_path')
        # Resolve existing symlinks without reading file bytes. This is a
        # preflight snapshot, not race-free filesystem authorization.
        destination = native_path(path, cwd, require_absolute=cursor_read)
        if len(destination) > 1000:
            raise ValueError('oversized resolved path')
        action = 'read' if cursor_read or payload['tool_name'] == 'Read' else 'write'
        command = '' if action == 'read' else fields.get('content' if payload['tool_name'] == 'Write' else 'new_string')
        if harness == 'claude' and action == 'read':
            from .skill_security import instruction_path, read_text
            if instruction_path(destination) or instruction_path(path):
                command = read_text(destination)
        if cursor_read:
            command = fields.get('content')
            attachments = fields.get('attachments', [])
            if not isinstance(attachments, list) or len(attachments) > 32:
                raise ValueError('invalid attachments')
            from .commands import _credential_path
            for attachment in attachments:
                if not isinstance(attachment, dict) or attachment.get('type') not in {'file', 'rule'}:
                    raise ValueError('invalid attachment')
                attached_path = native_path(attachment.get('file_path'), '', require_absolute=True)
                if _credential_path(attached_path, include_dotenv=True):
                    destination = attached_path

        session = payload.get('conversation_id' if cursor_read else 'session_id', 'unknown')
        intent = ''
    elif harness == 'cursor':
        if payload.get('hook_event_name') not in (None, 'beforeShellExecution'):
            raise ValueError('unsupported hook')
        command = payload.get('command')
        session = payload.get('conversation_id', 'unknown')
        intent = ''
    else:
        if payload.get('hook_event_name') != 'PreToolUse' or payload.get('tool_name') != 'Bash':
            raise ValueError('unsupported hook')
        fields = payload.get('tool_input')
        if not isinstance(fields, dict):
            raise ValueError('tool input')
        command = fields.get('command')
        intent = fields.get('description') or ''
        session = payload.get('session_id', 'unknown')
    cwd = payload.get('cwd', '')
    for value, bound in [(command, 20000), (session, 4096), (intent, 1024), (cwd, 1000)]:
        if not isinstance(value, str) or len(value) > bound or any(0xD800 <= ord(c) <= 0xDFFF for c in value):
            raise ValueError('invalid text')
    if not command and not native:
        raise ValueError('empty command')
    if not native:
        command = resolved_shell_paths(command, cwd)
    return {'session_id': harness + '-' + hashlib.sha256(session.encode()).hexdigest()[:32],
            'action': action, 'app': harness,
            'source': ('reported-native-hook' if native else 'reported-shell-hook') + (':' + cwd if cwd else ''), 'destination': destination,
            'content': command, 'declared_intent': ''}


def native_path(path, cwd, *, require_absolute=False):
    """Preserve sensitive lexical names as well as existing symlink targets."""
    from .commands import _credential_path
    if not isinstance(path, str) or not path or len(path) > 1000 or '\x00' in path:
        raise ValueError('invalid file path')
    if require_absolute and not Path(path).is_absolute():
        raise ValueError('absolute file path required')
    target = Path(path).expanduser()
    target = target if target.is_absolute() else Path(cwd) / target
    resolved = str(target.resolve())
    if len(resolved) > 1000:
        raise ValueError('oversized resolved path')
    return str(target) if _credential_path(str(target), include_dotenv=True) else resolved


def resolved_shell_paths(command, cwd):
    """Add bounded credential-path evidence for existing shell argument symlinks.

    No file bytes or scripts are read. Shell expansion, races and dynamically
    constructed paths still require OS containment, not this preflight snapshot.
    """
    from .commands import _credential_path, IDENTITY_FLAGS
    if not cwd or not Path(cwd).is_absolute():
        return command
    try:
        words = shlex.split(command)
    except ValueError:
        return command  # Original command still goes through deterministic rules.
    evidence = []
    skip = False
    for word in words[:128]:
        if skip:
            skip = False
            continue
        if word.lower() in IDENTITY_FLAGS:
            skip = True
            continue
        if word.startswith('--data-binary=') or word.startswith('--post-file='):
            word = word.split('=', 1)[1]
        if word.startswith('-'):
            continue
        word = word.removeprefix('@')
        if not word or len(word) > 1000 or '://' in word or '\x00' in word:
            continue
        path = Path(word).expanduser()
        try:
            resolved = (path if path.is_absolute() else Path(cwd)/path).resolve(strict=True)
            if _credential_path(str(resolved), include_dotenv=True):
                evidence.append(shlex.quote(str(resolved)))
        except (OSError, RuntimeError, ValueError):
            continue
        if len(evidence) == 8:
            break
    return command + ('\n' + ' '.join(evidence) if evidence else '')


def callback_tool(harness, payload):
    """Identify only supported reported actions; this is not vendor authentication."""
    if not isinstance(payload, dict):
        return None
    if harness == 'cursor':
        tool = payload.get('hook_event_name')
        if tool is None:
            tool = 'beforeShellExecution'
    else:
        if payload.get('hook_event_name') != 'PreToolUse':
            return None
        tool = payload.get('tool_name')
    return tool if isinstance(tool, str) and tool in ACTIONS[harness] else None


def receipt(directory, harness, state, *, tool=None, **fields):
    # One last receipt per supported action plus the backward-compatible harness
    # receipt. No payload, file path or arbitrary tool name is persisted here.
    value = {'schema_version': 1, 'harness': harness,
             'state': state, 'at': datetime.now(timezone.utc).isoformat(), **fields}
    if tool in ACTIONS[harness]:
        value['tool'] = tool
        atomic(directory / (harness + '-' + tool + '-receipt.json'), value)
    atomic(directory / (harness + '-receipt.json'), value)


def cursor_imported_event(payload):
    """Cursor imports Claude registrations but sends its own preToolUse envelope.

    This is reported compatibility metadata, not authenticated vendor identity.
    Keep imported callbacks out of both Claude action receipts and Cursor's native
    event receipts: a generic imported preflight does not prove either was called.
    """
    if (not isinstance(payload, dict) or payload.get('hook_event_name') != 'preToolUse'
            or not isinstance(payload.get('cursor_version'), str)):
        raise ValueError('Invalid imported hook envelope')
    fields = payload.get('tool_input')
    if not isinstance(fields, dict):
        raise ValueError('Invalid imported tool input')
    tool = {'Shell': 'Bash', 'Bash': 'Bash', 'Read': 'Read', 'Write': 'Write', 'Edit': 'Edit'}.get(payload.get('tool_name'))
    if tool is None:
        raise ValueError('Unsupported imported tool')
    cwd = payload.get('cwd') or fields.get('working_directory')
    if not cwd:
        roots = payload.get('workspace_roots')
        if not isinstance(roots, list) or len(roots) != 1:
            raise ValueError('Ambiguous imported workspace')
        cwd = roots[0]
    if not isinstance(cwd, str) or not Path(cwd).is_absolute():
        raise ValueError('Invalid imported workspace')
    converted = {**payload, 'hook_event_name': 'PreToolUse', 'tool_name': tool, 'cwd': cwd,
                 'session_id': payload.get('conversation_id', payload.get('session_id', 'unknown'))}
    event = normalize('claude', converted)
    event['app'] = 'cursor'
    event['session_id'] = 'cursor-imported-' + hashlib.sha256(str(converted['session_id']).encode()).hexdigest()[:32]
    event['source'] = 'reported-imported-hook:' + cwd
    return event


def hook(harness, directory):
    allowed = False
    explanation = 'BoxCop could not evaluate this action. Retry after checking BoxCop and its local audit storage. The action was not run.'
    started = time.monotonic()
    tool = None
    receipt_harness = harness
    def expired(*_):
        raise TimeoutError('deadline')
    signal.signal(signal.SIGALRM, expired)
    signal.setitimer(signal.ITIMER_REAL, 3)
    try:
        from .desktop import _private_store
        from .engine import Engine
        from .models import EventInput
        from .classification import ContentClassifier
        raw = sys.stdin.buffer.read(MAX_BYTES + 1)
        if len(raw) > MAX_BYTES:
            raise ValueError('oversized')
        payload = json.loads(raw, object_pairs_hook=unique)
        imported = (harness == 'claude' and isinstance(payload, dict)
                    and payload.get('hook_event_name') == 'preToolUse'
                    and isinstance(payload.get('cursor_version'), str))
        if imported:
            receipt_harness = 'cursor'
            event = cursor_imported_event(payload)
        else:
            tool = callback_tool(harness, payload)
            event = normalize(harness, payload)
        # Deterministic rules only: no model downloads, inference or network calls.
        # SQLite's normal 10s busy wait exceeds vendor hook deadlines. A busy or
        # unavailable audit must produce an explicit deny before the harness times out.
        # Allow brief writer contention between callbacks within the 3s deadline.
        engine = Engine(_private_store(str(directory), timeout=1), classifier=ContentClassifier())
        record = engine.evaluate(EventInput(**event))
        allowed = record.decision.action == 'allow'
        if not allowed:
            explanation = ' '.join(record.decision.reasons) + ' ' + MESSAGE + ' Reference: ' + record.id
        receipt(directory, receipt_harness, 'observed', tool=tool, decision=record.decision.action,
                record_id=record.id, session_id=event['session_id'],
                elapsed_ms=round((time.monotonic() - started) * 1000, 3))
    except Exception:
        allowed = False
        try:
            receipt(directory, receipt_harness, 'error', tool=tool, decision='deny', elapsed_ms=round((time.monotonic() - started) * 1000, 3))
        except Exception:
            pass
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
    print(json.dumps(response(harness, allowed, explanation)))
    return 0


def registration(harness, executable):
    command = shlex.join([str(executable), MARKER, harness])
    if harness == 'cursor':
        return 'beforeShellExecution', {'command': command, 'timeout': 5, 'failClosed': True}
    return 'PreToolUse', {'matcher': '^(Bash|Read|Write|Edit)$' if harness == 'claude' else '^Bash$', 'hooks': [{'type': 'command', 'command': command, 'timeout': 5}]}


def registered_commands(group, harness):
    if not isinstance(group, dict):
        return []
    handlers = [group] if harness == 'cursor' else group.get('hooks', [])
    return [h.get('command') for h in handlers if isinstance(h, dict) and isinstance(h.get('command'), str)]


COVERAGE = {
    'claude': 'Shell commands and Read/Write/Edit file actions',
    'codex': 'Shell commands only; native file and MCP actions are not covered',
    'cursor': 'Shell commands and Agent/Tab file reads',
}


def callback_state(last, configured_at, now=None):
    """Check time before using either a successful or failed callback as recent."""
    try:
        observed = datetime.fromisoformat(last['at'])
        age = ((now or datetime.now(timezone.utc)) - observed).total_seconds()
        if age < 0 or age > 86400:
            return 'callback_stale'
        if observed.timestamp() < configured_at:
            return 'callback_before_configuration'
    except (KeyError, TypeError, ValueError, OverflowError):
        return 'callback_stale'
    return 'callback_observed' if last.get('state') == 'observed' else 'callback_error'


def action_details(harness, directory, row, configured_at):
    details = {}
    for tool, event in ACTIONS[harness].items():
        registered = row.get('registered_events', {}).get(event, False)
        state = 'configured_not_observed' if registered else row['state']
        last = None
        path = directory / (harness + '-' + tool + '-receipt.json')
        if registered:
            try:
                last = read_object(path)[0]
                if (last.get('schema_version') != 1 or last.get('harness') != harness
                        or last.get('tool') != tool or last.get('state') not in ('observed', 'error')):
                    raise ValueError('invalid callback identity')
                state = callback_state(last, configured_at)
            except FileNotFoundError:
                pass
            except (OSError, ValueError):
                last = None
                state = 'callback_unavailable'
        if registered:
            try:
                failure = read_object(directory / (harness + '-supervisor-receipt.json'))[0]
                if (failure.get('schema_version') != 1 or failure.get('harness') != harness
                        or failure.get('state') != 'error' or failure.get('source') != 'native_supervisor'):
                    raise ValueError('Invalid supervisor evidence')
                if (callback_state(failure, configured_at) == 'callback_error'
                        and (not last or datetime.fromisoformat(failure['at']) > datetime.fromisoformat(last['at']))):
                    state = 'callback_error'
            except FileNotFoundError:
                pass
            except (OSError, ValueError, KeyError, TypeError):
                state = 'callback_unavailable'
        details[tool] = {'registered': registered, 'state': state,
                         'last_callback': last, 'enforcement': 'unverified'}
    return details


def connection_details(harness, row, now=None):
    """Describe evidence, never infer enforcement from registration or silence."""
    now = now or datetime.now(timezone.utc)
    state = row['state']
    last = row.get('last_callback') or {}
    if state in {'callback_observed', 'callback_error'}:
        state = callback_state(last, 0, now)
        row['state'] = state
    guidance = {
        'not_detected': 'No supported configuration directory found. Open the tool once, then install hooks.',
        'not_configured': 'Install or repair hooks.',
        'disable_setting_unverified': 'Cannot verify that Cursor honors disableAllHooks; existing hooks may still run. Use Remove BoxCop agent hooks to opt out. Settings were preserved.',
        'disabled_by_harness': 'Hooks are disabled in the tool settings. Review those settings before reconnecting.',
        'configuration_conflict': 'Configuration could not be read safely. Repair its format or permissions; existing settings were preserved.',
        'configured_not_observed': 'Perform a harmless action in the tool to check callback delivery. Restart the tool if no callback appears.',
        'callback_before_configuration': 'Configuration changed since the last callback. Check a fresh action.',
        'callback_stale': 'No recent callback evidence (within 24 hours). Run a harmless action in a fresh session and recheck.',
        'callback_error': 'The last callback could not evaluate an action. Check the installed app and local audit storage.',
        'callback_unavailable': 'Callback evidence could not be read safely. Recheck after a fresh harmless action.',
        'callback_observed': 'A callback reached BoxCop recently. This does not verify every tool event or prove the tool honored a denial.',
    }
    for detail in row.get('actions', {}).values():
        detail['next_step'] = guidance.get(detail['state'], 'Recheck the integration.')
    row['coverage'] = COVERAGE[harness]
    row['next_step'] = guidance.get(state, 'Recheck the integration.')
    if harness == 'codex':
        row['next_step'] += ' Review and trust BoxCop in /hooks before starting a fresh session.'
    row['compatibility'] = 'Effect evidence applies only to the recorded CLI binary and tested action; updates require a fresh effect test.'
    return row


def integrations(mode, home, directory, executable):
    """Merge only owned entries; never overwrite malformed config or disable other hooks.

    An explicit remove persists an opt-out; automatic startup respects it. No hook
    trust databases or harness permission settings are edited.
    """
    private_directory(directory)
    state_path = directory / 'agent-integrations.json'
    lock_fd = os.open(directory / 'agent-integrations.lock', os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    with os.fdopen(lock_fd, 'w') as lock:
        fcntl.flock(lock.fileno(), fcntl.LOCK_EX)
        previous = read_object(state_path)[0] if state_path.exists() else {}
        if mode == 'auto' and previous.get('disabled'):
            return {'summary': 'Agent hooks: removed by user; automatic registration paused.', 'disabled': True}
        result = {'schema_version': 1, 'disabled': mode == 'remove', 'harnesses': {}}
        for harness, relative in CONFIGS.items():
            path = home / relative
            event_name, entry = registration(harness, executable)
            entries = {event_name: entry}
            if harness == 'cursor':
                entries.update({event: dict(entry) for event in CURSOR_READ_EVENTS})
            try:
                parent = path.parent.lstat()
                if not stat.S_ISDIR(parent.st_mode) or parent.st_uid != os.getuid() or parent.st_mode & 0o022:
                    raise ValueError('unsafe config directory')
                config, original = read_object(path) if path.exists() or path.is_symlink() else ({}, None)
                disable_uncertain = harness == 'cursor' and config.get('disableAllHooks') is True
                read_only = mode == 'status' or (disable_uncertain and mode != 'remove')
                if config.get('disableAllHooks') is True and harness != 'cursor' and mode != 'remove':
                    result['harnesses'][harness] = {'state': 'disabled_by_harness'}
                    continue
                hooks = config.setdefault('hooks', {})
                if not isinstance(hooks, dict):
                    raise ValueError('unsupported config shape')
                owned = previous.get('harnesses', {}).get(harness, {}).get('command')
                current = registered_commands(entry, harness)[0]
                owned_commands = {c for c in (owned, current) if isinstance(c, str)}
                coverage = {}
                for event_name, entry in entries.items():
                    groups = hooks.get(event_name, [])
                    if not isinstance(groups, list):
                        raise ValueError('unsupported config shape')
                    # Require the complete registration, including matcher and failure policy.
                    coverage[event_name] = entry in groups
                    filtered = []
                    for group in groups:
                        if not isinstance(group, dict):
                            raise ValueError('unsupported hook group')
                        if harness == 'cursor':
                            if group.get('command') not in owned_commands:
                                filtered.append(group)
                        else:
                            if not isinstance(group.get('hooks', []), list):
                                raise ValueError('unsupported hook group')
                            kept = [h for h in group.get('hooks', []) if not isinstance(h, dict) or h.get('command') not in owned_commands]
                            if kept or not group.get('hooks'):
                                filtered.append({**group, 'hooks': kept} if group.get('hooks') else group)
                    if not read_only:
                        hooks[event_name] = filtered + ([] if mode == 'remove' else [entry])
                        coverage[event_name] = mode != 'remove'
                present = all(coverage.values())
                if not read_only:
                    if harness == 'cursor':
                        config.setdefault('version', 1)
                    encoded = (json.dumps(config, indent=2, ensure_ascii=True) + '\n').encode()
                    if encoded != original:
                        if original is not None:
                            backup = directory / (harness + '-' + hashlib.sha256(original).hexdigest()[:16] + '.config-backup.json')
                            if not backup.exists():
                                # Private exact backup, never printed or committed.
                                fd = os.open(backup, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
                                with os.fdopen(fd, 'wb') as f:
                                    f.write(original); f.flush(); os.fsync(f.fileno())
                        # Refuse concurrent edits instead of silently overwriting them.
                        if (read_object(path)[1] if path.exists() or path.is_symlink() else None) != original:
                            raise ValueError('config changed during install')
                        atomic(path, config)
                    present = mode != 'remove'
                state = 'configured_not_observed' if present else 'not_configured'
                last = None
                rp = directory / (harness + '-receipt.json')
                if present:
                    try:
                        last = read_object(rp)[0]
                        if (last.get('schema_version') != 1 or last.get('harness') != harness
                                or last.get('state') not in ('observed', 'error')):
                            raise ValueError('invalid callback identity')
                        state = callback_state(last, path.stat().st_mtime)
                    except FileNotFoundError:
                        pass
                    except (OSError, ValueError):
                        last = None
                        state = 'callback_unavailable'
                result['harnesses'][harness] = {'state': state, 'command': current, 'last_callback': last,
                    'requires_harness_trust': harness == 'codex', 'registered_events': coverage}
                result['harnesses'][harness]['actions'] = action_details(
                    harness, directory, result['harnesses'][harness], path.stat().st_mtime if path.exists() else 0)
                if disable_uncertain and mode != 'remove':
                    result['harnesses'][harness]['state'] = 'disable_setting_unverified'
            except FileNotFoundError:
                result['harnesses'][harness] = {'state': 'not_detected'}
            except Exception:
                result['harnesses'][harness] = {'state': 'configuration_conflict'}
        verification_cache = {}
        for harness, row in result['harnesses'].items():
            if 'actions' not in row:
                row['actions'] = action_details(harness, directory, row, 0)
            for tool, detail in row['actions'].items():
                detail['verification'] = verification(harness, tool, directory, home, executable,
                    detail['registered'], detail['state'], cache=verification_cache)
                detail['enforcement'] = detail['verification']['state']
            connection_details(harness, row)
        result['summary'] = 'Agent action hooks: ' + ' · '.join(k + ' ' + v['state'].replace('_', ' ') for k, v in result['harnesses'].items())
        if result['harnesses'].get('codex', {}).get('state') == 'configured_not_observed':
            result['summary'] += '. Codex: review BoxCop in /hooks, then start a new session.'
        result['summary'] += ' Observed callbacks are historical, not a guarantee of current coverage.'
        if mode != 'status':
            atomic(state_path, result)
        return result


def main(args):
    # Called by the bundled desktop entry point, with an explicit trusted data path.
    if len(args) == 4 and args[0] == '--host-agent-hook' and args[1] in CONFIGS and args[2] == '--data-dir':
        return hook(args[1], Path(args[3]))
    if len(args) == 8 and args[0] == '--host-agent-integrations' and args[1] in {'auto', 'install', 'status', 'remove'} and args[2] == '--home' and args[4] == '--data-dir' and args[6] == '--executable':
        try:
            print(json.dumps(integrations(args[1], Path(args[3]), Path(args[5]), Path(args[7]))))
            return 0
        except Exception:
            print(json.dumps({'summary': 'Agent hooks: configuration unavailable; no protection claim.'}))
            return 1
    return 2
