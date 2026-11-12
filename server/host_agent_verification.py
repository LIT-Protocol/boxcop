"""Same-user, scoped effect evidence; never an authorization or attestation boundary.

Status hashes files without executing vendor code. Only the opt-in VM acceptance
runner records evidence after checking independent effects. Historical reports
without exact bindings are deliberately ineligible.
"""
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import stat
import tempfile

CONFIGS = {'claude': '.claude/settings.json', 'codex': '.codex/hooks.json', 'cursor': '.cursor/hooks.json'}
SCOPES = {
    'credential': ('Bash', 'Shell credential-read denial and benign shell output'),
    'native_read': ('Read', 'Claude credential-file read denial and benign public read'),
    'native_write': ('Write', 'Claude credential-file creation denial and benign write'),
    'native_edit': ('Edit', 'Claude sensitive-content edit denial and benign edit'),
    'cursor_native_read': ('beforeReadFile', 'Cursor desktop native Agent read denial and benign file copy'),
    'cursor_tab_read': ('beforeTabFileRead', 'Cursor desktop Tab read denial with no canary completion and benign completion'),
}
TTL_SECONDS = 86400


def file_identity(path):
    path = Path(path).absolute()
    invoked = path.lstat()
    resolved = path.resolve(strict=True)
    fd = os.open(resolved, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as stream:
        before = os.fstat(stream.fileno())
        if not stat.S_ISREG(before.st_mode) or before.st_size > 512 * 1024 * 1024:
            raise ValueError('Not a bounded regular file')
        digest = hashlib.sha256()
        for chunk in iter(lambda: stream.read(1024 * 1024), b''):
            digest.update(chunk)
        after = os.fstat(stream.fileno())
    if ((before.st_size, before.st_mtime_ns, before.st_ctime_ns) !=
            (after.st_size, after.st_mtime_ns, after.st_ctime_ns) or path.resolve(strict=True) != resolved):
        raise ValueError('File changed during inspection')
    return {'path': str(path), 'resolved_path': str(resolved), 'sha256': digest.hexdigest(),
            'device': after.st_dev, 'inode': after.st_ino,
            'modified_ns': after.st_mtime_ns, 'changed_ns': after.st_ctime_ns,
            'invoked_inode': invoked.st_ino, 'invoked_changed_ns': invoked.st_ctime_ns}


def vendor_identity(harness, vendor, kind='cli'):
    identity = file_identity(vendor)
    if kind == 'cursor_desktop':
        if harness != 'cursor': raise ValueError('Unsupported desktop vendor')
        native = Path(identity['resolved_path']); contents = native.parent.parent
        if native.parent.name != 'MacOS' or contents.name != 'Contents' or contents.parent.suffix != '.app':
            raise ValueError('Expected desktop app executable')
        identity.update(kind=kind, info=file_identity(contents/'Info.plist'),
                        resource_seal=file_identity(contents/'_CodeSignature/CodeResources'))
        return identity
    if kind != 'cli': raise ValueError('Unsupported vendor kind')
    # Cursor ships a shell launcher alongside Node and JavaScript chunks. Binding
    # only the launcher would miss in-place runtime updates.
    if harness == 'cursor':
        root = Path(identity['resolved_path']).parent
        if not (root / 'node').is_file() or not (root / 'index.js').is_file():
            raise ValueError('Unsupported Cursor runtime layout')
        manifest = []
        for parent, dirs, files in os.walk(root, followlinks=False):
            dirs[:] = sorted(d for d in dirs if d != '.running')
            if any((Path(parent) / d).is_symlink() for d in dirs):
                raise ValueError('Unsupported runtime directory link')
            for name in sorted(files):
                if name == '.running': continue
                path = Path(parent) / name
                if not path.resolve().is_relative_to(root):
                    raise ValueError('Runtime escaped distribution directory')
                manifest.append(file_identity(path))
                if len(manifest) > 10000:
                    raise ValueError('Oversized runtime distribution')
        identity['runtime_manifest_sha256'] = hashlib.sha256(json.dumps(manifest, sort_keys=True).encode()).hexdigest()
    return identity


def binding(harness, home, executable, vendor, kind='cli'):
    executable = Path(executable)
    result = {
        'vendor': vendor_identity(harness, vendor, kind),
        'app': file_identity(executable),
        'engine': file_identity(executable.parent.parent / 'Resources/engine/boxcop-engine'),
        'configuration': file_identity(Path(home) / CONFIGS[harness]),
    }
    if kind == 'cursor_desktop':
        for key, relative in [('imported_claude_configuration', '.claude/settings.json'),
                              ('desktop_settings', 'Library/Application Support/Cursor/User/settings.json')]:
            path = Path(home)/relative
            result[key] = file_identity(path) if path.exists() or path.is_symlink() else {'path':str(path), 'present':False}
    return result


def action_for(harness, scenario):
    tool = SCOPES[scenario][0]
    if scenario.startswith('cursor_'):
        if harness != 'cursor': raise ValueError('Desktop Cursor route required')
        return tool
    if scenario.startswith('native_') and harness != 'claude':
        raise ValueError('Unsupported native route')
    return 'beforeShellExecution' if harness == 'cursor' else tool


def evidence_path(directory, harness, tool):
    return Path(directory) / f'{harness}-{tool}-verification.json'


def read_evidence(path):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_size > 65536:
            raise ValueError('Unsafe evidence')
        result = json.loads(stream.read(65537))
    if not isinstance(result, dict):
        raise ValueError('Invalid evidence')
    return result


def record(directory, report):
    """Called only after live grading; a failed rerun also supersedes older success."""
    harness, scenario = report['harness'], report['scenario']
    tool = action_for(harness, scenario)
    if report.get('sip') != 'System Integrity Protection status: enabled.' or report.get('qualification_scope') != 'scoped_vendor_route':
        raise ValueError('SIP-enabled scoped evidence required')
    if scenario.startswith('cursor_') and report['verification_binding']['vendor'].get('kind') != 'cursor_desktop':
        raise ValueError('Desktop evidence cannot inherit a CLI binding')
    evidence = {
        'schema': 1, 'harness': harness, 'tool': tool, 'scenario': scenario,
        'at': report['started_at'], 'vendor_version': report['version'],
        'binding': report['verification_binding'],
        'passed': report['status'] == 'PASS' and bool(report['checks']) and all(v is True for v in report['checks'].values()),
        'scope': SCOPES[scenario][1],
    }
    directory = Path(directory)
    info = directory.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o022:
        raise ValueError('Unsafe evidence directory')
    fd, name = tempfile.mkstemp(prefix='.verification-', dir=directory)
    try:
        with os.fdopen(fd, 'w') as stream:
            json.dump(evidence, stream); stream.flush(); os.fsync(stream.fileno())
        os.replace(name, evidence_path(directory, harness, tool))
    finally:
        if os.path.exists(name): os.unlink(name)


def verification(harness, tool, directory, home, executable, registered, callback, now=None, cache=None):
    result = {'state': 'unverified', 'scope': 'No bound effect test recorded.'}
    try:
        evidence = read_evidence(evidence_path(directory, harness, tool))
        scenario = evidence['scenario']
        if (evidence['schema'] != 1 or evidence['harness'] != harness or evidence['tool'] != tool
                or action_for(harness, scenario) != tool or not isinstance(evidence['vendor_version'], str)):
            raise ValueError('Invalid evidence identity')
        result.update(scope=SCOPES[scenario][1], tested_at=evidence['at'], vendor_version=evidence['vendor_version'])
        age = ((now or datetime.now(timezone.utc)) - datetime.fromisoformat(evidence['at'])).total_seconds()
        if evidence['passed'] is not True:
            result['state'] = 'failed'
        elif age < 0 or age > TTL_SECONDS:
            result['state'] = 'expired'
        elif not registered or callback in {'callback_error', 'callback_unavailable'}:
            result['state'] = 'invalidated'
        else:
            recorded = evidence['binding']
            vendor = recorded['vendor']['path']
            if not isinstance(vendor, str) or not Path(vendor).is_absolute():
                raise ValueError('Invalid vendor path')
            kind = recorded['vendor'].get('kind', 'cli')
            if scenario.startswith('cursor_') and kind != 'cursor_desktop':
                raise ValueError('Desktop evidence requires desktop binding')
            result['vendor_kind'] = kind
            key = (harness, vendor, kind)
            if cache is not None and key in cache:
                current = cache[key]
            else:
                current = binding(harness, home, executable, vendor, kind)
                if cache is not None: cache[key] = current
            result['state'] = 'effect_verified' if current == recorded else 'invalidated'
    except FileNotFoundError:
        if 'tested_at' in result: result['state'] = 'invalidated'
    except (OSError, ValueError, KeyError, TypeError, OverflowError):
        result['state'] = 'unavailable'
    return result
