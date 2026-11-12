"""Explicit, user-selected software updates. Inventory itself never executes software.

Only reviewed adapters generate argv. Client input selects IDs and approves a plan
fingerprint; it never supplies executable paths, package names, or commands.
"""
import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import signal
import stat
import subprocess
import tempfile

from .software_inventory import Scan, open_root
from .exposure_advisories import findings, numeric

SCHEMA = 'boxcop.software-remediation.v1'
BREW_NAMES = {'brotli', 'cloudflared', 'node', 'ruby'}
CLEAR = {'fixed_for_advisory', 'not_applicable_architecture'}
# One CLI process owns one update. Inventory and tests leave capture disabled.
_console = None


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def needs_review(record):
    return any(a['state'] not in CLEAR for a in record['advisories'])


def installation(record):
    path = Path(record['path'])
    for prefix in ('/opt/homebrew', '/usr/local'):
        root = Path(prefix) / 'Cellar'
        if path.is_relative_to(root):
            parts = path.relative_to(root).parts
            if len(parts) in (2, 3) and (len(parts) == 2 or parts[2] == 'INSTALL_RECEIPT.json'):
                return str(root / parts[0])
    return str(path)


def items(report):
    """Offline grouping and adapter eligibility, not a promise an update exists."""
    groups = {}
    for record in report['records']:
        if needs_review(record):
            groups.setdefault(installation(record), []).append(record)
    result = []
    for location, records in sorted(groups.items()):
        first = records[0]
        name = first['name']
        adapter = 'review'
        detail = 'Review vendor guidance; no verified automatic update handler is available.'
        path = Path(location)
        if name in BREW_NAMES and any(location == f'{prefix}/Cellar/{name}' for prefix in ('/opt/homebrew', '/usr/local')):
            if any(r['kind'] == 'package_metadata' and Path(r['path']).name == 'INSTALL_RECEIPT.json' for r in records):
                adapter = 'homebrew'
                detail = 'Update this Homebrew formula. Preview includes dependency changes. Running consumers need a restart.'
                installed = [r for r in report['records'] if installation(r) == location]
                if any(fixed(r['name'], r['version']) for r in installed):
                    adapter = 'homebrew_cleanup'
                    detail = 'A fixed version is installed, but old affected copies remain. Preview removal of old versions with Homebrew.'

        elif name == 'pillow':
            # Only an exact pyenv environment; no arbitrary interpreter from metadata.
            root = Path.home() / '.pyenv/versions'
            if path.is_relative_to(root):
                parts = path.relative_to(root).parts
                if (len(parts) == 6 and re.fullmatch(r'\d+\.\d+\.\d+', parts[0])
                        and parts[1] == 'lib' and re.fullmatch(r'python\d+\.\d+', parts[2])
                        and parts[3] == 'site-packages' and parts[4].lower().startswith('pillow-')
                        and parts[4].endswith('.dist-info') and parts[5] == 'METADATA'):
                    adapter = 'pillow'
                    detail = 'Resolve a fixed Pillow wheel for this Python environment. Review compatibility before applying.'
        if name == 'node' and '/.nvm/' in location:
            detail = 'Migration needed: choose a patched release, migrate project pins and global packages, then remove unused old versions. Installing another Node does not remove this copy.'
        elif name in {'claude-browser', 'cursor-browser', 'codex-browser', 'vscode-browser'}:
            detail = 'Vendor verification needed: this advisory has no verified desktop-version cutoff. Updating alone cannot clear it.'
        elif name == 'lm-studio':
            detail = 'Use the vendor updater and relaunch. Also review unexpected plugins and previous model downloads; an update does not remove existing persistence.'
        if any(a['state'] not in CLEAR | {'affected_version', 'update_available'} for r in records for a in r['advisories']):
            adapter = 'review'
        previous = next((r for r in report.get('remediation_results', []) if r['id'] == digest(location)[:24]), None)
        state = 'cleanup_needed' if adapter == 'homebrew_cleanup' else 'update_needed' if adapter != 'review' else 'review_needed'
        key = digest(['planner-v2', [(r['id'], r['version'], r.get('metadata_sha256')) for r in sorted(records, key=lambda r: r['id'])]])
        if previous and previous.get('evidence_key') == key:
            if previous['status'] == 'migration_needed':
                adapter = 'review'
                state = 'migration_needed'
                detail = previous['detail']
            elif previous['status'] in {'failed', 'in_progress', 'unverified'} and state != 'cleanup_needed':
                state = previous['status']
        result.append(dict(id=digest(location)[:24], name=name, state=state, evidence_key=key,

                           versions=', '.join(sorted({r['version'] for r in records})),
                           location=location, adapter=adapter, detail=detail,
                           observation_ids=sorted(r['id'] for r in records)))
    return result


class UpdateError(Exception):
    def __init__(self, message, *, returncode=None, stdout='', stderr='', category='needs_review'):
        super().__init__(message)
        self.returncode = returncode
        self.category = category
        self.stdout = stdout
        self.stderr = stderr

    @property
    def diagnostics(self):
        return redact((self.stdout + '\n' + self.stderr).strip())[-6000:]


def redact(text):
    # Keep useful local diagnostics without retaining URL credentials or ANSI escapes.
    text = re.sub(r'\x1b\[[0-?]*[ -/]*[@-~]', '', text)
    text = re.sub(r'(https?://)[^/\s@]+@', r'\1[redacted]@', text)
    return re.sub(r'(?i)([?&](?:token|key|password|secret|signature|credential)[^=\s]*=)[^&\s]+', r'\1[redacted]', text)


def log_failure(argv, error):
    """Private, bounded diagnostics. Failure to log never hides the UI error."""
    from datetime import datetime, timezone
    try:
        directory = open_root(Path.home() / 'Library/Application Support/BoxCop')
        try:
            info = os.fstat(directory)
            if info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700:
                return
            fd = os.open('software-remediation.jsonl', os.O_WRONLY | os.O_APPEND | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK,
                         0o600, dir_fd=directory)
        finally:
            os.close(directory)
        with os.fdopen(fd, 'wb') as stream:
            info = os.fstat(stream.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_nlink != 1:
                return
            os.fchmod(stream.fileno(), 0o600)
            entry = json.dumps(dict(at=datetime.now(timezone.utc).isoformat(), command=[redact(a) for a in argv],
                                    exit_code=error.returncode, message=str(error), output=error.diagnostics)).encode() + b'\n'
            if info.st_size + len(entry) > 256 * 1024:
                os.ftruncate(stream.fileno(), 0)
            stream.write(entry)
    except (OSError, ValueError):
        pass


def run(argv, timeout=120):
    """Bound preparation; installs use timeout=None and retain only bounded output tails."""
    import time
    env = {'HOME': str(Path.home()), 'PATH': '/usr/bin:/bin:/usr/sbin:/sbin',
           'LANG': 'en_US.UTF-8', 'HOMEBREW_NO_AUTO_UPDATE': '1',
           'HOMEBREW_NO_INSTALL_CLEANUP': '1', 'HOMEBREW_NO_ANALYTICS': '1',
           'HOMEBREW_NO_ENV_HINTS': '1', 'PIP_DISABLE_PIP_VERSION_CHECK': '1'}
    import selectors
    if _console is not None:
        import shlex
        _console.append('\n$ ' + shlex.join(argv) + '\n')
        _console.publish(force=True)
    proc = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, env=env, cwd='/', start_new_session=True)
    deadline = None if timeout is None else time.monotonic() + timeout
    buffers = {'stdout': bytearray(), 'stderr': bytearray()}
    limit = 2 * 1024 * 1024
    selector = selectors.DefaultSelector()
    selector.register(proc.stdout, selectors.EVENT_READ, 'stdout')
    selector.register(proc.stderr, selectors.EVENT_READ, 'stderr')
    try:
        while selector.get_map() or proc.poll() is None:
            if deadline is not None and time.monotonic() > deadline:
                raise UpdateError('Updater exceeded its time or output limit. Recheck before retrying.')
            for key, _ in selector.select(.1):
                chunk = os.read(key.fileobj.fileno(), 65536)
                if not chunk:
                    selector.unregister(key.fileobj)
                    continue
                if _console is not None:
                    _console.feed(key.data, chunk)
                buffer = buffers[key.data]
                buffer.extend(chunk)
                if len(buffer) > limit:
                    if timeout is not None:
                        raise UpdateError('Updater output exceeded its limit.')
                    # Source builds may be verbose. Drain continuously, retaining a
                    # bounded tail rather than killing an otherwise healthy install.
                    del buffer[:-limit]
            if _console is not None:
                _console.publish()
        if _console is not None:
            _console.append(f'\n[Command exited with code {proc.returncode}]\n')
            _console.publish(force=True)
        value = buffers['stdout'].decode('utf-8', errors='replace')
        stderr = buffers['stderr'].decode('utf-8', errors='replace')
        if proc.returncode:
            raise UpdateError(f'Package manager exited with code {proc.returncode}. Expand command details for the reported error.',
                              returncode=proc.returncode, stdout=value, stderr=stderr)
        return value
    except UpdateError as error:
        if not error.stdout and not error.stderr:
            error.stdout = buffers['stdout'].decode('utf-8', errors='replace')
            error.stderr = buffers['stderr'].decode('utf-8', errors='replace')
        log_failure(argv, error)
        raise
    finally:
        selector.close()
        if proc.poll() is None:
            os.killpg(proc.pid, signal.SIGKILL)
            proc.wait()
        proc.stdout.close(); proc.stderr.close()


def dependency_issues(python):
    try:
        run([python, '-I', '-m', 'pip', '--isolated', 'check'])
        return set()
    except UpdateError as error:
        # pip check uses exit 1 and stdout for existing dependency problems.
        # Interpreter/pip startup failures must still stop the plan.
        if error.returncode != 1 or not error.stdout.strip():
            raise
        return set(error.stdout.strip().splitlines())


def checked_executable(path, root):
    resolved = Path(path).resolve(strict=True)
    if not resolved.is_relative_to(root) or not resolved.is_file() or not os.access(resolved, os.X_OK):
        raise UpdateError('Expected package manager or interpreter is unavailable.')
    # Homebrew commonly uses admin-group-writable directories. The user explicitly
    # selects these local managers; permission bits alone must not block updates.
    return str(resolved)


def fixed(name, version):
    rows = findings(name, version)
    return bool(rows) and all(a['state'] in CLEAR for a in rows)


def pillow_dependency_script(target):
    return '''import importlib.metadata as m, json
from pip._vendor.packaging.requirements import Requirement
from pip._vendor.packaging.utils import canonicalize_name
conflicts=[]
for d in m.distributions():
 for raw in d.requires or []:
  r=Requirement(raw)
  if canonicalize_name(r.name)=='pillow' and (r.marker is None or r.marker.evaluate({'extra': ''})) and not r.specifier.contains(%r): conflicts.append(d.metadata['Name'])
print(json.dumps(conflicts))''' % target


def prepare(item, report):
    base = dict(item)
    base.update(ready=False, target='', impact='', fingerprint='')
    if item['adapter'] == 'review':
        base['impact'] = item['detail']
        return base
    try:
        if report['incomplete']:
            raise UpdateError('Scan has coverage gaps. Resolve them and recheck before updating.')
        records = [r for r in report['records'] if r['id'] in item['observation_ids']]
        evidence = [{k: r.get(k) for k in ('id', 'version', 'metadata_sha256', 'identity')} for r in sorted(records, key=lambda r: r['id'])]
        if item['adapter'] in {'homebrew', 'homebrew_cleanup'}:
            prefix = Path(item['location']).parent.parent
            brew = checked_executable(prefix / 'bin/brew', prefix)
            info = json.loads(run([brew, 'info', '--json=v2', '--formula', item['name']]))['formulae']
            if len(info) != 1 or info[0]['name'] != item['name'] or info[0].get('tap') != 'homebrew/core':
                raise UpdateError('Only the official Homebrew formula is supported.')
            formula = info[0]
            if formula.get('pinned') or formula.get('deprecated') or formula.get('disabled'):
                raise UpdateError('Pinned or unavailable formula needs manual review.', category='migration_needed')
            if item['adapter'] == 'homebrew_cleanup':
                installed = formula.get('installed', [])
                active = formula.get('linked_keg')
                if not active or not any(r['version'] == active and fixed(item['name'], r['version'].split('_')[0]) for r in installed):
                    raise UpdateError('A fixed active Homebrew version must be verified before cleanup.')
                preview = run([brew, 'cleanup', '--dry-run', item['name']]).strip()
                if not preview:
                    raise UpdateError('Homebrew did not propose cleanup. Review old copies manually.')
                base.update(target=active, impact='Remove old installed versions for this formula. Homebrew may also remove its stale downloads. This is not reversible without reinstalling; restart old consumers first.\n' + preview)
                evidence.append(formula)
                base['ready'] = True
                base['fingerprint'] = digest({'item': {k: v for k, v in base.items() if k != 'state'}, 'evidence': evidence})
                return base
            target = formula['versions']['stable']
            if not numeric(target) or not fixed(item['name'], target):
                raise UpdateError('Homebrew does not currently offer a verified fixed release in its local catalog. Refresh Homebrew and try again.')
            current = [numeric(r['version']) for r in records]
            if any(v is None or v[0] != numeric(target)[0] for v in current) and item['name'] in {'node', 'ruby'}:
                raise UpdateError('This upgrade changes runtime major version. Review project compatibility and migrate explicitly.', category='migration_needed')
            preview = run([brew, 'upgrade', '--dry-run', '--formula', item['name']]).strip()
            if not preview:
                raise UpdateError('Homebrew did not propose an upgrade. Review retained old installations.')
            base.update(target=target, impact='Homebrew upgrade preview (dependencies may also change):\n' + preview + '\nAfter verifying a fixed active replacement, BoxCop will automatically run Homebrew cleanup for this formula if affected old copies remain. Cleanup removes old versions and may remove stale downloads; restoring them requires reinstalling. Restart affected apps or services afterward. Embedded copies are not updated.')
            if not formula.get('linked_keg') and not formula.get('keg_only'):
                base['impact'] += '\nThis formula is currently unlinked. Upgrading may link the replacement and change shell command resolution; review this before applying.'
            evidence.append(formula)
        elif item['adapter'] == 'pillow':
            parts = Path(item['location']).relative_to(Path.home() / '.pyenv/versions').parts
            environment = Path.home() / '.pyenv/versions' / parts[0]
            python = checked_executable(environment / 'bin/python3', environment)
            baseline = dependency_issues(python)
            base['existing_issues'] = sorted(baseline)
            with tempfile.TemporaryDirectory(prefix='boxcop-pillow-') as directory:
                report_path = Path(directory) / 'resolution.json'
                try:
                    run(pillow_command(python, 'Pillow>=13.0.0,<14.0.0') + ['--dry-run', '--report', str(report_path)])
                except UpdateError as error:
                    raise UpdateError('No compatible fixed Pillow wheel could be resolved for this Python. Review command details; if no matching distribution exists, migrate this environment to a newer Python.', returncode=error.returncode, stdout=error.stdout, stderr=error.stderr, category='migration_needed' if 'No matching distribution found' in error.diagnostics else 'needs_review') from error
                if report_path.stat().st_size > 1024 * 1024:
                    raise UpdateError('Package resolution report is too large.')
                resolution = json.loads(report_path.read_text())['install']
            if len(resolution) != 1 or resolution[0]['metadata']['name'].lower() != 'pillow':
                raise UpdateError('Pillow needs additional dependency changes or no update was resolved. Review this environment.')
            package = resolution[0]
            target = package['metadata']['version']
            if not numeric(target) or not fixed('pillow', target):
                raise UpdateError('No compatible verified fixed Pillow release was found.')
            url = package['download_info']['url']
            if not url.startswith('https://files.pythonhosted.org/') or not url.endswith('.whl'):
                raise UpdateError('Only official PyPI wheels are supported.')
            sha = package['download_info']['archive_info']['hashes']['sha256']
            if not re.fullmatch('[a-f0-9]{64}', sha):
                raise UpdateError('Resolved wheel has no valid SHA-256.')
            # Check installed reverse dependencies against the proposed major upgrade.
            script = pillow_dependency_script(target)
            if json.loads(run([python, '-I', '-c', script])):
                raise UpdateError('Installed packages constrain Pillow to an incompatible version. Migrate this environment first.', category='migration_needed')
            base.update(target=target, impact=f'Install Pillow {target} into {environment}. This may be a major upgrade; application behavior still needs testing. Restart Python consumers afterward.')
            if baseline:
                base['impact'] += f' This environment already has {len(baseline)} dependency issue(s); unrelated existing issues do not block this update.'
                base['diagnostics'] = redact('Existing dependency issues (before updating):\n' + '\n'.join(sorted(baseline)))[:6000]
            base['artifact'] = url + '#sha256=' + sha
            evidence.append({'wheel': url, 'sha256': sha})
        base.update(ready=True)
        base['fingerprint'] = digest({'item': {k: v for k, v in base.items() if k != 'state'}, 'evidence': evidence})
    except (UpdateError, OSError, ValueError, KeyError, TypeError) as error:
        base['impact'] = str(error) if isinstance(error, UpdateError) else 'Could not verify the update plan. Recheck the package manager and retry.'
        if isinstance(error, UpdateError):
            base['diagnostics'] = error.diagnostics
            base['blocked_status'] = error.category
    return base


def pillow_command(python, requirement):
    return [python, '-I', '-m', 'pip', '--isolated', 'install', '--disable-pip-version-check',
            '--no-input', '--index-url', 'https://pypi.org/simple', '--only-binary=:all:', '--upgrade', requirement]


def apply(item_id, fingerprint, scan=None):
    scan = scan or (lambda: Scan().run())
    report = scan()
    item = next((i for i in items(report) if i['id'] == item_id), None)
    if item is None:
        return dict(id=item_id, status='needs_review', detail='Installation changed or is no longer flagged. Recheck software.')
    plan = prepare(item, report)
    if not plan['ready'] or plan['fingerprint'] != fingerprint:
        return dict(id=item_id, status='needs_review', detail='Update plan changed or is unavailable. Preview again before applying.')
    try:
        if item['adapter'] in {'homebrew', 'homebrew_cleanup'}:
            prefix = Path(item['location']).parent.parent
            executable = checked_executable(prefix / 'bin/brew', prefix)
            command = [executable, 'cleanup', item['name']] if item['adapter'] == 'homebrew_cleanup' else [executable, 'upgrade', '--formula', item['name']]
            run(command, timeout=None)
        else:
            parts = Path(item['location']).relative_to(Path.home() / '.pyenv/versions').parts
            root = Path.home() / '.pyenv/versions' / parts[0]
            executable = checked_executable(root / 'bin/python3', root)
            run(pillow_command(executable, plan['artifact']) + ['--no-deps'], timeout=None)
            added = dependency_issues(executable) - set(plan.get('existing_issues', []))
            if added:
                raise UpdateError('Pillow updated, but new dependency issues were detected. Review this environment before using it.', stdout='\n'.join(sorted(added)))
        after = scan()
        # A disappeared record is not evidence of a fix; require positive metadata.
        matching = [r for r in after['records'] if (installation(r) == item['location'] if item['adapter'] in {'homebrew', 'homebrew_cleanup'}
                    else r['name'] == 'pillow' and Path(r['path']).parent.parent == Path(item['location']).parent.parent)]
        if not after['incomplete'] and matching and any(fixed(r['name'], r['version']) for r in matching) and any(not fixed(r['name'], r['version']) for r in matching):
            if item['adapter'] == 'homebrew':
                cleanup = next((i for i in items(after) if i['id'] == item_id and i['adapter'] == 'homebrew_cleanup'), None)
                cleanup_plan = prepare(cleanup, after) if cleanup else None
                if not cleanup_plan or not cleanup_plan['ready']:
                    return dict(id=item_id, status='cleanup_needed', detail='Upgrade succeeded, but automatic cleanup could not be verified. ' + (cleanup_plan['impact'] if cleanup_plan else 'Review retained old copies.'))
                try:
                    run([executable, 'cleanup', item['name']], timeout=None)
                except (UpdateError, OSError, ValueError) as error:
                    return dict(id=item_id, status='cleanup_needed', detail='Upgrade succeeded, but automatic old-version cleanup failed. Retry cleanup.', diagnostics=error.diagnostics if isinstance(error, UpdateError) else '')
                after = scan()
                matching = [r for r in after['records'] if installation(r) == item['location']]
                if not after['incomplete'] and matching and any(fixed(r['name'], r['version']) for r in matching) and any(not fixed(r['name'], r['version']) for r in matching):
                    return dict(id=item_id, status='cleanup_needed', detail='Upgrade succeeded, but Homebrew cleanup left affected old copies. Review retained versions.')
            else:
                return dict(id=item_id, status='cleanup_needed', detail='Cleanup left affected old copies. Review retained versions.')
        if after['incomplete'] or not matching or any(not fixed(r['name'], r['version']) for r in matching):
            return dict(id=item_id, status='unverified', detail='Updater completed, but the rescan could not verify every installed copy. Review retained versions and scan coverage.')
        return dict(id=item_id, status='restart_needed', detail='Fixed installed version verified. Restart affected apps or services; running and embedded copies remain unverified.')
    except (UpdateError, OSError, ValueError) as error:
        return dict(id=item_id, status='failed', detail=str(error) if isinstance(error, UpdateError) else 'Updater could not run. Recheck before retrying; partial changes may have occurred.', diagnostics=error.diagnostics if isinstance(error, UpdateError) else '')


def load_results():
    try:
        directory = open_root(Path.home() / 'Library/Application Support/BoxCop')
        try:
            fd = os.open('software-remediation-results.json', os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
        finally:
            os.close(directory)
        with os.fdopen(fd, 'r') as stream:
            info = os.fstat(stream.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077 or info.st_size > 2 * 1024 * 1024:
                return []
            rows = json.load(stream)
            return rows if isinstance(rows, list) and len(rows) <= 128 and all(isinstance(r, dict) and all(isinstance(r.get(k), str) for k in ('id', 'status', 'detail')) for r in rows) else []
    except (OSError, ValueError):
        return []


def save_result(result):
    from datetime import datetime, timezone
    import uuid
    row = dict(result, attempted_at=datetime.now(timezone.utc).isoformat())
    rows = [row] + [r for r in load_results() if r['id'] != row['id']]
    data = json.dumps(rows[:128]).encode()
    if len(data) > 2 * 1024 * 1024:
        raise ValueError('Result history too large')
    directory = open_root(Path.home() / 'Library/Application Support/BoxCop')
    name = '.remediation-' + uuid.uuid4().hex
    try:
        info = os.fstat(directory)
        if info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700:
            raise ValueError('Private data directory required')
        fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=directory)
        with os.fdopen(fd, 'wb') as stream:
            stream.write(data); stream.flush(); os.fsync(stream.fileno())
        os.replace(name, 'software-remediation-results.json', src_dir_fd=directory, dst_dir_fd=directory)
    finally:
        try: os.unlink(name, dir_fd=directory)
        except FileNotFoundError: pass
        os.close(directory)
    return row


def main(argv=None):
    global _console
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('operation', choices=['prepare', 'apply'])
    args = parser.parse_args(argv)
    import sys
    try:
        raw = sys.stdin.buffer.read(16385)
        if len(raw) > 16384:
            raise ValueError('Request too large')
        request = json.loads(raw)
        # Shared private lock prevents concurrent remediations from app windows/processes.
        directory = Path.home() / 'Library/Application Support/BoxCop'
        fd = open_root(directory)
        try:
            info = os.fstat(fd)
            if info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700:
                raise ValueError('Application data directory must be private and owned')
            lock = os.open('software-remediation.lock', os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600, dir_fd=fd)
        finally:
            os.close(fd)
        with os.fdopen(lock, 'w') as stream:
            info = os.fstat(stream.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_nlink != 1:
                raise ValueError('Invalid update lock')
            fcntl.flock(stream, fcntl.LOCK_EX | fcntl.LOCK_NB)
            if args.operation == 'prepare':
                ids = request['ids']
                if not isinstance(ids, list) or not 0 < len(ids) <= 128 or any(not isinstance(i, str) for i in ids):
                    raise ValueError('Invalid selection')
                report = Scan().run()
                report['remediation_results'] = load_results()
                candidates = {i['id']: i for i in items(report)}
                plans = [prepare(candidates[i], report) for i in dict.fromkeys(ids) if i in candidates]
                for plan in plans:
                    if not plan['ready'] and plan['adapter'] != 'review':
                        save_result(dict(id=plan['id'], name=plan['name'], versions=plan['versions'], evidence_key=plan['evidence_key'], status=plan.get('blocked_status', 'needs_review'), detail=plan['impact'], diagnostics=plan.get('diagnostics', '')))
                result = dict(schema=SCHEMA, plans=plans, results=load_results())
            else:
                if not re.fullmatch('[a-f0-9]{24}', request['id']) or not re.fullmatch('[a-f0-9]{64}', request['fingerprint']):
                    raise ValueError('Invalid approval')
                report = Scan().run()
                selected = next((i for i in items(report) if i['id'] == request['id']), None)
                context = {k: selected[k] for k in ('name', 'versions', 'evidence_key')} if selected else {}
                save_result(dict(id=request['id'], status='in_progress', detail='Update started; completion has not been recorded. Recheck before retrying.', **context))
                from .remediation_console import ConsoleLog
                _console = ConsoleLog(request['id'], redact)
                try:
                    outcome = apply(request['id'], request['fingerprint'])
                    _console.finish(outcome['status'], outcome['detail'])
                finally:
                    _console = None
                result = dict(schema=SCHEMA, plans=[], results=[save_result(dict(outcome, **context))])
        print(json.dumps(result))
        return 0
    except (OSError, ValueError, KeyError, TypeError):
        print(json.dumps(dict(schema=SCHEMA, plans=[], results=[], error='Update request unavailable or another update is in progress. Recheck and retry.')))
        return 1
