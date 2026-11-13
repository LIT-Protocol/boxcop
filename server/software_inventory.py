"""Bounded offline inventory, automatic defaults and explicit-root test support.

Descriptor-relative traversal never follows symlinks (including root ancestors).
Only metadata is parsed; no package, interpreter, helper or installer is executed.
"""
import argparse
from datetime import datetime, timezone
from email.parser import BytesHeaderParser
import hashlib
import json
import os
from pathlib import Path
import plistlib
import re
import stat
import time
import uuid
import zipfile
import zlib
import xml.etree.ElementTree as ET
from xml.parsers.expat import ExpatError

from .exposure_advisories import findings, REVIEWED_AT
from .supply_chain import assess
from . import inventory_metadata, deployment_metadata
import yaml
from .feed_advisories import PACKAGES, NAMES as FEED_NAMES, REVIEWED_AT as FEED_REVIEWED_AT
from .november_advisories import REVIEWED_AT as NOVEMBER_REVIEWED_AT

APP_IDS = {'com.google.Chrome':'chrome', 'org.mozilla.firefox':'firefox',
           'com.teamviewer.TeamViewer':'teamviewer', 'com.teamviewer.TeamViewerHost':'teamviewer',
           'io.tailscale.ipn.macos':'tailscale', 'io.tailscale.ipn.macsys':'tailscale',
           'org.electrum.electrum':'electrum', 'ai.elementlabs.lmstudio':'lm-studio',
           'com.cloudflare.1dot1dot1dot1.macos':'cloudflare-warp',
           'com.todesktop.230313mzl4w4u92':'cursor-browser', 'com.microsoft.VSCode':'vscode-browser',
           'com.anthropic.claudefordesktop':'claude-browser', 'com.openai.codex':'codex-browser'}
FLAGS = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC
MAX_RECORDS = 128
REVIEWED_NAMES = {"php","node","nodejs","brotli","pillow","ruby","wasmtime","wasmtime-cli","electrum","litellm","@subql/common","tailscale","headscale","teamviewer"}


def parse_plist(data):
    """Accept stray XML control characters tolerated by macOS, in memory only.

    Always try the original bytes first, including binary/other-encoding plists.
    The fallback is limited to UTF-8 XML and preserves legal XML whitespace.
    Callers retain the original bytes for metadata digests and identity.
    """
    try:
        return plistlib.loads(data)
    except ExpatError:
        text = data.decode('utf-8-sig')
        if not text.lstrip().startswith(('<?xml', '<plist')):
            raise
        cleaned = re.sub(r'[\x00-\x08\x0b\x0c\x0e-\x1f]', '', text)
        if cleaned == text:
            raise
        return plistlib.loads(cleaned.encode('utf-8'))


def defaults(home=None):
    home = Path.home() if home is None else Path(home)
    return [Path('/Applications'), home/'Applications', Path('/opt/homebrew/Cellar'), Path('/usr/local/Cellar'),
            home/'.pyenv/versions', home/'.local/share/uv/python', home/'.asdf/installs',
            home/'.local/share/mise/installs', home/'.nvm/versions/node', home/'.rbenv/versions',
            home/'Library/Python', home/'.wasmtime', Path('/Library/PrivilegedHelperTools'), Path('/Library/LaunchDaemons'),
            Path('/opt/homebrew/Caskroom'), Path('/usr/local/Caskroom')]


def open_root(path):
    if not path.is_absolute() or '..' in path.parts: raise ValueError('Absolute root required')
    fd = os.open('/', FLAGS | os.O_DIRECTORY)
    try:
        for part in path.parts[1:]:
            child = os.open(part, FLAGS | os.O_DIRECTORY, dir_fd=fd)
            os.close(fd); fd = child
        return fd
    except BaseException:
        os.close(fd)
        raise


class Scan:
    def __init__(self, *, max_entries=300000, max_seconds=5, max_bytes=16*1024*1024):
        self.entries = self.bytes = 0
        self.max_entries, self.max_bytes = max_entries, max_bytes
        self.started = time.monotonic()
        self.deadline = self.started + max_seconds
        self.records, self.roots, self.issues = [], [], []
        self.limitations, self.issue_details = [], []
        self.issue_count = 0
        self.root_entries = 0
        self.root_entry_limit = max_entries
        self.incomplete = False
        self.seen = set()

    def issue(self, reason, path=None):
        self.incomplete = True
        self.issue_count += 1
        if reason not in self.issues: self.issues.append(reason)
        if path is not None and len(self.issue_details) < 64:
            self.issue_details.append(dict(reason=reason, path=str(path)))

    def limitation(self, reason):
        if reason not in self.limitations: self.limitations.append(reason)

    def available(self):
        if self.entries - self.root_entries >= self.root_entry_limit:
            self.issue('root_entry_limit', self.roots[-1]['path'] if self.roots else None); return False
        if self.entries >= self.max_entries or self.bytes >= self.max_bytes or time.monotonic() >= self.deadline or len(self.records) >= MAX_RECORDS:
            self.issue('scan_limit_reached'); return False
        return True

    def read(self, fd, name, *, max_size=262144):
        child = os.open(name, FLAGS, dir_fd=fd)
        try:
            before = os.fstat(child)
            if not stat.S_ISREG(before.st_mode) or before.st_size > max_size: raise ValueError('not bounded regular metadata')
            data = bytearray()
            while len(data) <= max_size:
                if not self.available(): raise ValueError('scan bound')
                chunk = os.read(child, min(65536, max_size+1-len(data)))
                if not chunk: break
                data.extend(chunk); self.bytes += len(chunk)
            after = os.fstat(child)
            if len(data) > max_size or (before.st_dev,before.st_ino,before.st_size,before.st_mtime_ns,before.st_ctime_ns) != (after.st_dev,after.st_ino,after.st_size,after.st_mtime_ns,after.st_ctime_ns):
                raise ValueError('metadata changed')
            return bytes(data), after
        finally: os.close(child)

    def record(self, name, version, path, kind, data=b'', info=None, channel='unknown'):
        if not isinstance(name,str) or not isinstance(version,str) or not name or len(name)>128 or len(version)>128:
            self.issue('invalid_metadata'); return
        # Composer's installed.json describes several packages in one physical file.
        key = str(path) + ('#' + name if kind in {'composer_metadata', 'maven_archive_metadata'} else '')
        declaration = kind in {'deployment_image_declaration', 'go_module_declaration', 'source_release_metadata'}
        if declaration: key = str(path) + '#' + name + '@' + version
        if key in self.seen: return
        if len(self.records) >= MAX_RECORDS: self.issue('record_limit'); return
        self.seen.add(key)
        # We do not infer binary architecture from the host (Rosetta/embedded binaries).
        rows = findings(name, version, architecture='unknown', channel=channel)
        if declaration:
            for row in rows:
                row['declared_version_state'] = row['state']
                if row['state'] == 'fixed_for_advisory': row['state'] = 'unresolved'
                row['prerequisites'] += ' This is a local declaration/source tree, not verified installed or running code; fixed declarations remain unresolved until deployment is verified.'
        finding = assess(name, version)
        self.records.append(dict(id=hashlib.sha256(key.encode()).hexdigest()[:24],name=name,version=version or 'unknown',path=str(path),
            kind=kind,metadata_sha256=hashlib.sha256(data).hexdigest() if data else None,
            identity={'device':info.st_dev,'inode':info.st_ino,'size':info.st_size,'mtime_ns':info.st_mtime_ns,'owner_uid':info.st_uid} if info else None,
            trust='metadata_only',architecture='unknown',channel=channel,
            finding=finding.__dict__ if finding else None, assessment='review_required' if any(r['state'] not in {'fixed_for_advisory','not_applicable_architecture'} for r in rows) else 'no_snapshot_match',
            advisories=rows, running_state='unknown', embedded_dependencies='not_fully_enumerated', configuration='unknown',
            remediation='Review the advisory, update through the software vendor, then restart/rebuild consumers. No executable policy was changed.'))

    def package(self, package, version, ecosystem, path, data, info):
        if not isinstance(package, str) or not isinstance(version, str):
            self.issue('invalid_metadata'); return
        normalized = re.sub(r'[-_.]+', '-', package.lower()) if ecosystem == 'python' else package.lower()
        if normalized in FEED_NAMES:
            if normalized not in PACKAGES[ecosystem]: return
            if not version: self.issue('missing_package_version', path)
            if ecosystem == 'composer' and re.fullmatch(r'v[0-9]+\.[0-9]+\.[0-9]+', version):
                version = version[1:]
            channel = 'lts' if normalized == 'jenkins-lts' else 'weekly' if normalized == 'jenkins' else 'unknown'
            self.record(normalized, version, path,
                        'composer_metadata' if ecosystem == 'composer' else 'package_metadata',
                        data, info, channel=channel)
        elif ecosystem != 'composer' and re.sub(r'[-_.]+', '-', package.lower()) in REVIEWED_NAMES:
            self.record(package, version, path, 'package_metadata', data, info)

    def composer(self, data, info, path):
        # Composer 1 uses a list, Composer 2 a packages object. Never load installed.php,
        # execute autoloaders, or equate composer.lock's desired versions with installs.
        row = json.loads(data)
        packages = row.get('packages') if isinstance(row, dict) else row
        if not isinstance(packages, list) or len(packages) > 2000:
            raise ValueError('invalid Composer package list')
        names = set()
        for package in packages:
            if not isinstance(package, dict) or not isinstance(package.get('name'), str):
                raise ValueError('invalid Composer package')
            name = package['name'].lower()
            if name in names: raise ValueError('duplicate Composer package')
            names.add(name)
        for package in packages:
            if not self.available(): return
            self.entries += 1
            self.package(package['name'], package.get('version', ''), 'composer', path, data, info)

    def app(self, fd, path):
        contents = os.open('Contents', FLAGS | os.O_DIRECTORY, dir_fd=fd)
        try:
            data, info = self.read(contents, 'Info.plist')
            row = parse_plist(data)
            name = APP_IDS.get(row.get('CFBundleIdentifier'))
            # Display names alone do not identify the abandoned fork.
            if name:
                self.record(name, row.get('CFBundleShortVersionString',''), path/'Contents/Info.plist', 'app_bundle', data, info)
            elif 'popcorn' in path.name.lower():
                self.record('time4popcorn', row.get('CFBundleShortVersionString',''), path/'Contents/Info.plist', 'app_identity_candidate', data, info)
        finally: os.close(contents)

    def child_mode(self, mode, name):
        # Automatic inventory follows installation layouts, not arbitrary payloads.
        if mode == 'apps': return 'apps'
        if mode == 'caskroom': return 'cask' if name == 'clickhouse' else None
        if mode == 'cask': return 'metadata' if name == '.metadata' else None
        if mode == 'cellar': return 'formula'
        if mode == 'formula': return 'runtime'
        if mode == 'versions': return 'runtime'
        if mode == 'managers': return 'versions'
        if mode == 'wasmtime': return 'metadata' if name == 'bin' else None
        if mode == 'runtime':
            if name in {'lib', 'lib64', 'Lib', 'Frameworks', 'Python.framework', 'Versions'} or re.fullmatch(r'python[0-9.]+|[0-9]+\.[0-9]+', name): return 'runtime'
            if name in {'site-packages', 'dist-packages'}: return 'python_packages'
            if name == 'node_modules': return 'npm_packages'
        if mode == 'python_packages' and name.endswith('.dist-info'): return 'metadata'
        if mode == 'npm_packages': return 'npm_scope' if name.startswith('@') else 'npm_package'
        if mode == 'npm_scope': return 'npm_package'
        if mode == 'npm_package' and name == 'node_modules': return 'npm_packages'
        return None

    def walk(self, fd, path, depth=0, mode=None):
        if depth > (64 if mode else 10): self.issue('depth_limit', path); return
        # scandir streams entries; never build an unbounded list from a hostile directory.
        with os.scandir(fd) as entries:
            for entry in entries:
                if not self.available(): return
                self.entries += 1
                name, item = entry.name, path/entry.name
                try:
                    if entry.is_symlink():
                        if mode: self.limitation('Symbolic links are excluded; linked installations are not checked.')
                        else: self.issue('symlinks_skipped', item)
                        continue
                    if entry.is_dir(follow_symlinks=False):
                        next_mode = self.child_mode(mode, name) if mode else None
                        if mode and next_mode is None: continue
                        child = os.open(name, FLAGS | os.O_DIRECTORY, dir_fd=fd)
                        try:
                            # Version-manager directories are hints, never executable identity.
                            runtime = 'node' if path.name == 'node' else 'ruby' if 'rbenv' in str(path) else path.name
                            if runtime in {'node','ruby','php'} and re.fullmatch(r'v?[0-9]+\.[0-9]+\.[0-9]+', name):
                                self.record(runtime,name.removeprefix('v'),item,'version_directory_hint')
                            if name.endswith('.app'):
                                try:
                                    self.app(child, item)  # App contents are not recursively crawled.
                                except FileNotFoundError:
                                    if not mode: raise
                                    self.limitation('App bundles without standard Contents/Info.plist metadata are excluded.')
                            else: self.walk(child, item, depth+1, next_mode)
                        finally: os.close(child)
                        continue
                    if name == 'PT.updd' and path.name == 'PrivilegedHelperTools':
                        info = entry.stat(follow_symlinks=False)
                        if stat.S_ISREG(info.st_mode): self.record('time4popcorn-helper', '', item, 'privileged_helper_candidate', info=info)
                        else: self.issue('invalid_helper_type')
                        continue
                    if name == 'PT.updd.plist' and path.name == 'LaunchDaemons':
                        data, info = self.read(fd,name); row = parse_plist(data)
                        if not isinstance(row,dict): raise ValueError('invalid launch daemon')
                        # Parse only to prove it is a plist. Do not execute its Program/arguments.
                        self.record('time4popcorn-helper', '', item, 'launch_daemon_candidate', data, info)
                        continue
                    if not mode and deployment_metadata.inspect(self, fd, path, name): continue
                    if inventory_metadata.inspect(self, fd, path, name): continue
                    if name == 'installed.json' and path.name == 'composer' and path.parent.name == 'vendor':
                        data, info = self.read(fd, name)
                        self.composer(data, info, item)
                        continue
                    if name not in {'METADATA','package.json','INSTALL_RECEIPT.json','wasmtime'}: continue
                    if mode and name == 'package.json':
                        package_hint = (path.parent.name + '/' if path.parent.name.startswith('@') else '') + path.name
                        if package_hint not in REVIEWED_NAMES | PACKAGES['npm']: continue
                    if name == 'wasmtime':
                        info = entry.stat(follow_symlinks=False)
                        if stat.S_ISREG(info.st_mode): self.record('wasmtime','',item,'unversioned_executable',info=info)
                        continue
                    if name == 'METADATA' and not path.name.endswith('.dist-info'): continue
                    data, info = self.read(fd,name)
                    if name == 'METADATA':
                        row = BytesHeaderParser().parsebytes(data)
                        package, version = row.get('Name',''), row.get('Version','')
                        ecosystem = 'python'
                    elif name == 'package.json':
                        row = json.loads(data); package, version = row.get('name',''),row.get('version','')
                        if package == 'goahead':
                            if row.get('repository') == 'git://github.com/embedthis/goahead.git' and row.get('homepage') == 'https://embedthis.com/goahead/':
                                self.record('goahead', version, item, 'source_release_metadata', data, info)
                            continue
                        ecosystem = 'npm'
                    else:
                        row = json.loads(data); package = path.parent.name.split('@')[0]
                        version = row.get('source',{}).get('versions',{}).get('stable','')
                        ecosystem = 'homebrew'
                        if package in PACKAGES['homebrew']:
                            # A HEAD build or custom tap is not the reviewed stable artifact.
                            source = row.get('source', {})
                            if source.get('spec') != 'stable' or source.get('tap') != 'homebrew/core':
                                version = 'unverified-build'
                    self.package(package, version, ecosystem, item, data, info)
                except (OSError, ValueError, UnicodeError, TypeError, AttributeError, plistlib.InvalidFileException, ExpatError, RecursionError, ET.ParseError, yaml.YAMLError, zipfile.BadZipFile, NotImplementedError, RuntimeError, EOFError, zlib.error):
                    self.issue('unreadable_or_invalid_metadata', item)

    def run(self, roots=None):
        automatic = roots is None
        if automatic:
            roots = defaults()
            self.limitation('Automatic checks cover supported app metadata, Homebrew receipts, runtime versions and installed Python/npm package metadata. Source trees, embedded libraries and nonstandard layouts are excluded.')
        modes = ['apps', 'apps', 'cellar', 'cellar', 'versions', 'versions', 'managers', 'managers', 'versions', 'versions', 'runtime', 'wasmtime', 'helpers', 'helpers', 'caskroom', 'caskroom']
        for index, root in enumerate(roots[:32]):
            # Reserve a share for every root so a large installation cannot starve later roots.
            self.root_entries = self.entries
            self.root_entry_limit = max(1, (self.max_entries - self.entries) - min(1000, self.max_entries // max(1, len(roots[:32]))) * (len(roots[:32]) - index - 1))
            issue_start = self.issue_count
            root = Path(root).absolute()
            item = dict(path=str(root),state='scanned')
            self.roots.append(item)
            if not self.available(): item['state']='not_scanned'; continue
            try:
                fd = open_root(root)
                try:
                    self.walk(fd,root,mode=modes[index] if automatic else None)
                    if self.issue_count > issue_start:
                        item['state'] = 'partial'
                finally: os.close(fd)
            except FileNotFoundError: item['state']='absent'
            except (OSError,ValueError): item['state']='unavailable'; self.issue('root_unavailable', root)
        if len(roots)>32: self.issue('root_limit')
        now = datetime.now(timezone.utc)
        return dict(schema='boxcop.software-inventory.v2', generated_at=now.isoformat(), reviewed_at=max(REVIEWED_AT, FEED_REVIEWED_AT, NOVEMBER_REVIEWED_AT),
                    freshness_seconds=600, incomplete=self.incomplete, issues=self.issues, roots=self.roots,
                    limitations=self.limitations, issue_details=self.issue_details,
                    elapsed_ms=round((time.monotonic()-self.started)*1000,2), scanned_entries=self.entries, metadata_bytes=self.bytes,
                    trust='Metadata observations only; no match is not proof of safety. No package code was executed.',
                    coverage='Selected app, runtime/package and helper roots only. Running code, embedded libraries and configuration are not fully enumerated.',
                    records=self.records)


def save_report(report, directory):
    """Atomic private cache in an existing owned app directory; never follows links."""
    fd = open_root(Path(directory))
    name = '.inventory-' + uuid.uuid4().hex
    try:
        info = os.fstat(fd)
        if info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700:
            raise ValueError('Cache directory must be private and owned')
        data = json.dumps(report, separators=(',',':')).encode()
        if len(data)>2*1024*1024: raise ValueError('Report too large')
        out = os.open(name, os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW, 0o600, dir_fd=fd)
        with os.fdopen(out,'wb') as stream:
            stream.write(data); stream.flush(); os.fsync(stream.fileno())
        os.replace(name,'software-inventory.json',src_dir_fd=fd,dst_dir_fd=fd)
    finally:
        try: os.unlink(name,dir_fd=fd)
        except FileNotFoundError: pass
        os.close(fd)


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--root',action='append',type=Path)
    p.add_argument('--cache',action='store_true',help='Save a private report in the existing BoxCop app data directory')
    p.add_argument('--format', choices=('inventory', 'findings', 'agent'), default='inventory',
                   help='Full inventory, actionable findings JSON, or a repair prompt')
    args = p.parse_args(argv)
    report = Scan().run(args.root)
    from .software_remediation import items, load_results
    report['remediation_results'] = load_results()
    report['remediation_items'] = items(report)
    if args.cache:
        report['cache_status'] = 'saved'
        try: save_report(report,Path.home()/'Library/Application Support/BoxCop')
        except (OSError,ValueError): report['cache_status'] = 'unavailable'
    if args.format == 'inventory':
        print(json.dumps(report, separators=(',',':')))
    else:
        from .software_findings import findings_report, agent_prompt
        evidence = findings_report(report)
        print(agent_prompt(evidence) if args.format == 'agent' else json.dumps(evidence, separators=(',', ':')))
    return 0

if __name__ == '__main__': raise SystemExit(main())
