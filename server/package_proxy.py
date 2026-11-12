"""Opt-in, loopback-only, read-only public npm/PyPI registry firewall.

Only authenticated artifact links issued from upstream metadata can download.
It is not a transparent system-wide interceptor: existing caches, direct URLs,
private registries and lockfiles pointing elsewhere remain outside this boundary.
"""
import argparse
import base64
import hashlib
import hmac
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import threading
from urllib.parse import quote, unquote, urlsplit

import httpx
from packaging.utils import parse_wheel_filename, parse_sdist_filename

from .package_intelligence import (MAX_BYTES, PolicyStore, canonical,
                                   package_name, version)

METADATA_LIMIT = 32 * 1024 * 1024
ARTIFACT_LIMIT = 1024 * 1024 * 1024


class Upstream:
    """Fixed HTTPS origins; no credentials, environment proxies or redirects."""
    def __init__(self):
        self.client = httpx.Client(timeout=60, follow_redirects=False, trust_env=False)

    def metadata(self, url):
        with self.client.stream('GET', url, headers={'Accept': 'application/vnd.pypi.simple.v1+json' if 'pypi.org' in url else 'application/json'}) as response:
            response.raise_for_status()
            data = bytearray()
            for chunk in response.iter_bytes():
                data.extend(chunk)
                if len(data) > METADATA_LIMIT:
                    raise ValueError('Registry metadata exceeds limit')
            return json.loads(data)


def artifact_url(ecosystem, url):
    parts = urlsplit(url)
    expected = 'registry.npmjs.org' if ecosystem == 'npm' else 'files.pythonhosted.org'
    if parts.scheme != 'https' or parts.netloc != expected or parts.username or parts.query:
        raise ValueError('Unsupported artifact origin')
    if not parts.path.startswith('/') or '\\' in url or any(part == '..' for part in unquote(parts.path).split('/')):
        raise ValueError('Invalid artifact path')
    # Fragment hashes are metadata, not part of the HTTPS request.
    return parts._replace(fragment='').geturl()


class Firewall:
    def __init__(self, store, secret, upstream=None):
        self.store, self.secret = store, secret
        self.upstream = upstream or Upstream()
        self.blocks = 0

    def verdict(self, ecosystem, name, candidate):
        policy = self.store.policy
        return policy.assess(ecosystem, name, candidate) if policy else {'decision': 'unknown', 'reports': []}

    def link(self, base, ecosystem, name, candidate, url):
        name = package_name(ecosystem, name)
        version(ecosystem, candidate)
        data = canonical(dict(ecosystem=ecosystem, name=name, version=candidate, url=artifact_url(ecosystem, url)))
        encoded = base64.urlsafe_b64encode(data).decode().rstrip('=')
        signature = hmac.new(self.secret, data, hashlib.sha256).hexdigest()
        # Keep the actual filename suffix: pip uses it to identify wheels/sdists.
        filename = quote(unquote(urlsplit(url).path.rsplit('/', 1)[-1]), safe='')
        return f'{base}/artifacts/{encoded}/{signature}/{filename}'

    def resolve(self, path):
        parts = path.split('/')
        if len(parts) != 5 or parts[1] != 'artifacts':
            raise ValueError('Invalid artifact link')
        data = base64.b64decode(parts[2] + '=' * (-len(parts[2]) % 4), altchars=b'-_', validate=True)
        if not hmac.compare_digest(hmac.new(self.secret, data, hashlib.sha256).hexdigest(), parts[3]):
            raise ValueError('Invalid artifact signature')
        item = json.loads(data)
        artifact_url(item['ecosystem'], item['url'])
        expected = quote(unquote(urlsplit(item['url']).path.rsplit('/', 1)[-1]), safe='')
        if parts[4] != expected:
            raise ValueError('Artifact filename mismatch')
        return item

    def npm(self, path, base, *, pnpm_client=False):
        # Supports packuments and exact/tag endpoints; never forwards arbitrary
        # registry API paths (publishing, login, audit, search, etc.).
        prefix = '/pnpm/' if path.startswith('/pnpm/') else '/npm/'
        pnpm = prefix == '/pnpm/' or pnpm_client
        decoded = unquote(path.removeprefix(prefix))
        parts = decoded.split('/')
        length = 2 if decoded.startswith('@') else 1
        name = '/'.join(parts[:length])
        package_name('npm', name)
        if len(parts) > length + 1:
            raise ValueError('Unsupported registry path')
        requested = parts[length] if len(parts) > length else None
        if requested:
            # Exact-version requests can be refused before even fetching metadata.
            if self.verdict('npm', name, requested)['decision'] == 'block':
                raise Blocked(self.verdict('npm', name, requested))
        metadata = self.upstream.metadata('https://registry.npmjs.org/' + quote(name, safe=''))
        if metadata['name'] != name:
            raise ValueError('Package identity mismatch')
        clean, blocked = {}, {}
        for candidate, manifest in metadata['versions'].items():
            if manifest.get('name') != name or manifest.get('version') != candidate:
                raise ValueError('Version identity mismatch')
            verdict = self.verdict('npm', name, candidate)
            if verdict['decision'] == 'block':
                blocked[candidate] = verdict
                continue
            manifest = dict(manifest, dist=dict(manifest['dist']))
            # npm's native registry-host replacement routes these URLs to this
            # listener at download time. Preserve public URLs in lockfiles.
            manifest['dist']['tarball'] = artifact_url('npm', manifest['dist']['tarball'])
            if pnpm:
                # pnpm omits its standard registry tarball URL from the lockfile,
                # but unlike npm does not reroute explicit public tarball URLs.
                manifest['dist']['tarball'] = base + prefix.rstrip('/') + urlsplit(manifest['dist']['tarball']).path
            clean[candidate] = manifest
        tags = metadata.get('dist-tags', {})
        if requested:
            selected = tags.get(requested, requested)
            if selected in blocked:
                raise Blocked(blocked[selected])
            if selected not in clean:
                raise Missing()
            return clean[selected]
        if not clean and blocked:
            raise Blocked(next(iter(blocked.values())))
        return dict(metadata, versions=clean, **{'dist-tags': {tag: candidate for tag, candidate in tags.items() if candidate in clean}})

    def npm_artifact(self, path):
        """Bind canonical tarball paths to current registry metadata, not a
        caller-supplied package/version. This also works for existing lockfiles.
        """
        path = path.removeprefix('/npm') if path.startswith('/npm/') else path.removeprefix('/pnpm') if path.startswith('/pnpm/') else path
        decoded = unquote(path)
        if decoded.count('/-/') != 1:
            raise ValueError('Invalid npm artifact path')
        name, filename = decoded[1:].split('/-/')
        package_name('npm', name)
        if not filename or '/' in filename or not filename.endswith('.tgz'):
            raise ValueError('Invalid npm artifact filename')
        metadata = self.upstream.metadata('https://registry.npmjs.org/' + quote(name, safe=''))
        if metadata['name'] != name:
            raise ValueError('Package identity mismatch')
        candidates = []
        for candidate, manifest in metadata['versions'].items():
            url = artifact_url('npm', manifest['dist']['tarball'])
            if unquote(urlsplit(url).path) == decoded:
                if manifest.get('name') != name or manifest.get('version') != candidate:
                    raise ValueError('Version identity mismatch')
                candidates.append(dict(ecosystem='npm', name=name, version=candidate, url=url))
        if not candidates:
            raise Missing()
        for item in candidates:
            verdict = self.verdict('npm', name, item['version'])
            if verdict['decision'] == 'block':
                raise Blocked(verdict)
        if len(candidates) != 1:
            raise ValueError('Ambiguous artifact identity')
        return candidates[0]

    def pypi(self, path, base):
        name = package_name('PyPI', unquote(path.removeprefix('/pypi/simple/').rstrip('/')))
        metadata = self.upstream.metadata('https://pypi.org/simple/' + quote(name, safe='') + '/')
        if package_name('PyPI', metadata['name']) != name:
            raise ValueError('Package identity mismatch')
        files, blocked = [], []
        for item in metadata['files']:
            filename = item['filename']
            try:
                parsed = parse_wheel_filename(filename) if filename.endswith('.whl') else parse_sdist_filename(filename)
            except ValueError as error:
                # Do not silently expose an artifact whose version is unresolved.
                raise ValueError('Unsupported Python distribution filename') from error
            if str(parsed[0]) != name:
                raise ValueError('Distribution name mismatch')
            candidate = str(parsed[1])
            verdict = self.verdict('PyPI', name, candidate)
            if verdict['decision'] == 'block':
                blocked.append(verdict)
                continue
            rewritten = {key: item[key] for key in ('filename', 'hashes', 'requires-python', 'yanked', 'size', 'upload-time') if key in item}
            rewritten['url'] = self.link(base, 'PyPI', name, candidate, item['url'])
            # PEP 658 sidecars are deliberately not advertised: append-only
            # .metadata URLs would otherwise bypass authenticated artifact links.
            files.append(rewritten)
        if not files and blocked:
            raise Blocked(blocked[0])
        return {'meta': {'api-version': '1.0'}, 'name': name, 'files': files}


class Blocked(Exception):
    def __init__(self, verdict):
        self.verdict = verdict


class Missing(Exception):
    pass


class Handler(BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.0'

    def log_message(self, *_):
        pass  # No dependency names, URLs, tokens or credentials in access logs.

    def setup(self):
        super().setup()
        self.connection.settimeout(30)

    def respond(self, status, value, content_type='application/json'):
        body = canonical(value)
        self.send_response(status)
        self.send_header('Content-Type', content_type)
        self.send_header('Content-Length', str(len(body)))
        self.send_header('Cache-Control', 'no-store')
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.end_headers()
        if self.command != 'HEAD':
            self.wfile.write(body)

    def do_HEAD(self):
        self.do_GET()

    def do_GET(self):
        expected = f'127.0.0.1:{self.server.server_port}'
        if (self.headers.get('Host') != expected or self.headers.get('Origin') or
                self.headers.get('Authorization') or self.headers.get('Cookie') or
                self.headers.get('Transfer-Encoding') or self.headers.get('Content-Length') not in (None, '0')):
            self.respond(400, {'error': 'Only credential-free local registry requests are supported'})
            return
        if len(self.path) > 8192 or urlsplit(self.path).query or urlsplit(self.path).netloc:
            self.respond(400, {'error': 'Unsupported request target'})
            return
        if not self.server.slots.acquire(blocking=False):
            self.respond(503, {'error': 'Registry firewall is busy'})
            return
        firewall = self.server.firewall
        base = 'http://' + expected
        try:
            if self.path == '/status':
                self.respond(200, dict(firewall.store.status(), blocked_requests=firewall.blocks,
                    scope='Public npm/PyPI requests routed through this proxy only'))
            elif '/-/' in unquote(self.path):
                self.artifact(firewall.npm_artifact(self.path))
            elif self.path.startswith(('/npm/', '/pnpm/')):
                self.respond(200, firewall.npm(self.path, base, pnpm_client='pnpm/' in self.headers.get('User-Agent', '')))
            elif self.path.startswith('/pypi/simple/'):
                self.respond(200, firewall.pypi(self.path, base), 'application/vnd.pypi.simple.v1+json')
            elif self.path.startswith('/artifacts/'):
                item = firewall.resolve(self.path)
                verdict = firewall.verdict(item['ecosystem'], item['name'], item['version'])
                if verdict['decision'] == 'block':
                    raise Blocked(verdict)
                self.artifact(item)
            else:
                self.respond(404, {'error': 'Unsupported registry endpoint'})
        except Blocked as error:
            firewall.blocks += 1
            self.respond(403, {'error': 'BOXCOP_KNOWN_MALWARE', 'message': 'This package release is listed as malicious.',
                'reports': [{key: row[key] for key in ('source', 'id', 'url')} for row in error.verdict['reports']]})
        except Missing:
            self.respond(404, {'error': 'Release not found'})
        except httpx.HTTPStatusError as error:
            self.respond(404 if error.response.status_code == 404 else 502, {'error': 'Upstream registry unavailable'})
        except (httpx.HTTPError, ValueError, KeyError, TypeError):
            self.respond(502, {'error': 'Registry response or request could not be validated'})
        except (BrokenPipeError, ConnectionResetError, TimeoutError):
            pass
        finally:
            self.server.slots.release()

    def artifact(self, item):
        with self.server.firewall.upstream.client.stream('HEAD' if self.command == 'HEAD' else 'GET', item['url'],
                                                        headers={'Accept-Encoding': 'identity'}) as response:
            response.raise_for_status()
            size = response.headers.get('Content-Length')
            if size and int(size) > ARTIFACT_LIMIT:
                raise ValueError('Artifact exceeds size limit')
            # Recheck after opening upstream; an update may have arrived while
            # waiting. Once streaming starts, already-sent bytes cannot be revoked.
            verdict = self.server.firewall.verdict(item['ecosystem'], item['name'], item['version'])
            if verdict['decision'] == 'block':
                raise Blocked(verdict)
            self.send_response(200)
            self.send_header('Content-Type', 'application/octet-stream')
            self.send_header('Cache-Control', 'no-store')
            if size and not response.headers.get('Content-Encoding'):
                self.send_header('Content-Length', size)
            self.end_headers()
            if self.command == 'HEAD':
                return
            total = 0
            try:
                for chunk in response.iter_bytes():
                    total += len(chunk)
                    if total > ARTIFACT_LIMIT:
                        break
                    self.wfile.write(chunk)
            except httpx.HTTPError:
                # Headers have been sent. Close the response; don't append JSON
                # to package bytes. Client integrity checks detect truncation.
                self.close_connection = True


class RegistryServer(ThreadingHTTPServer):
    daemon_threads = True
    def __init__(self, firewall, port=8794):
        self.firewall = firewall
        self.slots = threading.BoundedSemaphore(16)
        super().__init__(('127.0.0.1', port), Handler)


def refresh(store, url):
    from .package_transport import download
    if urlsplit(url).scheme != 'https' or urlsplit(url).username:
        raise ValueError('Snapshot updates require HTTPS')
    try:
        store.install(download(url, limit=MAX_BYTES))
    except Exception:
        # Retain last-good policy. No upstream exception body or URL in status.
        store.error = 'Update failed; retaining last verified policy'


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--snapshot', type=Path, required=True)
    parser.add_argument('--public-key', type=Path, required=True, help='Pinned raw 32-byte Ed25519 public key')
    parser.add_argument('--state-dir', type=Path, required=True, help='Persistent artifact-link key; retain across restarts')
    parser.add_argument('--port', type=int, default=8794)
    parser.add_argument('--update-url', help='HTTPS signed snapshot endpoint; no package names are sent')
    parser.add_argument('--update-seconds', type=int, default=900)
    args = parser.parse_args(argv)
    if not 1024 <= args.port <= 65535 or args.update_seconds < 60:
        parser.error('Use an unprivileged port and update interval of at least 60 seconds')
    store = PolicyStore(args.snapshot, args.public_key.read_bytes())
    if args.update_url:
        refresh(store, args.update_url)
    if not store.policy:
        parser.error('A verified initial snapshot is required')
    args.state_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    key_path = args.state_dir / 'artifact-link.key'
    try:
        fd = os.open(key_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, 'wb') as stream:
            stream.write(os.urandom(32))
    except FileExistsError:
        pass
    secret = key_path.read_bytes()
    if len(secret) != 32:
        parser.error('Invalid artifact-link key')
    server = RegistryServer(Firewall(store, secret), args.port)
    stopped = threading.Event()
    if args.update_url:
        def updater():
            while not stopped.wait(args.update_seconds):
                refresh(store, args.update_url)
        threading.Thread(target=updater, daemon=True).start()
    print(f'BoxCop package firewall listening on http://127.0.0.1:{args.port}; GET /status for coverage', flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        stopped.set()
        server.server_close()
        server.firewall.upstream.client.close()


if __name__ == '__main__':
    main()
