"""Reversible user npmrc routing. Never changes scoped registries or credentials."""
import json
from pathlib import Path
import re

from .package_intelligence import atomic_write, canonical

BEGIN = '# BEGIN BOXCOP PACKAGE PROTECTION'
END = '# END BOXCOP PACKAGE PROTECTION'
REGISTRY = 'http://127.0.0.1:8794/npm/'
BLOCK = BEGIN + '\nregistry=' + REGISTRY + '\n' + END + '\n'


def read_config(path):
    if path.is_symlink():
        raise ValueError('Symlinked npm configuration requires manual setup')
    if not path.exists():
        return ''
    with path.open('r') as stream:
        text = stream.read(1024 * 1024 + 1)
    if len(text) > 1024 * 1024:
        raise ValueError('npm configuration is too large')
    return text


def default_registry(text):
    values = re.findall(r'^\s*registry\s*=\s*(.*?)\s*$', text, re.MULTILINE)
    return values[-1].strip('"\'') if values else 'https://registry.npmjs.org/'


def enable(home, state):
    path, receipt = Path(home) / '.npmrc', Path(state) / 'npm-routing.json'
    text = read_config(path)
    if BEGIN in text or END in text:
        if BLOCK not in text or not receipt.exists():
            raise ValueError('Existing BoxCop routing needs manual review')
        if default_registry(text) != REGISTRY:
            raise ValueError('Another registry setting overrides BoxCop routing')
        return
    if default_registry(text).rstrip('/') != 'https://registry.npmjs.org':
        raise ValueError('Existing custom registry preserved; configure public routing manually')
    if re.search(r'^\s*(?:_auth|_authToken|_password)\s*=', text, re.MULTILINE):
        raise ValueError('Scope npm credentials to their registry before enabling protection')
    newline = bool(text and not text.endswith('\n'))
    # Receipt contains no npmrc content or credentials; persist before changing
    # routing so a crash leaves enough information to remove our exact block.
    atomic_write(receipt, canonical({'created': not path.exists(), 'added_newline': newline}))
    atomic_write(path, (text + ('\n' if newline else '') + BLOCK).encode())


def disable(home, state):
    path, receipt = Path(home) / '.npmrc', Path(state) / 'npm-routing.json'
    text = read_config(path)
    if BEGIN not in text and END not in text:
        receipt.unlink(missing_ok=True)
        return
    if text.count(BLOCK) != 1 or text.count(BEGIN) != 1 or text.count(END) != 1:
        raise ValueError('BoxCop routing was edited; remove the marked block manually before stopping the service')
    value = json.loads(receipt.read_bytes()) if receipt.exists() else {}
    suffix = text.endswith(BLOCK)
    restored = text.replace(BLOCK, '', 1)
    if suffix and value.get('added_newline') and restored.endswith('\n'):
        restored = restored[:-1]
    if not restored and value.get('created'):
        path.unlink()
    else:
        atomic_write(path, restored.encode())
    receipt.unlink(missing_ok=True)


def status(home):
    text = read_config(Path(home) / '.npmrc')
    return {'configured': BLOCK in text and default_registry(text) == REGISTRY, 'managed': BEGIN in text or END in text,
            'scope': 'User npm/pnpm defaults; project settings, environment overrides, caches and direct URLs can bypass'}
