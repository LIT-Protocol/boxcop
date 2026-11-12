"""Shared optional policy for existing command/inventory consumers.

Provisioning pins the public key locally. This is not a boundary against a user
who can modify their own app state; remote updates cannot replace the key.
"""
from pathlib import Path
import threading

_lock = threading.Lock()
_cached_identity = None
_cached_policy = None


def state_directory():
    return Path.home() / 'Library/Application Support/BoxCop/package-protection'


def local_policy():
    global _cached_identity, _cached_policy
    directory = state_directory()
    paths = (directory / 'policy.json', directory / 'public.key')
    try:
        identity = tuple((str(path), path.stat().st_ino, path.stat().st_mtime_ns, path.stat().st_size) for path in paths)
        with _lock:
            if identity != _cached_identity:
                from .package_intelligence import MAX_BYTES, verify
                if paths[0].stat().st_size > MAX_BYTES:
                    return None
                _cached_policy = verify(paths[0].read_bytes(), paths[1].read_bytes())
                _cached_identity = identity
            return _cached_policy
    except Exception:
        # Existing command heuristics still work without provisioned intelligence.
        # The registry helper separately exposes update/coverage status.
        return None
