"""Policy provisioning and recovery for legacy standalone installations.

New enrollment is managed inside the BoxCop app engine.
"""
import argparse
import os
from pathlib import Path
import subprocess
import json

import httpx

from server.local_package_policy import state_directory
from server.package_intelligence import PolicyStore, atomic_write

LABEL = 'com.boxcop.package-protection'


def service_plist(engine, directory, *, update_url=None, port=8794):
    arguments = [str(engine), '--package-protection', '--snapshot', str(directory / 'policy.json'),
        '--public-key', str(directory / 'public.key'), '--state-dir', str(directory), '--port', str(port)]
    if update_url:
        from urllib.parse import urlsplit
        parsed = urlsplit(update_url)
        if parsed.scheme != 'https' or not parsed.hostname or parsed.username:
            raise ValueError('Update URL must use HTTPS without credentials')
        arguments += ['--update-url', update_url]
    return {'Label': LABEL, 'ProgramArguments': arguments, 'RunAtLoad': True, 'KeepAlive': True,
            'ThrottleInterval': 10, 'ProcessType': 'Background'}


def provision(directory, signed_policy, public_key):
    directory = Path(directory)
    pinned = directory / 'public.key'
    if pinned.exists() and pinned.read_bytes() != public_key:
        raise ValueError('Pinned key differs; explicit key rotation is required')
    # Authenticate before publishing either the pin or policy.
    store = PolicyStore(directory / 'policy.json', public_key)
    store.install(signed_policy)
    if not pinned.exists():
        atomic_write(pinned, public_key)


def launch_agent_path():
    return Path.home() / 'Library/LaunchAgents' / (LABEL + '.plist')


def management_status():
    from server.package_channel import bundled_channel
    from server.package_routing import status
    channel = bundled_channel()
    routing = status(Path.home())
    helper = None
    try:
        with httpx.Client(trust_env=False, timeout=2) as client:
            response = client.get('http://127.0.0.1:8794/status')
            response.raise_for_status()
            helper = response.json()
    except (httpx.HTTPError, ValueError):
        pass
    available = bool(helper and helper.get('available'))
    return {'configured': channel is not None, 'routed': routing['managed'], 'helper_available': available,
        'stale': helper.get('stale', True) if helper else True,
        'generated_at': helper.get('generated_at') if helper else None,
        'update_error': helper.get('update_error') if helper else None,
        'summary': 'npm/pnpm routing enabled' if routing['configured'] and available else
                   'Routing enabled; helper unavailable' if routing['configured'] else
                   'BoxCop routing was overridden or edited; review or disable it' if routing['managed'] else
                   'Ready to enable' if channel else 'Feed not configured in this build', 'coverage': routing['scope']}


def management_main(argv=None):
    """Small JSON interface for the app; actions require an explicit UI click."""
    parser = argparse.ArgumentParser()
    parser.add_argument('operation', choices=['status', 'enable', 'disable'])
    parser.add_argument('--engine', type=Path)
    args = parser.parse_args(argv)
    try:
        if args.operation == 'enable':
            raise ValueError('Enable package protection in BoxCop; standalone background enrollment is no longer supported')
        elif args.operation == 'disable':
            from server.package_routing import disable
            disable(Path.home(), state_directory())
            if launch_agent_path().exists():
                subprocess.run(['/bin/launchctl', 'bootout', f'gui/{os.getuid()}', str(launch_agent_path())], check=True, capture_output=True)
                launch_agent_path().unlink()
        print(json.dumps(management_status()))
        return 0
    except Exception as error:
        try:
            value = management_status()
        except Exception:
            value = {'configured': False, 'routed': True, 'helper_available': False, 'stale': True}
        value['summary'] = str(error) if isinstance(error, ValueError) else 'Package protection setup failed: ' + type(error).__name__
        print(json.dumps(value))
        return 1


def main(argv=None):
    raise SystemExit('Package protection runs inside BoxCop. Use the app to enable or disable it.')


if __name__ == '__main__':
    main()
