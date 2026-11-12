#!/usr/bin/env python3
"""Install GitHub signing secrets into a disposable runner keychain; never log secrets."""
import base64
import json
import os
from pathlib import Path
import secrets
import shlex
import shutil
import subprocess
import sys


def run(args):
    result = subprocess.run(args, capture_output=True, text=True)
    if result.returncode:
        # Commands and captured output may contain credentials.
        raise RuntimeError('Signing credential operation failed: ' + Path(args[0]).name)
    return result.stdout


def root():
    if os.environ.get('GITHUB_ACTIONS') != 'true' or not os.environ.get('RUNNER_TEMP'):
        raise RuntimeError('This helper is only for GitHub Actions runners')
    return Path(os.environ['RUNNER_TEMP']) / 'boxcop-signing'


def install():
    required = ['BOXCOP_CERTIFICATE_BASE64', 'BOXCOP_CERTIFICATE_PASSWORD', 'BOXCOP_APP_PROFILE_BASE64',
                'BOXCOP_NETWORK_PROFILE_BASE64', 'BOXCOP_NOTARY_APPLE_ID', 'BOXCOP_NOTARY_PASSWORD']
    if any(not os.environ.get(name) for name in required):
        raise RuntimeError('Missing required GitHub signing secrets; no unsigned fallback')
    directory = root()
    directory.mkdir(mode=0o700)
    keychain = directory / 'ci.keychain-db'
    old = shlex.split(run(['security', 'list-keychains', '-d', 'user']))
    (directory / 'search-list.json').write_text(json.dumps(old))
    for variable, filename in [('BOXCOP_CERTIFICATE_BASE64', 'identity.p12'),
                               ('BOXCOP_APP_PROFILE_BASE64', 'Allay_Developer_ID.provisionprofile'),
                               ('BOXCOP_NETWORK_PROFILE_BASE64', 'Allay_Network_Developer_ID.provisionprofile')]:
        path = directory / filename
        path.write_bytes(base64.b64decode(os.environ[variable], validate=True))
        path.chmod(0o600)
    password = secrets.token_urlsafe(32)
    run(['security', 'create-keychain', '-p', password, str(keychain)])
    run(['security', 'set-keychain-settings', '-lut', '21600', str(keychain)])
    run(['security', 'unlock-keychain', '-p', password, str(keychain)])
    run(['security', 'import', str(directory / 'identity.p12'), '-k', str(keychain), '-P',
         os.environ['BOXCOP_CERTIFICATE_PASSWORD'], '-T', '/usr/bin/codesign', '-T', '/usr/bin/security'])
    run(['security', 'set-key-partition-list', '-S', 'apple-tool:,apple:,codesign:', '-s', '-k', password, str(keychain)])
    run(['security', 'list-keychains', '-d', 'user', '-s', str(keychain), *old])
    run(['xcrun', 'notarytool', 'store-credentials', 'boxcop-ci', '--apple-id', os.environ['BOXCOP_NOTARY_APPLE_ID'],
         '--password', os.environ['BOXCOP_NOTARY_PASSWORD'], '--team-id', 'QWER3PMRVZ', '--keychain', str(keychain)])
    (directory / 'identity.p12').unlink()
    exported = {'BOXCOP_KEYCHAIN_PATH': str(keychain), 'BOXCOP_NOTARY_PROFILE': 'boxcop-ci',
                'BOXCOP_APP_PROFILE': str(directory / 'Allay_Developer_ID.provisionprofile'),
                'BOXCOP_NETWORK_PROFILE': str(directory / 'Allay_Network_Developer_ID.provisionprofile'),
                'BOXCOP_SIGNING_IDENTITY': '8D5650DE08B51DDACD873C92D767F43B4654AFA6'}
    with open(os.environ['GITHUB_ENV'], 'a') as stream:
        for name, value in exported.items():
            if '\n' in value or '\r' in value: raise RuntimeError('Invalid runner path')
            stream.write(name + '=' + value + '\n')
    print('Signing identity, profiles and notarization credentials installed')


def cleanup():
    directory = root()
    if not directory.exists(): return
    failed = False
    previous = directory / 'search-list.json'
    if previous.exists():
        try: run(['security', 'list-keychains', '-d', 'user', '-s', *json.loads(previous.read_text())])
        except RuntimeError: failed = True
    keychain = directory / 'ci.keychain-db'
    if keychain.exists():
        try: run(['security', 'delete-keychain', str(keychain)])
        except RuntimeError: failed = True
    shutil.rmtree(directory)
    if failed: raise RuntimeError('Keychain cleanup encountered an error')
    print('Temporary signing credentials removed')


if __name__ == '__main__':
    try:
        if sys.argv[1:] == ['install']: install()
        elif sys.argv[1:] == ['cleanup']: cleanup()
        else: raise RuntimeError('Expected install or cleanup')
    except Exception as exc:
        # Do not emit arbitrary exception representations (including secret values).
        print(str(exc) if type(exc) is RuntimeError else 'Signing setup failed; secret details suppressed', file=sys.stderr)
        sys.exit(1)
