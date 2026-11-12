"""Provisioned system-extension packaging. Never manufactures Apple approval."""
from datetime import datetime, timezone
import hashlib
from pathlib import Path
import plistlib
import re
import shutil
import subprocess

APP_ID = 'local.sentinel.endpoint'
NETWORK_ID = APP_ID + '.network-filter'
REQUIRED = {
    'app': {'com.apple.developer.system-extension.install': True,
            'com.apple.developer.networking.networkextension': ['content-filter-provider-systemextension']},
    'network': {'com.apple.developer.networking.networkextension': ['content-filter-provider-systemextension']},
}
IDENTIFIERS = {'app': APP_ID, 'network': NETWORK_ID}


def validate_profile(profile, kind, identity, now=None):
    """Exact app ID, distribution scope, entitlement, expiry, team and certificate checks."""
    now = now or datetime.now(timezone.utc)
    expires = profile.get('ExpirationDate')
    if not isinstance(expires, datetime) or expires.replace(tzinfo=timezone.utc) <= now:
        raise ValueError(kind + ': provisioning profile expired or missing expiry')
    teams = profile.get('TeamIdentifier', [])
    if len(teams) != 1 or not re.fullmatch(r'[A-Z0-9]{10}', teams[0]):
        raise ValueError(kind + ': invalid team identity')
    team = teams[0]
    entitlements = profile.get('Entitlements', {})
    identifier = entitlements.get('com.apple.application-identifier', entitlements.get('application-identifier'))
    if identifier != team + '.' + IDENTIFIERS[kind]:
        raise ValueError(kind + ': profile must match the exact bundle identifier')
    if profile.get('ProvisionsAllDevices') is not True or entitlements.get('get-task-allow') or entitlements.get('com.apple.security.get-task-allow'):
        raise ValueError(kind + ': Developer ID distribution profile required')
    if entitlements.get('com.apple.developer.team-identifier') != team:
        raise ValueError(kind + ': entitlement team mismatch')
    if not re.fullmatch(r'[A-Fa-f0-9]{40}', identity) or identity.upper() not in {
        hashlib.sha1(certificate).hexdigest().upper() for certificate in profile.get('DeveloperCertificates', [])
    }:
        raise ValueError(kind + ': selected signing certificate is absent from profile')
    for key, required in REQUIRED[kind].items():
        actual = entitlements.get(key)
        if (isinstance(required, list) and (not isinstance(actual, list) or not set(required) <= set(actual))) or (required is True and actual is not True):
            raise ValueError(kind + ': profile lacks ' + key)
    return team


def load_profiles(paths, identity):
    if set(paths) != set(REQUIRED) or any(path is None for path in paths.values()):
        raise ValueError('Protected builds require app and network Developer ID profiles')
    result = {}
    for kind, path in paths.items():
        path = Path(path)
        if not path.is_file() or path.is_symlink():
            raise ValueError(kind + ': regular provisioning profile file required')
        decoded = subprocess.run(['/usr/bin/security', 'cms', '-D', '-i', str(path)], capture_output=True, check=True)
        profile = plistlib.loads(decoded.stdout)
        team = validate_profile(profile, kind, identity)
        result[kind] = {'path': path, 'team': team, 'entitlements': {
            **REQUIRED[kind], 'com.apple.application-identifier': team + '.' + IDENTIFIERS[kind],
            'com.apple.developer.team-identifier': team,
        }}
    if len({row['team'] for row in result.values()}) != 1:
        raise ValueError('App and extensions must have the same signing team')
    return result


def embed(bundle, native, network, profiles, build_version):
    if not re.fullmatch(r'[1-9][0-9]*', str(build_version)):
        raise ValueError('An increasing positive extension build version is required')
    destinations = {'app': bundle}
    for kind, executable in [('network', network)]:
        identifier = IDENTIFIERS[kind]
        destination = bundle / 'Contents/Library/SystemExtensions' / (identifier + '.systemextension')
        (destination / 'Contents/MacOS').mkdir(parents=True)
        name = 'BoxCopNetworkFilter'
        shutil.copy2(executable, destination / 'Contents/MacOS' / name)
        shutil.copytree(Path(__file__).resolve().parents[1] / 'Resources/ThreatDomains',
                        destination / 'Contents/Resources/ThreatDomains')
        info = {'CFBundleIdentifier': identifier, 'CFBundleName': 'BoxCop Network Filter',
                'CFBundleExecutable': name, 'CFBundlePackageType': 'SYSX', 'CFBundleVersion': str(build_version),
                'CFBundleShortVersionString': '0.1', 'LSMinimumSystemVersion': '14.0', 'BoxCopNetworkMode': 'standalone',
                'NSSystemExtensionUsageDescription': 'BoxCop logs outgoing connections from all apps and blocks listed threat domains.'}
        if kind == 'network':
            info['NetworkExtension'] = {'NEProviderClasses': {'com.apple.networkextension.filter-data': 'BoxCopFilterDataProvider'}}
        (destination / 'Contents/Info.plist').write_bytes(plistlib.dumps(info))
        destinations[kind] = destination
    app_info = bundle / 'Contents/Info.plist'
    info = plistlib.loads(app_info.read_bytes())
    info['NSSystemExtensionUsageDescription'] = 'BoxCop logs outgoing connections from all apps and blocks listed threat domains.'
    info['CFBundleVersion'] = str(build_version)
    app_info.write_bytes(plistlib.dumps(info))
    for kind, destination in destinations.items():
        shutil.copy2(profiles[kind]['path'], destination / 'Contents/embedded.provisionprofile')
    return {destinations[kind]: profiles[kind]['entitlements'] for kind in destinations}
