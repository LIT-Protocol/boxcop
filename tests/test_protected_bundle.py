"""Distribution guards: no Apple approval is inferred from an entitlement plist."""
from datetime import datetime, timedelta, timezone
import hashlib
import importlib.util
from pathlib import Path
import plistlib

import pytest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('protected_bundle', ROOT / 'desktop/macos/scripts/protected_bundle.py')
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
CERTIFICATE = b'synthetic public certificate bytes'
IDENTITY = hashlib.sha1(CERTIFICATE).hexdigest()
TEAM = 'ABCDE12345'


def profile(kind):
    return {'ExpirationDate': datetime.now(timezone.utc) + timedelta(days=1),
            'TeamIdentifier': [TEAM], 'ProvisionsAllDevices': True, 'DeveloperCertificates': [CERTIFICATE],
            'Entitlements': {**module.REQUIRED[kind], 'com.apple.developer.team-identifier': TEAM,
                             'com.apple.application-identifier': TEAM + '.' + module.IDENTIFIERS[kind]}}


@pytest.mark.parametrize('kind', ['app', 'network'])
def test_network_distribution_does_not_require_endpoint_security(kind):
    data = profile(kind)
    assert module.validate_profile(data, kind, IDENTITY) == TEAM
    assert 'com.apple.developer.endpoint-security.client' not in data['Entitlements']


@pytest.mark.parametrize('mutation', ['expired', 'debug', 'wildcard', 'certificate', 'capability', 'distribution', 'team'])
def test_rejects_invalid_distribution_profiles(mutation):
    data = profile('network')
    if mutation == 'expired': data['ExpirationDate'] = datetime.now(timezone.utc) - timedelta(days=1)
    if mutation == 'debug': data['Entitlements']['com.apple.security.get-task-allow'] = True
    if mutation == 'wildcard': data['Entitlements']['com.apple.application-identifier'] = TEAM + '.*'
    if mutation == 'certificate': data['DeveloperCertificates'] = [b'other']
    if mutation == 'capability': data['Entitlements']['com.apple.developer.networking.networkextension'] = ['packet-tunnel-provider']
    if mutation == 'distribution': data['ProvisionsAllDevices'] = False
    if mutation == 'team': data['Entitlements']['com.apple.developer.team-identifier'] = 'OTHER12345'
    with pytest.raises(ValueError): module.validate_profile(data, 'network', IDENTITY)


def test_missing_profiles_fail_before_decoding():
    with pytest.raises(ValueError, match='app and network'):
        module.load_profiles({'app': None, 'network': None}, IDENTITY)


def test_bundle_has_only_network_extension_and_matching_version(tmp_path):
    bundle = tmp_path / 'BoxCop.app'
    (bundle / 'Contents').mkdir(parents=True)
    (bundle / 'Contents/Info.plist').write_bytes(plistlib.dumps({'CFBundleIdentifier': module.APP_ID}))
    native = tmp_path / 'native'; native.write_bytes(b'native-fixture')
    network = tmp_path / 'network'; network.write_bytes(b'network-fixture')
    profiles = {}
    for kind in ['app', 'network']:
        path = tmp_path / (kind + '.provisionprofile'); path.write_bytes(b'synthetic-profile')
        profiles[kind] = {'path': path, 'entitlements': module.REQUIRED[kind]}
    signing = module.embed(bundle, native, network, profiles, '42')
    extensions = list((bundle / 'Contents/Library/SystemExtensions').iterdir())
    assert len(extensions) == 1
    info = plistlib.loads((extensions[0] / 'Contents/Info.plist').read_bytes())
    assert info['BoxCopNetworkMode'] == 'standalone'
    assert info['NSSystemExtensionUsageDescription'].strip()
    assert plistlib.loads((bundle / 'Contents/Info.plist').read_bytes())['NSSystemExtensionUsageDescription'].strip()
    assert info['CFBundleVersion'] == '42'
    assert info['CFBundleIdentifier'] == module.NETWORK_ID
    assert (extensions[0] / 'Contents/MacOS/BoxCopNetworkFilter').read_bytes() == b'network-fixture'
    import json
    threats = extensions[0] / 'Contents/Resources/ThreatDomains'
    metadata = json.loads((threats / 'manifest.json').read_text())
    assert hashlib.sha256((threats / 'domains.txt').read_bytes()).hexdigest() == metadata['sha256']
    assert (threats / 'LICENSE').is_file()
    assert (threats / 'NOTICE.txt').is_file()
    assert len(signing) == 2
    assert plistlib.loads((bundle / 'Contents/Info.plist').read_bytes())['CFBundleVersion'] == '42'


@pytest.mark.parametrize('version', ['', '0', '-1', '1.0', '../2'])
def test_extension_version_is_explicit_positive_integer(version, tmp_path):
    with pytest.raises(ValueError, match='version'):
        module.embed(tmp_path, tmp_path, tmp_path, {}, version)
