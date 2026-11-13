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
def test_combined_extension_requires_endpoint_security_only_on_extension(kind):
    data = profile(kind)
    assert module.validate_profile(data, kind, IDENTITY) == TEAM
    assert data['Entitlements'].get('com.apple.developer.endpoint-security.client', False) == (kind == 'network')


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


def test_bundle_identifiers_match_the_provisioning_profiles():
    """The profiles BoxCop is signed with are bound to these identifiers; renaming needs new profiles."""
    assert module.APP_ID == 'local.sentinel.endpoint'
    assert module.NETWORK_ID == 'local.sentinel.endpoint.network-filter'
    info = plistlib.loads((ROOT / 'desktop/macos/Resources/Info.plist').read_bytes())
    assert info['CFBundleIdentifier'] == module.APP_ID


def test_missing_profiles_fail_before_decoding():
    with pytest.raises(ValueError, match='app and network'):
        module.load_profiles({'app': None, 'network': None}, IDENTITY)


def test_bundle_has_only_network_extension_and_matching_version(tmp_path):
    bundle = tmp_path / 'BoxCop.app'
    (bundle / 'Contents').mkdir(parents=True)
    (bundle / 'Contents/Info.plist').write_bytes(plistlib.dumps({'CFBundleIdentifier': module.APP_ID,
                                                                  'CFBundleShortVersionString': '1.2.3'}))
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
    # The filter always runs standalone; no mode key is needed or read.
    assert 'BoxCopNetworkMode' not in info
    assert 'BoxCopNetworkMode' not in (ROOT / 'desktop/macos/Sources/BoxCopNetworkFilter/main.swift').read_text()
    assert info['CFBundleName'] == info['CFBundleDisplayName'] == 'BoxCop Network Filter'
    assert info['CFBundleShortVersionString'] == '1.2.3'
    assert info['NSSystemExtensionUsageDescription'].startswith('BoxCop records new outgoing connections')
    provider = info['NetworkExtension']['NEProviderClasses']['com.apple.networkextension.filter-data']
    # The system instantiates the provider by this Objective-C name.
    swift = (ROOT / 'desktop/macos/Sources/BoxCopNetworkFilter/main.swift').read_text()
    assert provider == 'BoxCopFilterDataProvider' and f'@objc({provider})' in swift
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


def test_old_network_profile_is_rejected_without_endpoint_security():
    data = profile('network')
    del data['Entitlements']['com.apple.developer.endpoint-security.client']
    with pytest.raises(ValueError, match='endpoint-security'):
        module.validate_profile(data, 'network', IDENTITY)
