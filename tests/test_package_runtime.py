import base64
import threading
import time

import httpx
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from server.package_intelligence import build_payload, datadog_records, now, report, sign
from server.package_runtime import PackageRuntime
from server.package_routing import status as routing_status
from tools.package_service import provision


def fixture(tmp_path, monkeypatch, *, refresh=None):
    key = Ed25519PrivateKey.generate()
    public = key.public_key().public_bytes_raw()
    channel = dict(schema='boxcop.package-channel.v1', url='https://feed.invalid/policy',
                   public_key=base64.b64encode(public).decode(), minimum_sequence=1)
    directory = tmp_path / 'state'
    rows = list(datadog_records({'bad-fixture': ['1.0.0']}, 'npm'))
    rows.append(report('github', 'GHSA-reported', 'npm', 'maybe-bad', [{'kind': 'exact', 'versions': ['2.0.0']}], disposition='review'))
    provision(directory, sign(build_payload(rows, 1, {'fixture': {'fetched_at': now()}}), key), public)
    monkeypatch.setattr('server.package_runtime.refresh', refresh or (lambda *_: None))
    return PackageRuntime(home=tmp_path, directory=directory, channel=channel, port=0)


def idle(runtime):
    deadline = time.monotonic() + 5
    while runtime.status()['busy']:
        assert time.monotonic() < deadline
        time.sleep(.01)
    return runtime.status()


def test_ready_while_refresh_is_blocked_and_quit_keeps_routing(tmp_path, monkeypatch):
    entered, finish = threading.Event(), threading.Event()
    def slow(*_):
        entered.set()
        finish.wait(10)
    runtime = fixture(tmp_path, monkeypatch, refresh=slow)
    try:
        runtime.command('enable')
        assert idle(runtime)['active']
        assert entered.wait(2)
        port = runtime.server.server_port
        with httpx.Client(trust_env=False) as client:
            assert client.get(f'http://127.0.0.1:{port}/npm/bad-fixture/1.0.0').status_code == 403
        runtime.close()
        assert runtime.server is None
        assert routing_status(tmp_path)['configured']
        with httpx.Client(trust_env=False, timeout=.2) as client:
            import pytest
            with pytest.raises(httpx.ConnectError):
                client.get(f'http://127.0.0.1:{port}/status')
    finally:
        finish.set()
        runtime.close()


def test_failed_enable_can_retry_and_disable_restores_config(tmp_path, monkeypatch):
    runtime = fixture(tmp_path, monkeypatch)
    config = tmp_path / '.npmrc'
    config.write_text('registry=https://private.invalid/\n')
    try:
        runtime.command('enable')
        failed = idle(runtime)
        assert not failed['active'] and not failed['busy']
        assert 'custom registry' in failed['summary']
        assert runtime.server is None
        config.write_text('fund=false\n')
        runtime.command('enable')
        assert idle(runtime)['active']
        runtime.command('disable')
        assert not idle(runtime)['routed']
        assert config.read_text() == 'fund=false\n'
        assert runtime.server is None
    finally:
        runtime.close()


def test_relaunch_restores_previously_enabled_routing(tmp_path, monkeypatch):
    runtime = fixture(tmp_path, monkeypatch)
    runtime.command('enable')
    assert idle(runtime)['active']
    runtime.close()
    restarted = PackageRuntime(home=tmp_path, directory=runtime.directory, channel=runtime.channel,
                               port=0)
    try:
        restarted.command('status')
        assert idle(restarted)['active']
    finally:
        restarted.close()


def test_normal_status_does_not_enable_routing(tmp_path, monkeypatch):
    runtime = fixture(tmp_path, monkeypatch)
    try:
        runtime.command('status')
        assert not idle(runtime)['routed']
        assert runtime.server is None
    finally:
        runtime.close()


def test_test_package_is_always_blocked_and_blocks_are_recorded(tmp_path, monkeypatch):
    """`npm install boxcop-test-malware` is the install-gate check. The feed does not
    list it and the upstream registry is never asked about it."""
    import json
    from server.security_events import firewall_events
    runtime = fixture(tmp_path, monkeypatch)
    try:
        runtime.command('enable')
        assert idle(runtime)['active']
        def no_upstream(url):
            raise AssertionError('upstream must not be contacted for the test package: ' + url)
        monkeypatch.setattr(runtime.server.firewall.upstream, 'metadata', no_upstream)
        base = f'http://127.0.0.1:{runtime.server.server_port}'
        with httpx.Client(trust_env=False) as client:
            for path in ('/npm/boxcop-test-malware', '/npm/boxcop-test-malware/1.2.3', '/pnpm/boxcop-test-malware',
                         '/npm/boxcop-test-malware/-/boxcop-test-malware-9.9.9.tgz',
                         '/pypi/simple/boxcop-test-malware/', '/pypi/simple/BoxCop_Test.Malware/'):
                response = client.get(base + path)
                assert response.status_code == 403, path
                assert response.json()['error'] == 'BOXCOP_KNOWN_MALWARE'
                assert response.json()['reports'][0]['id'] == 'BOXCOP-SELF-TEST'
            # A listed release is recorded once however many times the client asks.
            for _ in range(3):
                assert client.get(base + '/npm/bad-fixture/1.0.0').status_code == 403
            assert client.get(base + '/status').json()['blocked_requests'] == 9
        rows = json.loads((runtime.directory / 'blocks.json').read_text())
        assert [(row['ecosystem'], row['package'], row['version'], row['self_test'], row['count']) for row in rows] == [
            ('npm', 'boxcop-test-malware', None, True, 4), ('PyPI', 'boxcop-test-malware', None, True, 2),
            ('npm', 'bad-fixture', '1.0.0', False, 3)]
        assert rows[-1]['sources'] == ['datadog']
        events = firewall_events(runtime.directory, 50)
        listed = next(event for event in events if event['package'] == 'bad-fixture')
        assert listed['title'] == 'Blocked install of bad-fixture 1.0.0' and listed['subject'] == 'bad-fixture@1.0.0'
        assert listed['layer'] == 'install_gate' and listed['outcome'] == 'blocked' and 'datadog' in listed['reason']
        assert any(event['title'] == 'Blocked install of boxcop-test-malware' and 'test package' in event['reason']
                   for event in events)
    finally:
        runtime.close()


def test_similar_names_are_not_the_test_package(tmp_path, monkeypatch):
    from server.package_proxy import self_test
    assert self_test('npm', 'boxcop-test-malware') and self_test('PyPI', 'Boxcop.Test_Malware')
    for name in ('boxcop-test-malware2', '@scope/boxcop-test-malware', 'boxcop-test', '../boxcop-test-malware'):
        assert not self_test('npm', name)


def test_allow_and_revoke_one_reported_release_take_effect_at_once(tmp_path, monkeypatch):
    from server.security_events import firewall_events
    runtime = fixture(tmp_path, monkeypatch)
    try:
        # Before the install gate is on there is no verified list to check against.
        early = runtime.command('allow', 'npm', 'maybe-bad', '2.0.0')
        assert early['exceptions'] == [] and early['exception_error'] == 'Turn on the install gate before allowing a release.'
        runtime.command('enable')
        status = idle(runtime)
        assert status['active'] and status['exceptions'] == [] and status['exception_error'] is None
        base = f'http://127.0.0.1:{runtime.server.server_port}'
        with httpx.Client(trust_env=False) as client:
            refused = client.get(base + '/npm/maybe-bad/2.0.0')
            assert refused.status_code == 403 and refused.json()['error'] == 'BOXCOP_REPORTED_MALWARE'
            row, = firewall_events(runtime.directory, 10)
            assert row['allowable'] and (row['ecosystem'], row['package'], row['version']) == ('npm', 'maybe-bad', '2.0.0')
            for arguments, message in [
                    (('npm', 'bad-fixture', '1.0.0'), 'Confirmed malware cannot be allowed.'),
                    (('npm', 'boxcop-test-malware', '1.0.0'), 'The BoxCop test package cannot be allowed.'),
                    (('PyPI', 'BoxCop_Test.Malware', '1.0.0'), 'The BoxCop test package cannot be allowed.'),
                    (('npm', 'unlisted', '1.0.0'), 'This release is not on the malware list, so there is nothing to allow.'),
                    (('npm', 'maybe-bad', '2.0.1'), 'This release is not on the malware list, so there is nothing to allow.'),
                    (('PyPI', 'maybe-bad', '2.0.0'), 'This release is not on the malware list, so there is nothing to allow.'),
                    (('npm', '../escape', '1.0.0'), 'That is not a valid package release.'),
                    (('gem', 'maybe-bad', '2.0.0'), 'That is not a valid package release.'),
                    (('npm', 'maybe-bad', None), 'That is not a valid package release.')]:
                reply = runtime.command('allow', *arguments)
                assert reply['exception_error'] == message and reply['exceptions'] == [], arguments
            assert not (runtime.directory / 'exceptions.json').exists()
            allowed = runtime.command('allow', 'npm', 'maybe-bad', '2.0.0')
            assert allowed['exception_error'] is None and allowed['active']
            entry, = allowed['exceptions']
            assert set(entry) == {'ecosystem', 'package', 'version', 'added'}
            assert (entry['ecosystem'], entry['package'], entry['version']) == ('npm', 'maybe-bad', '2.0.0')
            assert runtime.command('allow', 'npm', 'maybe-bad', '2.0.0')['exceptions'] == [entry]  # Again: no duplicate.
            assert runtime.command('status')['exceptions'] == [entry] and runtime.command('status')['exception_error'] is None
            assert (runtime.directory / 'exceptions.json').stat().st_mode & 0o777 == 0o600
            # No restart: the next request for it is no longer refused by BoxCop, and the row stops offering it.
            assert runtime.server.firewall.verdict('npm', 'maybe-bad', '2.0.0')['refused'] is None
            assert firewall_events(runtime.directory, 10)[0]['allowable'] is False
            # Confirmed malware stays refused whatever the file says.
            assert client.get(base + '/npm/bad-fixture/1.0.0').status_code == 403
            revoked = runtime.command('revoke', 'npm', 'maybe-bad', '2.0.0')
            assert revoked['exceptions'] == [] and revoked['exception_error'] is None
            assert runtime.command('revoke', 'npm', 'maybe-bad', '2.0.0')['exception_error'] is None  # Already gone.
            assert client.get(base + '/npm/maybe-bad/2.0.0').status_code == 403
        # An exception survives a restart of the engine.
        runtime.command('allow', 'npm', 'maybe-bad', '2.0.0')
    finally:
        runtime.close()
    restarted = PackageRuntime(home=tmp_path, directory=runtime.directory, channel=runtime.channel, port=0)
    try:
        assert [row['package'] for row in restarted.status()['exceptions']] == ['maybe-bad']
    finally:
        restarted.close()
