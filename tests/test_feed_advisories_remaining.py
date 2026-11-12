"""Final-feed metadata coverage and declaration trust boundaries."""
import json
import plistlib
import subprocess
import sys

import pytest
from server.exposure_advisories import findings
from server.software_inventory import Scan, defaults
from server.deployment_metadata import IMAGES

CASES = [
    ('github.com/labstack/echo/v4', '4.16.0', '4.16.1'),
    ('github.com/labstack/echo/v5', '5.4.0', '5.4.1'),
    ('goahead', '6.1.0', '6.1.1'),
    ('kubeflow-frontend', '2.17.3', '2.18.0'),
    ('postiz', '2.25.2', '2.25.3'),
    ('zitadel', '4.19.4', '4.19.5'),
    ('rancher', '2.15.2', '2.15.3'),
    ('fleet', '0.16.2', '0.16.3'),
    ('cloudflared', '2026.10.1', '2026.10.2'),
    ('cloudflare-warp', '2026.8.2114.0', '2026.8.2115.0'),
]


@pytest.mark.parametrize('name,old,fixed', CASES)
def test_reviewed_boundaries(name, old, fixed):
    assert findings(name, old)[0]['state'] in {'affected_version', 'update_available'}
    row = findings(name, fixed)[0]
    assert row['state'] == 'fixed_for_advisory'
    assert row['enforcement'] == 'finding_only'


@pytest.mark.parametrize('name,old,fixed', CASES)
@pytest.mark.parametrize('version', ['', 'latest', '1.2', '99999.0.0', '4.19.5-vendor', '4.19.5rc1', 'v4.19.5'])
def test_no_guessed_versions(name, old, fixed, version):
    assert findings(name, version)[0]['state'] == 'unresolved'


@pytest.mark.parametrize('product,version', [('rancher', v) for v in ('2.11.19', '2.12.15', '2.13.11', '2.14.7')] + [('fleet', v) for v in ('0.13.17', '0.14.12', '0.15.8')])
def test_other_branches(product, version):
    assert findings(product, version)[0]['state'] == 'fixed_for_advisory'
    parts = version.split('.')
    parts[-1] = str(int(parts[-1])-1)
    assert findings(product, '.'.join(parts))[0]['state'] == 'update_available'


def test_source_specific_uncertainty():
    assert findings('kubeflow-frontend', '2.17.4')[0]['state'] == 'unresolved'
    assert findings('zitadel', '3.4.15')[0]['state'] == 'affected_version'
    assert findings('zitadel', '3.4.16')[0]['state'] == 'unresolved'
    assert findings('github.com/labstack/echo/v4', '5.4.1')[0]['state'] == 'unresolved'
    for name in ('cursor-browser', 'vscode-browser', 'claude-browser', 'codex-browser'):
        assert findings(name, '999.999.999')[0]['state'] == 'unresolved'


def scan_text(tmp_path, name, text):
    (tmp_path/name).write_text(text)
    return Scan().run([tmp_path])


def test_echo_require_declarations_and_updates(tmp_path):
    text = 'module example.org/app\ngo 1.25\nrequire (\n github.com/labstack/echo/v4 v4.16.0 // indirect\n github.com/labstack/echo/v5 v5.4.0\n)\n'
    report = scan_text(tmp_path, 'go.mod', text)
    assert not report['incomplete'] and len(report['records']) == 2
    assert len({r['id'] for r in report['records']}) == 2
    assert all(r['advisories'][0]['state'] == 'affected_version' for r in report['records'])
    report = scan_text(tmp_path, 'go.mod', text.replace('4.16.0', '4.16.1').replace('5.4.0', '5.4.1'))
    assert all(r['advisories'][0]['state'] == 'unresolved' for r in report['records'])
    assert all(r['advisories'][0]['declared_version_state'] == 'fixed_for_advisory' for r in report['records'])


@pytest.mark.parametrize('suffix', ['replace github.com/labstack/echo/v4 => ../fork', 'replace (\n github.com/labstack/echo/v4 => ../fork\n)', 'exclude github.com/labstack/echo/v4 v4.16.0'])
def test_go_overrides_are_not_resolved(tmp_path, suffix):
    report = scan_text(tmp_path, 'go.mod', 'require github.com/labstack/echo/v4 v4.16.1\n'+suffix)
    assert report['records'][0]['version'] == 'unknown'
    assert report['records'][0]['advisories'][0]['state'] == 'unresolved'


@pytest.mark.parametrize('text', ['require (\n github.com/labstack/echo/v4 v4.16.1', 'require github.com/labstack/echo/v4 v4.16.1\nrequire github.com/labstack/echo/v4 v4.1.0', 'require github.com/labstack/echo/v4 v4.16.1 unexpected'])
def test_bad_go_metadata_is_incomplete(tmp_path, text):
    report = scan_text(tmp_path, 'go.mod', text)
    assert report['incomplete'] and not report['records']


def test_go_sum_does_not_select_versions(tmp_path):
    report = scan_text(tmp_path, 'go.sum', 'github.com/labstack/echo/v4 v4.16.0 h1:dummy\n')
    assert not report['records']


@pytest.mark.parametrize('repository,product', IMAGES.items())
def test_exact_image_identity(tmp_path, repository, product):
    old = next(old for name, old, _ in CASES if name == product)
    report = scan_text(tmp_path, 'compose.yaml', f'services:\n  app:\n    image: {repository}:v{old}\n')
    assert not report['incomplete']
    row = report['records'][0]
    assert row['name'] == product and row['version'] == old
    assert row['kind'] == 'deployment_image_declaration' and row['running_state'] == 'unknown'
    report = scan_text(tmp_path, 'compose.yaml', f'services:\n  app:\n    image: attacker.test/{repository}:{old}\n')
    assert not report['records']


@pytest.mark.parametrize('tag', ['latest', '${TAG}', '2.25.3@sha256:'+'a'*64, '2.25.3-vendor', ''])
def test_image_unknown_tags(tmp_path, tag):
    reference = 'ghcr.io/gitroomhq/postiz-app' + (':'+tag if tag else '')
    report = scan_text(tmp_path, 'compose.json', json.dumps({'services': {'app': {'image': reference}}}))
    assert report['records'][0]['version'] == 'unknown'
    assert report['records'][0]['advisories'][0]['state'] == 'unresolved'


def test_compose_build_override_and_multiple_versions(tmp_path):
    report = scan_text(tmp_path, 'compose.json', json.dumps({'services': {
        'old': {'image': 'ghcr.io/gitroomhq/postiz-app:2.25.2'},
        'fixed': {'image': 'ghcr.io/gitroomhq/postiz-app:2.25.3'},
        'local': {'image': 'ghcr.io/gitroomhq/postiz-app:2.25.3', 'build': '.'},
    }}))
    assert len(report['records']) == 3 and len({r['id'] for r in report['records']}) == 3
    assert {r['version'] for r in report['records']} == {'2.25.2', '2.25.3', 'unknown'}
    assert all(r['advisories'][0]['state'] != 'fixed_for_advisory' for r in report['records'])


@pytest.mark.parametrize('kind,api', [('Pod','v1'), ('Deployment','apps/v1'), ('StatefulSet','apps/v1'), ('DaemonSet','apps/v1'), ('Job','batch/v1'), ('CronJob','batch/v1')])
def test_kubernetes_pod_spec_paths(tmp_path, kind, api):
    spec = {'containers': [{'image': 'ghcr.io/kubeflow/kfp-frontend:2.17.3'}], 'initContainers': [{'image': 'rancher/fleet:v0.16.2'}]}
    if kind != 'Pod': spec = {'template': {'spec': spec}}
    if kind == 'CronJob': spec = {'jobTemplate': {'spec': spec}}
    obj = {'apiVersion': api, 'kind': kind, 'spec': spec}
    report = scan_text(tmp_path, 'workloads.k8s.json', json.dumps({'apiVersion': 'v1', 'kind': 'List', 'items': [obj]}))
    assert not report['incomplete'] and len(report['records']) == 2
    obj['apiVersion'] = 'attacker/v1'
    report = scan_text(tmp_path, 'workloads.k8s.json', json.dumps(obj))
    assert not report['records']


@pytest.mark.parametrize('text', [
    'services: {app: {image: good, image: ghcr.io/gitroomhq/postiz-app:2.25.3}}',
    'services: &a {app: *a}', '!!python/object/apply:os.system ["touch SHOULD_NOT_EXIST"]',
    'services: []', 'services: {app: {image: []}}',
    'services: {app: {image: "ghcr.io/gitroomhq/postiz-app:2.25.2"}}\n---\nservices: [',
    'services: '+('['*40)+(']'*40),
    'services: {}\n---\n'*17,
    'services: {app: {image: !!str ghcr.io/gitroomhq/postiz-app:latest}, app: {}}',
])
def test_malformed_yaml_fails_without_partial_findings(tmp_path, text):
    report = scan_text(tmp_path, 'compose.yaml', text)
    assert report['incomplete'] and not report['records']
    assert report['issue_details'][0]['path'].endswith('compose.yaml')


def test_source_identity_not_npm_name(tmp_path):
    report = scan_text(tmp_path, 'package.json', '{"name":"goahead","version":"6.1.0"}')
    assert not report['records']
    row = {'name': 'goahead', 'version': '6.1.0', 'repository': 'git://github.com/embedthis/goahead.git', 'homepage': 'https://embedthis.com/goahead/'}
    report = scan_text(tmp_path, 'package.json', json.dumps(row))
    assert report['records'][0]['name'] == 'goahead'
    row['version'] = '6.1.1'
    report = scan_text(tmp_path, 'package.json', json.dumps(row))
    assert report['records'][0]['advisories'][0]['state'] == 'unresolved'
    # Postiz's real root manifest is gitroom 1.0.0, not its release version.
    report = scan_text(tmp_path, 'package.json', '{"name":"gitroom","version":"1.0.0"}')
    assert not report['records']


def test_app_and_formula_automatic_discovery(tmp_path, monkeypatch):
    from server import software_inventory
    roots = [tmp_path/str(i)/root.name for i, root in enumerate(defaults(tmp_path/'home'))]
    monkeypatch.setattr(software_inventory, 'defaults', lambda: roots)
    ids = {'com.cloudflare.1dot1dot1dot1.macos': '2026.8.2114.0', 'com.todesktop.230313mzl4w4u92': '3.0.0', 'com.microsoft.VSCode': '1.0.0', 'com.anthropic.claudefordesktop': '1.0.0', 'com.openai.codex': '1.0.0'}
    for i, (identity, version) in enumerate(ids.items()):
        app = roots[0]/f'{i}.app/Contents'
        app.mkdir(parents=True)
        (app/'Info.plist').write_bytes(plistlib.dumps({'CFBundleIdentifier': identity, 'CFBundleShortVersionString': version}))
    receipt = roots[2]/'cloudflared/2026.10.1/INSTALL_RECEIPT.json'
    receipt.parent.mkdir(parents=True)
    receipt.write_text(json.dumps({'source': {'tap': 'homebrew/core', 'spec': 'stable', 'versions': {'stable': '2026.10.1'}}}))
    report = Scan().run()
    assert not report['incomplete'] and len(report['records']) == 6
    assert sum(r['advisories'][0]['state'] == 'unresolved' for r in report['records']) == 4
    assert all(r['assessment'] == 'review_required' for r in report['records'])


def test_no_execution_or_environment_disclosure(tmp_path):
    marker = tmp_path/'executed'
    data = {'services': {'app': {'image': 'ghcr.io/gitroomhq/postiz-app:2.25.2', 'command': f'touch {marker}', 'environment': {'TOKEN': 'fixture-secret-do-not-emit'}}}}
    (tmp_path/'compose.json').write_text(json.dumps(data))
    result = subprocess.run([sys.executable, 'tools/supply_inventory.py', '--root', str(tmp_path)], capture_output=True, text=True, check=True)
    assert json.loads(result.stdout)['records']
    assert not marker.exists() and 'fixture-secret-do-not-emit' not in result.stdout


def test_read_limits_symlinks_and_node_bound(tmp_path):
    (tmp_path/'compose.yaml').write_text('x'*262145)
    assert Scan().run([tmp_path])['incomplete']
    (tmp_path/'compose.yaml').unlink()
    target = tmp_path/'payload'
    target.write_text('services: {}')
    (tmp_path/'compose.yaml').symlink_to(target)
    assert Scan().run([tmp_path])['incomplete']
    (tmp_path/'compose.yaml').unlink()
    report = scan_text(tmp_path, 'compose.json', json.dumps({'services': {}, 'noise': list(range(10001))}))
    assert report['incomplete'] and not report['records']


def test_go_directive_whitespace_and_quoted_requirements(tmp_path):
    report = scan_text(tmp_path, 'go.mod', 'require\tgithub.com/labstack/echo/v4\tv4.16.0\n')
    assert report['records'][0]['version'] == '4.16.0'
    report = scan_text(tmp_path, 'go.mod', 'require\tgithub.com/labstack/echo/v4\tv4.16.0\nreplace\tgithub.com/labstack/echo/v4 => ../fork')
    assert report['records'][0]['version'] == 'unknown'
    report = scan_text(tmp_path, 'go.mod', 'require "github.com/labstack/echo/v4" v4.16.0')
    assert report['incomplete'] and not report['records']


@pytest.mark.parametrize('name', ['cloudflared', 'cloudflare-warp', 'cursor-browser', 'github.com/labstack/echo/v4', 'postiz', 'fleet', 'zitadel'])
def test_product_names_are_not_cross_ecosystem_aliases(tmp_path, name):
    report = scan_text(tmp_path, 'package.json', json.dumps({'name': name, 'version': '1.0.0'}))
    assert not report['records']


def test_unrelated_display_names_and_wrong_formula_taps(tmp_path):
    app = tmp_path/'Cursor.app/Contents'
    app.mkdir(parents=True)
    (app/'Info.plist').write_bytes(plistlib.dumps({'CFBundleIdentifier': 'example.unrelated', 'CFBundleShortVersionString': '3.0.0'}))
    receipt = tmp_path/'cloudflared/2026.10.2/INSTALL_RECEIPT.json'
    receipt.parent.mkdir(parents=True)
    receipt.write_text(json.dumps({'source': {'tap': 'custom/tap', 'spec': 'stable', 'versions': {'stable': '2026.10.2'}}}))
    report = Scan().run([tmp_path])
    assert len(report['records']) == 1 and report['records'][0]['name'] == 'cloudflared'
    assert report['records'][0]['advisories'][0]['state'] == 'unresolved'
