import pytest
from server.supply_chain import assess, command_findings
from server.engine import Engine
from server.models import EventInput
from server.store import Store

@pytest.mark.parametrize('version', ['8.2.34','8.3.35','8.4.26','8.5.11'])
def test_php_each_branch(version):
    assert assess('php',version).policy == 'vulnerable-runtime'

@pytest.mark.parametrize('version', ['8.2.35','8.3.36','8.4.27','8.5.12'])
def test_php_fixed_branch(version):
    assert assess('php',version) is None

@pytest.mark.parametrize('version', ['8.3','8.3.6-0ubuntu0.24.04.13','8.4.27-1','latest','8.6.0RC3'])
def test_unknown_is_not_a_vulnerability_claim(version):
    assert assess('php',version).policy == 'unresolved-runtime-version'

@pytest.mark.parametrize('command', [
    'npm install @subql/common@5.8.3', 'pnpm add @subql/common@5.8.3', 'phpenv install 8.4.26',
    'pip install litellm==1.107.0', 'python3.12 -m pip install "litellm[proxy]==1.82.8"',
    'uv pip install litellm==1.82.7', 'echo ok && pip3 install litellm==1.107.0',
    'mise install php@8.4.26', 'asdf install php 8.2.34', 'phpenv install php 8.5.11',
])
def test_literal_install_blocked(tmp_path,command):
    r=Engine(Store(tmp_path/'audit.db')).evaluate(EventInput(session_id='s',action='command',app='test',content=command))
    assert r.decision.action=='block'
    assert command not in str(r.model_dump())

@pytest.mark.parametrize('command', [
    'echo "pip install litellm==1.107.0"', 'pip show litellm',
    'pip install litellm==1.106.2', 'mise install php@8.4.27',
    'pip uninstall litellm==1.107.0', 'cat README.md',
])
def test_benign_commands(command):
    assert command_findings(command)==[]


def test_inventory_reads_metadata_without_executing(tmp_path):
    from tools.supply_inventory import inventory
    metadata=tmp_path/'litellm-1.107.0.dist-info'/'METADATA'
    metadata.parent.mkdir()
    metadata.write_text('Name: litellm\nVersion: 1.107.0\n')
    (tmp_path/'sitecustomize.py').write_text('raise RuntimeError("must not import")')
    (tmp_path/'package.json').write_text('{"name":"@subql/common","version":"5.8.3","scripts":{"install":"exit 9"}}')
    results,incomplete=inventory(tmp_path)
    assert not incomplete
    assert len(results)==2
    assert all(r['finding']['policy']=='known-malicious-package' for r in results)


def test_inventory_rejects_malformed_and_symlink_metadata(tmp_path):
    from tools.supply_inventory import inventory
    (tmp_path/'package.json').symlink_to(tmp_path/'missing')
    results,incomplete=inventory(tmp_path)
    assert not results and incomplete


def test_review_snapshot_is_not_universal_safety():
    assert assess('unrecognized-package','0.1') is None
    assert assess('php','7.4.33').policy=='unsupported-runtime'
    assert assess('@subql/common','5.8.3-onf-rt1') is None
