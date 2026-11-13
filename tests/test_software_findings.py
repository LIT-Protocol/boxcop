import json

from server.software_findings import findings_report, agent_prompt
from server import software_inventory


def report():
    return dict(schema='boxcop.software-inventory.v2', generated_at='2026-11-12',
                incomplete=True, roots=[dict(path='/missing', state='absent')],
                issues=['scan_limit_reached'], coverage='selected metadata',
                records=[dict(id='one', name='example', version='1', path='/tmp/example',
                              advisories=[dict(state='unresolved', id='review'),
                                          dict(state='fixed_for_advisory', id='fixed')]),
                         dict(id='two', name='other', version='2', path='/tmp/other',
                              advisories=[dict(state='fixed_for_advisory', id='fixed')])])


def test_findings_keep_uncertainty_and_group_actions_without_mutating():
    original = report()
    result = findings_report(original)
    assert result['finding_count'] == 1
    assert result['incomplete'] and result['roots'] == original['roots']
    assert result['issues'] == original['issues']
    assert result['records'][0]['advisories'] == [dict(state='unresolved', id='review')]
    assert result['fix_plan'][0]['adapter'] == 'review'
    assert len(original['records'][0]['advisories']) == 2


def test_empty_findings_preserve_incomplete_coverage():
    original = report()
    original['records'] = []
    result = findings_report(original)
    assert result['finding_count'] == 0 and result['fix_plan'] == []
    assert result['incomplete']
    assert 'does\nnot mean safe' in agent_prompt(result)


def test_cli_formats_scan_requested_root(monkeypatch, capsys, tmp_path):
    from server import software_remediation
    roots = []
    monkeypatch.setattr(software_inventory.Scan, 'run', lambda self, requested: roots.extend(requested) or report())
    monkeypatch.setattr(software_remediation, 'load_results', lambda: [])
    assert software_inventory.main(['--root', str(tmp_path), '--format', 'findings']) == 0
    result = json.loads(capsys.readouterr().out)
    assert roots == [tmp_path]
    assert result['schema'] == 'boxcop.software-findings.v1'
    assert result['finding_count'] == 1
    assert software_inventory.main(['--root', str(tmp_path), '--format', 'agent']) == 0
    assert 'BEGIN UNTRUSTED SCAN EVIDENCE' in capsys.readouterr().out


def test_fix_plan_keeps_fixed_copies_as_cleanup_evidence():
    from server.exposure_advisories import findings
    from server.software_remediation import items
    original = report()
    original['records'] = [
        dict(id=version, name='node', version=version,
             path=f'/opt/homebrew/Cellar/node/{version}/INSTALL_RECEIPT.json',
             kind='package_metadata', advisories=findings('node', version))
        for version in ('26.0.0', '26.12.1')
    ]
    expected = items(original)
    assert expected[0]['adapter'] == 'homebrew_cleanup'
    result = findings_report(original)
    assert result['fix_plan'] == expected
    assert len(result['records']) == 1


def test_cache_remains_full_inventory(monkeypatch, capsys):
    from server import software_remediation
    saved = []
    monkeypatch.setattr(software_inventory.Scan, 'run', lambda self, roots: report())
    monkeypatch.setattr(software_remediation, 'load_results', lambda: [])
    monkeypatch.setattr(software_inventory, 'save_report', lambda value, directory: saved.append(value))
    software_inventory.main(['--cache', '--format', 'findings'])
    assert saved[0]['schema'] == 'boxcop.software-inventory.v2'
    assert len(saved[0]['records']) == 2
    assert len(json.loads(capsys.readouterr().out)['records']) == 1
