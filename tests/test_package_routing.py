import json

import pytest

from server.package_routing import BLOCK, REGISTRY, enable, disable, status


def test_routing_preserves_credentials_scoped_registry_and_unrelated_edits(tmp_path):
    home, state = tmp_path / 'home', tmp_path / 'state'
    home.mkdir()
    config = home / '.npmrc'
    original = '@private:registry=https://registry.example/\n//registry.example/:_authToken=synthetic-secret\n'
    config.write_text(original)
    enable(home, state)
    assert status(home)['configured']
    assert original in config.read_text()
    assert 'synthetic-secret' not in (state / 'npm-routing.json').read_text()
    config.write_text(config.read_text() + 'fund=false\n')
    disable(home, state)
    assert config.read_text() == original + 'fund=false\n'


@pytest.mark.parametrize('original', ['', 'audit=false', 'audit=false\n'])
def test_exact_recovery_and_idempotent_enable(tmp_path, original):
    config = tmp_path / '.npmrc'
    config.write_text(original)
    state = tmp_path / 'state'
    enable(tmp_path, state)
    enable(tmp_path, state)
    assert config.read_text().count(BLOCK) == 1
    disable(tmp_path, state)
    assert config.read_text() == original


def test_created_file_removed_and_custom_defaults_not_overwritten(tmp_path):
    state = tmp_path / 'state'
    enable(tmp_path, state)
    disable(tmp_path, state)
    assert not (tmp_path / '.npmrc').exists()
    for original in ['registry=https://private.example/\n', '_authToken=synthetic-secret\n']:
        (tmp_path / '.npmrc').write_text(original)
        with pytest.raises(ValueError):
            enable(tmp_path, state)
        assert (tmp_path / '.npmrc').read_text() == original


def test_edited_block_and_symlink_require_explicit_recovery(tmp_path):
    state = tmp_path / 'state'
    enable(tmp_path, state)
    config = tmp_path / '.npmrc'
    config.write_text(config.read_text().replace(REGISTRY, 'https://custom.example/'))
    with pytest.raises(ValueError):
        disable(tmp_path, state)
    config.unlink()
    config.symlink_to(tmp_path / 'other')
    with pytest.raises(ValueError):
        enable(tmp_path, state)


def test_disable_restores_routing_before_launchd_failure(tmp_path, monkeypatch, capsys):
    from tools.package_service import management_main
    monkeypatch.setattr('tools.package_service.Path.home', lambda: tmp_path)
    monkeypatch.setattr('tools.package_service.state_directory', lambda: tmp_path / 'state')
    enable(tmp_path, tmp_path / 'state')
    plist = tmp_path / 'Library/LaunchAgents/com.boxcop.package-protection.plist'
    plist.parent.mkdir(parents=True)
    plist.write_text('fixture')
    def failure(*args, **kwargs):
        raise OSError('launchctl unavailable')
    monkeypatch.setattr('tools.package_service.subprocess.run', failure)
    assert management_main(['disable']) == 1
    assert not status(tmp_path)['configured']
    assert json.loads(capsys.readouterr().out)['summary'].startswith('Package protection setup failed')
