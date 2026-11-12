"""Portable packaging behavior; these do NOT claim macOS compilation."""
import importlib.util
import json
import os
from pathlib import Path
import plistlib
import subprocess
import sys

import pytest

ROOT = Path(__file__).resolve().parents[1]
MAC = ROOT / "desktop" / "macos"
BUILD = MAC / "scripts" / "build_app.py"


def load_builder():
    assert BUILD.is_file(), "Native bundle builder is not implemented"
    spec = importlib.util.spec_from_file_location("boxcop_bundle_builder", BUILD)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_builder_rejects_linux_before_creating_output(tmp_path):
    builder = load_builder()
    output = tmp_path / "must-not-exist"
    with pytest.raises(builder.BuildError, match="macOS"):
        builder.build(output, host_system="Linux")
    assert not output.exists()


def test_bundle_metadata_has_real_native_lifecycle_and_no_elevated_permissions():
    path = MAC / "Resources" / "Info.plist"
    assert path.is_file(), "App bundle metadata is missing"
    data = plistlib.loads(path.read_bytes())
    assert data["CFBundleIdentifier"] == "local.sentinel.endpoint"
    assert data["CFBundleExecutable"] == "BoxCop"
    assert data["CFBundlePackageType"] == "APPL"
    assert data["LSUIElement"] is True
    assert data["LSMinimumSystemVersion"] == "14.0"
    assert "NSScreenCaptureUsageDescription" not in data
    assert "NSMicrophoneUsageDescription" not in data
    assert "NSCameraUsageDescription" not in data


def test_child_environment_drops_import_injection_and_development_overrides():
    builder = load_builder()
    env = builder.child_environment({"PATH": "/usr/bin", "PYTHONPATH": "/bad", "PYTHONHOME": "/bad", "BOXCOP_ENGINE_EXECUTABLE": "/bad", "BOXCOP_ENGINE_ARGUMENTS": "[]", "PYTHONINSPECT": "1", "DYLD_INSERT_LIBRARIES": "/bad", "LD_PRELOAD": "/bad"})
    assert env["PATH"] == "/usr/bin"
    assert not any(key.startswith(("PYTHON", "BOXCOP_ENGINE_", "DYLD_", "LD_")) for key in env)


def test_package_channel_is_optional_and_embeds_only_public_pin(tmp_path, monkeypatch):
    import base64
    builder = load_builder()
    monkeypatch.delenv('BOXCOP_PACKAGE_FEED_URL', raising=False)
    monkeypatch.delenv('BOXCOP_PACKAGE_FEED_PUBLIC_KEY_BASE64', raising=False)
    assert builder.prepare_package_channel(tmp_path) == []
    monkeypatch.setenv('BOXCOP_PACKAGE_FEED_URL', 'https://feed.example/v1/policy.json')
    with pytest.raises(builder.BuildError):
        builder.prepare_package_channel(tmp_path)
    public = base64.b64encode(b'p' * 32).decode()
    monkeypatch.setenv('BOXCOP_PACKAGE_FEED_PUBLIC_KEY_BASE64', public)
    options = builder.prepare_package_channel(tmp_path)
    assert options[0] == '--add-data'
    channel = json.loads((tmp_path / 'channel.json').read_text())
    assert channel['public_key'] == public
    assert set(channel) == {'schema', 'url', 'public_key', 'minimum_sequence'}


def test_timestamp_retry_never_downgrades_signing_or_swallows_failure(monkeypatch):
    builder = load_builder()
    calls = []
    def fail(command, **kwargs):
        calls.append(command)
        raise subprocess.CalledProcessError(1, command)
    monkeypatch.setattr(builder.subprocess, 'run', fail)
    monkeypatch.setattr(builder.time, 'sleep', lambda _: None)
    command = ['/usr/bin/codesign', '--sign', 'fixture-identity', '--timestamp', '/fixture']
    with pytest.raises(subprocess.CalledProcessError):
        builder.run(command)
    assert calls == [command, command, command]


def test_existing_output_never_overwritten(tmp_path):
    builder = load_builder()
    app = tmp_path / "BoxCop.app"
    app.mkdir()
    marker = app / "keep"
    marker.write_text("existing installation")
    with pytest.raises(builder.BuildError, match="exists"):
        builder.validate_output(tmp_path)
    assert marker.read_text() == "existing installation"


@pytest.mark.parametrize("name", ["BoxCop.dmg", "BoxCop.zip"])
def test_existing_archive_never_overwritten(tmp_path, name):
    builder = load_builder()
    archive = tmp_path / name
    archive.write_text("previous build")
    with pytest.raises(builder.BuildError, match="exists"):
        builder.validate_output(tmp_path)
    assert archive.read_text() == "previous build"


def test_symlink_output_is_rejected(tmp_path):
    builder = load_builder()
    outside = tmp_path / "outside"
    outside.mkdir()
    linked = tmp_path / "linked"
    linked.symlink_to(outside, target_is_directory=True)
    with pytest.raises(builder.BuildError, match="symlink"):
        builder.validate_output(linked)


def test_bundle_links_cannot_escape(tmp_path):
    builder = load_builder()
    bundle = tmp_path / "BoxCop.app"
    bundle.mkdir()
    (bundle / "escape").symlink_to("/usr/bin/python3")
    with pytest.raises(builder.BuildError, match="outside"):
        builder.check_bundle_links(bundle)


def test_internal_bundle_links_allowed(tmp_path):
    builder = load_builder()
    bundle = tmp_path / "BoxCop.app"
    bundle.mkdir()
    (bundle / "resource").write_text("resource")
    (bundle / "link").symlink_to("resource")
    builder.check_bundle_links(bundle)


def test_build_runtime_dependencies_are_hash_locked_and_small():
    path = MAC / "requirements-build.txt"
    assert path.is_file(), "Pinned bundler requirements missing"
    text = path.read_text()
    for name in ("pydantic", "pyinstaller", "macholib", "pyinstaller-hooks-contrib"):
        assert name + "==" in text
    assert "--hash=sha256:" in text
    for unnecessary in ("fastapi==", "uvicorn==", "onnxruntime==", "httpx==", "numpy=="):
        assert unnecessary not in text


def test_fresh_checkout_build_always_provisions_classifier(tmp_path, monkeypatch):
    builder = load_builder()
    monkeypatch.setattr(builder, 'ROOT', tmp_path / 'fresh-checkout')
    calls = []
    monkeypatch.setattr(builder, 'run', lambda command, **kwargs: calls.append(command))
    work = tmp_path / 'build'
    options = builder.prepare_classifier('python', work, {})
    assert not (builder.ROOT / '.local/models/minilm').exists()
    assert '--require-hashes' in calls[0]
    assert calls[0][-1] == MAC / 'requirements-classifier.txt'
    assert calls[1] == ['python', builder.ROOT / 'scripts/setup_model.py', '--model-dir', work / 'models/minilm']
    assert str(work / 'models/minilm') + ':models/minilm' in options
    for dependency in ('onnxruntime', 'tokenizers'):
        assert dependency in options


def test_failed_classifier_provisioning_cannot_make_rules_only_package(tmp_path, monkeypatch):
    builder = load_builder()
    def fail_setup(command, **kwargs):
        if '--model-dir' in command:
            raise subprocess.CalledProcessError(1, command)
    monkeypatch.setattr(builder, 'run', fail_setup)
    with pytest.raises(subprocess.CalledProcessError):
        builder.prepare_classifier('python', tmp_path, {})


@pytest.mark.parametrize('returncode,payload', [(1, {'ready': False}), (0, {'ready': False}), (0, {'ready': True})])
def test_frozen_smoke_rejects_failed_or_incomplete_classifier_report(tmp_path, monkeypatch, returncode, payload):
    spec = importlib.util.spec_from_file_location('smoke_engine', MAC / 'scripts/smoke_engine.py')
    smoke = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(smoke)
    monkeypatch.setattr(smoke.subprocess, 'run', lambda *args, **kwargs:
                        subprocess.CompletedProcess(args[0], returncode, json.dumps(payload), ''))
    with pytest.raises(RuntimeError, match='classifier'):
        smoke.smoke_classifier(tmp_path / 'engine', tmp_path, {})


def test_engine_launcher_does_not_start_http_or_import_model():
    entry = MAC / "scripts" / "engine_entry.py"
    assert entry.is_file(), "Frozen helper launcher missing"
    source = entry.read_text()
    assert "from server.desktop import main" in source
    assert "server.app" not in source
    assert "server.semantic" not in source
    assert "uvicorn" not in source


def test_source_launcher_runs_isolated_from_unrelated_directory(tmp_path):
    """Development path for `swift run`: real interpreter in isolated mode, no PYTHONPATH."""
    entry = MAC / "scripts" / "engine_entry.py"
    work = tmp_path / "unrelated-cwd"
    work.mkdir()
    requests = [{"version": 1, "id": "status", "op": "status"}, {"version": 1, "id": "stop", "op": "shutdown"}]
    result = subprocess.run([sys.executable, "-I", "-B", str(entry), "--data-dir", str(tmp_path / "data")],
                            cwd=work, env={"PATH": "/usr/bin:/bin", "HOME": str(tmp_path)},
                            input="".join(json.dumps(item) + "\n" for item in requests),
                            capture_output=True, text=True, timeout=30)
    assert result.returncode == 0, "Source launcher could not start the real desktop service"
    responses = [json.loads(line) for line in result.stdout.splitlines()]
    assert [item["id"] for item in responses] == ["status", "stop"]
    assert all(item["ok"] is True for item in responses)
    assert responses[0]["result"]["network_listener"] is False


def test_bundle_validation_rejects_missing_engine(tmp_path):
    builder = load_builder()
    bundle = tmp_path / "BoxCop.app"
    (bundle / "Contents" / "MacOS").mkdir(parents=True)
    (bundle / "Contents" / "MacOS" / "BoxCop").write_bytes(b"\xcf\xfa\xed\xfe")
    with pytest.raises(builder.BuildError, match="engine"):
        builder.validate_bundle_layout(bundle)


def test_bundle_validation_rejects_linux_binary(tmp_path):
    builder = load_builder()
    bundle = tmp_path / "BoxCop.app"
    native = bundle / "Contents" / "MacOS" / "BoxCop"
    helper = bundle / "Contents" / "Resources" / "engine" / "boxcop-engine"
    for file in (native, helper):
        file.parent.mkdir(parents=True, exist_ok=True)
        file.write_bytes(b"\x7fELF")
        file.chmod(0o755)
    with pytest.raises(builder.BuildError, match="Mach-O"):
        builder.validate_bundle_layout(bundle)


def test_build_command_on_this_linux_host_fails_honestly(tmp_path):
    if sys.platform != "linux":
        pytest.skip("Linux-only guard test")
    assert BUILD.is_file(), "Native builder missing"
    result = subprocess.run([sys.executable, str(BUILD), "--output", str(tmp_path / "out")], capture_output=True, text=True, timeout=5)
    assert result.returncode != 0
    assert "macOS" in result.stderr
    assert not (tmp_path / "out").exists()

def test_bundle_signing_uses_selected_identity_for_all_nested_code(tmp_path, monkeypatch):
    builder = load_builder()
    bundle = tmp_path / "BoxCop.app"
    binary = bundle / "Contents/MacOS/BoxCop"
    binary.parent.mkdir(parents=True)
    binary.write_bytes(b"\xcf\xfa\xed\xfe")
    calls = []
    monkeypatch.setattr(builder, "run", lambda command: calls.append(command))
    builder.sign_bundle(bundle, identity="fixture-certificate")
    signed = [call for call in calls if "--sign" in call]
    assert len(signed) == 2
    assert all(call[call.index("--sign") + 1] == "fixture-certificate" for call in signed)
    assert "--verify" in calls[-1]


def test_beta_signing_hardens_nested_code_and_timestamps_certificate(tmp_path, monkeypatch):
    builder = load_builder()
    bundle = tmp_path / 'BoxCop.app'
    binary = bundle / 'Contents/MacOS/BoxCop'
    binary.parent.mkdir(parents=True)
    binary.write_bytes(b'\xcf\xfa\xed\xfe')
    calls = []
    monkeypatch.setattr(builder, 'run', lambda command: calls.append(command))
    builder.sign_bundle(bundle, identity='fixture-certificate', hardened=True)
    for command in calls:
        if '--sign' in command:
            assert '--timestamp' in command and '--timestamp=none' not in command
            assert command[command.index('--options') + 1] == 'runtime'


def test_limited_development_rejects_embedded_system_extension(tmp_path):
    builder = load_builder()
    (tmp_path / 'Contents/Library/SystemExtensions').mkdir(parents=True)
    with pytest.raises(builder.BuildError, match='system extensions'):
        builder.verify_limited_development_bundle(tmp_path)


@pytest.mark.parametrize('entitlement', ['com.apple.developer.endpoint-security.client',
    'com.apple.developer.networking.networkextension', 'com.apple.security.get-task-allow'])
def test_limited_development_rejects_restricted_nested_signature(tmp_path, monkeypatch, entitlement):
    builder = load_builder()
    binary = tmp_path / 'nested'
    binary.write_bytes(b'\xcf\xfa\xed\xfe')
    monkeypatch.setattr(builder.subprocess, 'run', lambda *args, **kwargs:
                        subprocess.CompletedProcess(args[0], 0, stdout=plistlib.dumps({entitlement: True})))
    with pytest.raises(builder.BuildError, match='entitlement'):
        builder.verify_limited_development_bundle(tmp_path)


@pytest.mark.parametrize("suffix", [".app", ".dmg"])
def test_rejected_notarization_never_staples_or_assesses(tmp_path, monkeypatch, suffix):
    builder = load_builder()
    commands = []
    monkeypatch.setattr(builder, 'run', lambda command: commands.append(command))
    monkeypatch.setattr(builder.subprocess, 'run', lambda *args, **kwargs:
                        subprocess.CompletedProcess(args[0], 0, stdout='{"status":"Invalid","id":"fixture"}'))
    with pytest.raises(builder.BuildError, match='not accepted'):
        builder.notarize(tmp_path / ('BoxCop' + suffix), tmp_path, 'fixture-profile')
    assert not any('stapler' in command or '--assess' in command for command in commands)
    receipt = 'dmg-notary-receipt.json' if suffix == '.dmg' else 'notary-receipt.json'
    assert json.loads((tmp_path / receipt).read_text())['status'] == 'Invalid'


def test_dmg_notarization_submits_image_and_checks_gatekeeper(tmp_path, monkeypatch):
    builder = load_builder()
    image = tmp_path / "BoxCop.dmg"
    commands = []
    submissions = []
    monkeypatch.setattr(builder, "run", lambda command: commands.append(command))
    def submit(command, **kwargs):
        submissions.append(command)
        return subprocess.CompletedProcess(command, 0, stdout='{"status":"Accepted","id":"dmg-id"}')
    monkeypatch.setattr(builder.subprocess, "run", submit)
    assert builder.notarize(image, tmp_path, "fixture-profile") == "dmg-id"
    assert submissions[0][3] == str(image)
    assert ["xcrun", "stapler", "staple", image] in commands
    assert ["xcrun", "stapler", "validate", image] in commands
    assert commands[-1] == ["/usr/sbin/spctl", "--assess", "--type", "open",
                            "--context", "context:primary-signature", "--verbose=2", image]
    assert not any("/usr/bin/ditto" in command for command in commands)


def png_size(path):
    header = path.read_bytes()[:24]
    assert header[:8] == b"\x89PNG\r\n\x1a\n"
    return int.from_bytes(header[16:20], "big"), int.from_bytes(header[20:24], "big")


def test_dmg_installer_window_is_laid_out_for_drag_to_applications(tmp_path):
    builder = load_builder()
    settings = builder.dmg_settings(tmp_path / "BoxCop.app")
    width, height = builder.DMG_WINDOW
    assert settings["window_rect"][1] == (width, height)
    assert settings["symlinks"] == {"Applications": "/Applications"}
    assert settings["files"] == [str(tmp_path / "BoxCop.app")]
    assert set(settings["icon_locations"]) == {"BoxCop.app", "Applications"}
    assert not any(settings[key] for key in ("show_toolbar", "show_pathbar", "show_sidebar", "show_status_bar", "show_tab_view"))
    half = settings["icon_size"] / 2
    app, applications = settings["icon_locations"]["BoxCop.app"], settings["icon_locations"]["Applications"]
    assert app[1] == applications[1] and app[0] < applications[0]
    for x, y in (app, applications):
        assert half <= x <= width - half and half <= y <= height - half - 30, "Icon and label must fit the window"
    background = Path(settings["background"])
    assert png_size(background) == (width, height)
    assert png_size(background.with_name("background@2x.png")) == (2 * width, 2 * height)
    assert Path(settings["icon"]).is_file()
    # SetFile's hidden-extension flag adds FinderInfo to the bundle, which strict codesign rejects.
    assert not settings.get("hide_extensions")


def test_dmg_build_tools_are_hash_locked():
    text = (MAC / "requirements-dmg.txt").read_text()
    for name in ("dmgbuild==", "ds-store==", "mac-alias=="):
        assert name in text
    assert text.count("--hash=sha256:") == 3


def test_create_dmg_writes_loadable_settings_and_checks_image(tmp_path, monkeypatch):
    builder = load_builder()
    commands = []
    monkeypatch.setattr(builder, "run", lambda command: commands.append(command))
    checked = []
    monkeypatch.setattr(builder, "verify_dmg_contents", lambda image, mount: checked.append(image))
    image = builder.create_dmg(tmp_path / "BoxCop.app", tmp_path, "fixture-python")
    assert commands[0] == ["fixture-python", "-m", "dmgbuild", "-s", tmp_path / "dmg-settings.py", "BoxCop", image]
    loaded = {}
    exec((tmp_path / "dmg-settings.py").read_text(), {}, loaded)
    assert loaded == builder.dmg_settings(tmp_path / "BoxCop.app")
    assert checked == [image]
    assert not any("--sign" in command for command in commands), "Ad-hoc builds leave the image unsigned"


def test_notarization_requires_signed_distribution_before_building(tmp_path):
    builder = load_builder()
    with pytest.raises(builder.BuildError, match='Developer ID'):
        builder.build(tmp_path / 'out', host_system='Darwin', profile='distribution', notary_profile='fixture')
    assert not (tmp_path / 'out').exists()


@pytest.mark.parametrize('case', ['success', 'stable', 'custom_profiles', 'missing_profiles', 'legacy_profile', 'invalid_channel', 'invalid_version', 'empty_version', 'multiple', 'missing', 'ad_hoc', 'wrong_identity', 'notary_failure'])
def test_distribution_wrapper_requires_signing_and_notarization(tmp_path, case):
    """Exercise shell argument forwarding and fail-closed preflight without Apple credentials."""
    fake_bin = tmp_path / 'fake tools'
    fake_bin.mkdir()
    fingerprint = 'A' * 40
    identity_output = f'  1) {fingerprint} "Developer ID Application: Fixture (TEAM)"\n'
    if case == 'multiple':
        identity_output += f'  2) {"B" * 40} "Developer ID Application: Other (TEAM)"\n'
    if case == 'missing':
        identity_output = '  0 valid identities found\n'
    capture = tmp_path / 'arguments.json'
    scripts = {
        'date': '#!/bin/sh\nprintf "1793748000\\n"\n',
        'cmake': '#!/bin/sh\nexit 0\n',
        'uname': '#!/bin/sh\nprintf "Darwin\\n"\n',
        'security': '#!/bin/sh\ncat <<\'IDENTITIES\'\n' + identity_output + 'IDENTITIES\n',
        'xcrun': '#!/bin/sh\nexit ' + ('1' if case == 'notary_failure' else '0') + '\n',
        'python3.12': f'#!{sys.executable}\nimport json,sys\nfrom pathlib import Path\n'
                      f'if sys.argv[1] != "-c": Path({str(capture)!r}).write_text(json.dumps(sys.argv[1:]))\n',
    }
    for name, content in scripts.items():
        path = fake_bin / name
        path.write_text(content)
        path.chmod(0o755)
    env = {k: v for k, v in os.environ.items() if not k.startswith('BOXCOP_')}
    env['PATH'] = str(fake_bin) + os.pathsep + env['PATH']
    # Isolate the wrapper from the developer's real profiles.
    env['HOME'] = str(tmp_path / 'test-home')
    if case == 'ad_hoc': env['BOXCOP_SIGNING_IDENTITY'] = '-'
    if case == 'wrong_identity': env['BOXCOP_SIGNING_IDENTITY'] = 'C' * 40
    extra = []
    if case == 'stable': env['BOXCOP_CHANNEL'] = 'stable'
    if case == 'invalid_channel': env['BOXCOP_CHANNEL'] = 'other'
    if case == 'legacy_profile': env['BOXCOP_PROFILE'] = 'beta'
    if case != 'missing_profiles':
        for kind in ['app', 'network']:
            if case != 'custom_profiles':
                filename = 'Allay_Developer_ID.provisionprofile' if kind == 'app' else 'Allay_Network_Developer_ID.provisionprofile'
                path = Path(env['HOME']) / '.sentinel-lab/profiles' / filename
                path.parent.mkdir(parents=True, exist_ok=True)
            else:
                path = tmp_path / (kind + ' with spaces.provisionprofile')
                env['BOXCOP_' + kind.upper() + '_PROFILE'] = str(path)
            path.write_bytes(b'fixture')
            extra += ['--' + kind + '-profile', str(path)]
        if case == 'custom_profiles':
            env['BOXCOP_EXTENSION_VERSION'] = '42'
        elif case in {'invalid_version', 'empty_version'}:
            env['BOXCOP_EXTENSION_VERSION'] = '0' if case == 'invalid_version' else ''
        extra += ['--extension-version', env.get('BOXCOP_EXTENSION_VERSION', '1793748000')]
    output = tmp_path / 'release with spaces'
    result = subprocess.run(['bash', str(ROOT / 'build.sh'), str(output)], cwd=tmp_path,
                            env=env, capture_output=True, text=True, timeout=10)
    if case in {'success', 'stable', 'custom_profiles'}:
        assert result.returncode == 0, result.stderr
        assert json.loads(capture.read_text()) == [str(BUILD), '--profile', 'distribution', '--channel', env.get('BOXCOP_CHANNEL', 'beta'), '--output', str(output),
                                                   '--signing-identity', fingerprint, '--notary-profile', 'sentinel-beta'] + extra
    else:
        assert result.returncode != 0
        assert not capture.exists(), 'Never invoke builder after failed distribution preflight'


def test_protected_signing_applies_extension_entitlements_before_app(tmp_path, monkeypatch):
    builder = load_builder()
    bundle = tmp_path / 'BoxCop.app'
    extension = bundle / 'Contents/Library/SystemExtensions/Filter.systemextension'
    binary = extension / 'Contents/MacOS/Filter'
    binary.parent.mkdir(parents=True)
    binary.write_bytes(b'\xcf\xfa\xed\xfe')
    calls = []
    def capture(command):
        entitlements = None
        if '--entitlements' in command:
            entitlements = plistlib.loads(Path(command[command.index('--entitlements') + 1]).read_bytes())
        calls.append((command, entitlements))
    monkeypatch.setattr(builder, 'run', capture)
    builder.sign_bundle(bundle, identity='fixture', hardened=True,
                        provisioned={bundle: {'app': True}, extension: {'filter': True}})
    signed = [(command[-1], entitlements) for command, entitlements in calls if '--sign' in command]
    assert signed == [(binary, None), (extension, {'filter': True}), (bundle, {'app': True})]
    assert '--verify' in calls[-1][0]


def test_notarization_uses_explicit_ci_keychain(tmp_path, monkeypatch):
    builder = load_builder()
    commands = []
    monkeypatch.setenv('BOXCOP_KEYCHAIN_PATH', '/temporary/keychain with spaces')
    monkeypatch.setattr(builder, 'run', lambda command: None)
    def submit(command, **kwargs):
        commands.append(command)
        return subprocess.CompletedProcess(command, 0, stdout='{"status":"Accepted","id":"fixture"}')
    monkeypatch.setattr(builder.subprocess, 'run', submit)
    builder.notarize(tmp_path / 'BoxCop.dmg', tmp_path, 'fixture')
    assert commands[0][-2:] == ['--keychain', '/temporary/keychain with spaces']


@pytest.mark.parametrize('channel', ['beta', 'stable'])
def test_every_distribution_channel_requires_signing_and_profiles(tmp_path, channel, monkeypatch):
    monkeypatch.syspath_prepend(str(MAC / "scripts"))
    builder = load_builder()
    with pytest.raises(builder.BuildError, match='Distribution requires'):
        builder.build(tmp_path / 'out', host_system='Darwin', profile='distribution', channel=channel)
    with pytest.raises(builder.BuildError, match='profiles'):
        builder.build(tmp_path / 'out', host_system='Darwin', profile='distribution', channel=channel,
                      signing_identity='A' * 40, notary_profile='fixture', extension_version='42')
    assert not (tmp_path / 'out').exists()


@pytest.mark.parametrize('profile', ['beta', 'protected'])
def test_ambiguous_legacy_build_profiles_are_rejected(tmp_path, profile):
    builder = load_builder()
    with pytest.raises(builder.BuildError, match='--channel'):
        builder.build(tmp_path / 'out', host_system='Darwin', profile=profile)
    assert not (tmp_path / 'out').exists()


def test_app_registers_team_invitation_scheme():
    info = plistlib.loads((MAC / "Resources" / "Info.plist").read_bytes())
    assert info["CFBundleURLTypes"] == [{
        "CFBundleURLName": "local.sentinel.endpoint.team-invitation",
        "CFBundleTypeRole": "Viewer",
        "CFBundleURLSchemes": ["boxcop"],
    }]
