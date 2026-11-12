#!/usr/bin/env python3
"""Build a real macOS-only application; Linux tests exercise guards, not signing."""
import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import platform
import plistlib
import re
import shutil
import subprocess
import sys
import tempfile
import time
import venv

MAC = Path(__file__).resolve().parents[1]
ROOT = MAC.parents[1]
MACHO = {b"\xfe\xed\xfa\xce", b"\xce\xfa\xed\xfe", b"\xfe\xed\xfa\xcf", b"\xcf\xfa\xed\xfe", b"\xca\xfe\xba\xbe", b"\xbe\xba\xfe\xca", b"\xca\xfe\xba\xbf", b"\xbf\xba\xfe\xca"}


class BuildError(RuntimeError):
    pass


def child_environment(source=None):
    source = os.environ if source is None else source
    return {key: value for key, value in source.items()
            if not key.startswith(("PYTHON", "BOXCOP_ENGINE_", "DYLD_", "LD_"))}


def validate_output(output):
    output = Path(output).absolute()
    for ancestor in (output, *output.parents):
        if ancestor.is_symlink():
            raise BuildError("Output path must not contain a symlink")
    if output.exists() and not output.is_dir():
        raise BuildError("Output exists and is not a directory")
    for name in ("BoxCop.app", "BoxCop.dmg", "BoxCop.zip", "build-evidence.json"):
        target = output / name
        if target.exists() or target.is_symlink():
            raise BuildError(f"Output already exists: {name}; choose a new output directory")
    return output


def check_bundle_links(bundle):
    bundle = Path(bundle).resolve()
    for path in bundle.rglob("*"):
        if path.is_symlink():
            try:
                target = path.resolve(strict=True)
            except (OSError, RuntimeError) as exc:
                raise BuildError("Broken or cyclic link in app bundle") from exc
            if not target.is_relative_to(bundle):
                raise BuildError("App bundle symlink points outside the bundle")


def is_macho(path):
    with path.open("rb") as file:
        return file.read(4) in MACHO


def validate_bundle_layout(bundle):
    bundle = Path(bundle)
    native = bundle / "Contents" / "MacOS" / "BoxCop"
    engine = bundle / "Contents" / "Resources" / "engine" / "boxcop-engine"
    for name, path in (("native executable", native), ("engine", engine)):
        if not path.is_file() or path.is_symlink():
            raise BuildError(f"Missing or invalid bundled {name}")
    for path in (native, engine):
        if not is_macho(path):
            raise BuildError("A bundle executable is not Mach-O; cross-platform renaming is not a Mac build")
        if not os.access(path, os.X_OK):
            raise BuildError("A bundle executable is not executable")
    check_bundle_links(bundle)
    return native, engine


def run(command, *, cwd=ROOT, env=None, timeout=600):
    # Commands contain build paths only, never live clipboard content.
    print("+", " ".join(map(str, command)), flush=True)
    arguments = list(map(str, command))
    # Apple's timestamp service can fail transiently. Retry the same mandatory
    # timestamped signing request; never downgrade to an untimestamped signature.
    attempts = 3 if arguments[0] == '/usr/bin/codesign' and '--timestamp' in arguments else 1
    for attempt in range(attempts):
        try:
            subprocess.run(arguments, cwd=cwd, env=env or child_environment(), check=True, timeout=timeout)
            return
        except subprocess.CalledProcessError:
            if attempt == attempts - 1:
                raise
            time.sleep(2 ** attempt)


def prepare_classifier(python, work, env):
    """Every profile includes the verified model; a fresh checkout is sufficient."""
    run([python, "-m", "pip", "install", "--require-hashes", "--only-binary=:all:",
         "-r", MAC / "requirements-classifier.txt"], env=env)
    model_dir = work / "models" / "minilm"
    # Setup is the only model download path. It bounds and verifies all artifacts
    # before publishing them. Never silently depend on a gitignored .local tree.
    run([python, ROOT / "scripts/setup_model.py", "--model-dir", model_dir], env=env)
    return ["--add-data", str(ROOT / "server/assets") + ":server/assets",
            "--collect-all", "onnxruntime", "--collect-all", "tokenizers",
            "--add-data", str(model_dir) + ":models/minilm"]


def prepare_package_channel(work):
    """Embed only a public trust pin. Missing configuration keeps activation off."""
    import importlib.util
    spec = importlib.util.spec_from_file_location('boxcop_package_channel', ROOT / 'server/package_channel.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    url = os.environ.get('BOXCOP_PACKAGE_FEED_URL')
    public = os.environ.get('BOXCOP_PACKAGE_FEED_PUBLIC_KEY_BASE64')
    if not url and not public:
        return []
    if not url or not public:
        raise BuildError('Package feed URL and public key must be configured together')
    value = module.validate_channel(dict(schema='boxcop.package-channel.v1', url=url, public_key=public,
        minimum_sequence=int(os.environ.get('BOXCOP_PACKAGE_FEED_MINIMUM_SEQUENCE', '1'))))
    path = work / 'channel.json'
    path.write_text(json.dumps(value))
    return ['--add-data', str(path) + ':server/assets/package-intelligence']


def sign_bundle(bundle, identity="-", *, hardened=False, provisioned=None):
    # Sign inner binaries first, then framework envelopes, then the app itself.
    options = ["--timestamp" if identity != "-" else "--timestamp=none"]
    if hardened:
        options += ["--options", "runtime"]
    paths = [path for path in bundle.rglob("*") if path.is_file() and not path.is_symlink() and is_macho(path)]
    for path in sorted(paths, key=lambda item: len(item.parts), reverse=True):
        run(["/usr/bin/codesign", "--force", "--sign", identity, *options, path])
    # Sparkle's Updater.app and XPC envelopes must be sealed before the framework.
    frameworks = [path for path in bundle.rglob("*") if path.suffix in {".framework", ".app", ".xpc"}
                  and path.is_dir() and not path.is_symlink()]
    for path in sorted(frameworks, key=lambda item: len(item.parts), reverse=True):
        run(["/usr/bin/codesign", "--force", "--sign", identity, *options, path])
    if provisioned:
        with tempfile.TemporaryDirectory(prefix="boxcop-entitlements-") as directory:
            for target, entitlements in sorted(provisioned.items(), key=lambda pair: len(pair[0].parts), reverse=True):
                path = Path(directory) / "entitlements.plist"
                path.write_bytes(plistlib.dumps(entitlements))
                run(["/usr/bin/codesign", "--force", "--sign", identity, *options, "--entitlements", path, target])
    else:
        run(["/usr/bin/codesign", "--force", "--sign", identity, *options, bundle])
    run(["/usr/bin/codesign", "--verify", "--deep", "--strict", "--verbose=2", bundle])


def embed_sparkle(scratch, contents):
    frameworks = list((scratch / "artifacts").glob("sparkle/Sparkle/Sparkle.xcframework/macos-*/Sparkle.framework"))
    if len(frameworks) != 1:
        raise BuildError("Expected exactly one resolved Sparkle macOS framework")
    destination = contents / "Frameworks/Sparkle.framework"
    shutil.copytree(frameworks[0], destination, symlinks=True)
    # BoxCop is not sandboxed and does not enable these optional XPC services.
    shutil.rmtree(destination / "Versions/B/XPCServices")
    (destination / "XPCServices").unlink(missing_ok=True)
    check_bundle_links(contents.parent)


def release_version(source=None):
    value = (os.environ if source is None else source).get("BOXCOP_VERSION")
    if value is not None and not re.fullmatch(r"(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)", value):
        raise BuildError("BOXCOP_VERSION must be a numeric major.minor.patch version")
    return value


def release_metadata(source=None):
    source = os.environ if source is None else source
    metadata = {}
    version = release_version(source)
    if version:
        metadata['CFBundleShortVersionString'] = version
    feed = source.get('BOXCOP_UPDATE_FEED_URL')
    if feed is not None:
        allowed = {'https://getallay.ai/updates/appcast.xml'}
        if feed not in allowed:
            raise BuildError('BOXCOP_UPDATE_FEED_URL must be an approved BoxCop release feed')
        metadata['SUFeedURL'] = feed
    return metadata


def verify_limited_development_bundle(bundle):
    """Reject privileged payloads or restricted signatures in limited development builds."""
    if (bundle / "Contents/Library/SystemExtensions").exists():
        raise BuildError("Limited development builds must not embed system extensions")
    for path in bundle.rglob("*"):
        if not path.is_file() or path.is_symlink() or not is_macho(path):
            continue
        result = subprocess.run(["/usr/bin/codesign", "-d", "--entitlements", ":-", str(path)],
                                capture_output=True, check=True)
        entitlements = plistlib.loads(result.stdout) if result.stdout.strip() else {}
        forbidden = {"com.apple.developer.endpoint-security.client", "com.apple.developer.networking.networkextension",
                     "com.apple.developer.system-extension.install", "com.apple.security.get-task-allow"}
        if any(entitlements.get(key) for key in forbidden):
            raise BuildError("Limited development binary has a privileged or debug entitlement: " + str(path))


def notarize(bundle, work, profile):
    disk_image = bundle.suffix == ".dmg"
    archive = bundle if disk_image else work / "notary-submission.zip"
    if not disk_image:
        run(["/usr/bin/ditto", "-c", "-k", "--sequesterRsrc", "--keepParent", bundle, archive])
    keychain = ["--keychain", os.environ["BOXCOP_KEYCHAIN_PATH"]] if os.environ.get("BOXCOP_KEYCHAIN_PATH") else []
    result = subprocess.run(["xcrun", "notarytool", "submit", str(archive), "--keychain-profile", profile,
                             "--wait", "--output-format", "json", *keychain], capture_output=True, text=True, check=True, timeout=1800)
    receipt = json.loads(result.stdout)
    (work / ("dmg-notary-receipt.json" if disk_image else "notary-receipt.json")).write_text(json.dumps(receipt, indent=2) + "\n")
    if receipt.get("status") != "Accepted":
        raise BuildError("Notarization not accepted; see retained notary receipt")
    run(["xcrun", "stapler", "staple", bundle])
    run(["xcrun", "stapler", "validate", bundle])
    assessment = ["--type", "open", "--context", "context:primary-signature"] if disk_image else ["--type", "execute"]
    run(["/usr/sbin/spctl", "--assess", *assessment, "--verbose=2", bundle])
    return receipt.get("id")


# Installer window, in Finder points. Icon locations are icon centres and must match
# the arrow drawn in Resources/dmg/background.svg.
DMG_WINDOW = (660, 360)
DMG_ICONS = {"BoxCop.app": (170, 200), "Applications": (490, 200)}


def dmg_settings(bundle):
    """dmgbuild settings for a fixed, chrome-free drag-to-Applications window."""
    return {
        "format": "UDZO",
        "filesystem": "HFS+",
        "files": [str(bundle)],
        "symlinks": {"Applications": "/Applications"},
        "icon": str(MAC / "Resources" / "BoxCop.icns"),
        # dmgbuild merges background@2x.png into a Retina TIFF hidden inside the image.
        "background": str(MAC / "Resources" / "dmg" / "background.png"),
        "window_rect": ((200, 160), DMG_WINDOW),
        "default_view": "icon-view",
        "show_toolbar": False,
        "show_pathbar": False,
        "show_sidebar": False,
        "show_status_bar": False,
        "show_tab_view": False,
        "icon_size": 128.0,
        "text_size": 13.0,
        "icon_locations": DMG_ICONS,
    }


def verify_dmg_contents(image, mount):
    """dmgbuild ignores copy failures, so check the mounted image before shipping it."""
    mount.mkdir()
    run(["/usr/bin/hdiutil", "attach", "-readonly", "-nobrowse", "-noautoopen", "-mountpoint", mount, image])
    try:
        applications = mount / "Applications"
        if not applications.is_symlink() or os.readlink(applications) != "/Applications":
            raise BuildError("Disk image is missing its Applications shortcut")
        for name in (".DS_Store", ".background.tiff", ".VolumeIcon.icns"):
            if not (mount / name).is_file():
                raise BuildError("Disk image is missing its installer layout: " + name)
        validate_bundle_layout(mount / "BoxCop.app")
        run(["/usr/bin/codesign", "--verify", "--deep", "--strict", "--verbose=2", mount / "BoxCop.app"])
    finally:
        run(["/usr/bin/hdiutil", "detach", mount])


def create_dmg(bundle, work, python, signing_identity="-"):
    """Create a compressed installer that opens as a laid-out drag-to-Applications window."""
    settings = work / "dmg-settings.py"
    settings.write_text("".join(f"{key} = {value!r}\n" for key, value in dmg_settings(bundle).items()))
    image = work / "BoxCop.dmg"
    run([python, "-m", "dmgbuild", "-s", settings, "BoxCop", image])
    run(["/usr/bin/hdiutil", "verify", image])
    verify_dmg_contents(image, work / "dmg-check")
    if signing_identity != "-":
        run(["/usr/bin/codesign", "--sign", signing_identity, "--timestamp", image])
        run(["/usr/bin/codesign", "--verify", "--strict", "--verbose=2", image])
    return image


def build(output, *, host_system=None, signing_identity="-", profile="distribution", notary_profile=None, protection_profiles=None, extension_version=None, channel="beta"):
    # This gate is deliberately BEFORE any filesystem write or dependency install.
    if (host_system or platform.system()) != "Darwin":
        raise BuildError("A macOS build host is required; this script cannot produce a verified .app on Linux")
    if profile not in {"development", "limited-development", "distribution"}:
        raise BuildError("Use profile distribution, limited-development or development; select beta/stable with --channel")
    if channel not in {"beta", "stable"}:
        raise BuildError("Release channel must be beta or stable")
    metadata = release_metadata()
    version = metadata.get('CFBundleShortVersionString')
    if notary_profile and (profile != "distribution" or signing_identity == "-"):
        raise BuildError("Notarization requires a distribution profile and a Developer ID signing identity")
    profiles = None
    if profile == "distribution":
        from protected_bundle import load_profiles
        if signing_identity == "-" or not notary_profile or not extension_version:
            raise BuildError("Distribution requires Developer ID signing, notarization and an extension version")
        try:
            profiles = load_profiles(protection_profiles or {}, signing_identity)
        except (ValueError, subprocess.SubprocessError, OSError) as exc:
            raise BuildError(str(exc)) from exc
    output = validate_output(output)
    if sys.version_info[:2] != (3, 12):
        raise BuildError("Use Python 3.12 to build the pinned standalone runtime")
    if int(platform.mac_ver()[0].split(".")[0]) < 14:
        raise BuildError("Build on macOS 14 or newer")
    if platform.machine() not in {"arm64", "x86_64"}:
        raise BuildError("Unsupported native Mac architecture")
    for tool in ("swift", "xcrun", "codesign", "ditto", "lipo", "hdiutil", "SetFile"):
        if shutil.which(tool) is None:
            raise BuildError(f"Required macOS build tool missing: {tool}")
    artifacts = MAC / ".build-artifacts"
    artifacts.mkdir(mode=0o700, exist_ok=True)
    work = Path(tempfile.mkdtemp(prefix="bundle-", dir=artifacts))
    env = child_environment()
    env["MACOSX_DEPLOYMENT_TARGET"] = "14.0"
    print(f"Build workspace (retained for debugging): {work}", flush=True)
    build_venv = work / "venv"
    # Relocatable Python distributions resolve libpython relative to the real
    # executable; copying it into the venv breaks that path on macOS.
    venv.EnvBuilder(with_pip=True, symlinks=True).create(build_venv)
    python = build_venv / "bin" / "python"
    run([python, "-m", "pip", "install", "--require-hashes", "--only-binary=:all:", "-r", MAC / "requirements-build.txt"], env=env)
    run([python, "-m", "pip", "install", "--require-hashes", "--only-binary=:all:", "-r", MAC / "requirements-dmg.txt"], env=env)
    classifier_options = prepare_classifier(python, work, env)
    run([python, "-m", "pip", "install", "--require-hashes", "--only-binary=:all:",
         "-r", MAC / "requirements-packages.txt"], env=env)
    run([python, "-m", "PyInstaller", "--noconfirm", "--clean", "--onedir", "--name", "boxcop-engine", "--paths", ROOT,
         "--distpath", work / "frozen", "--workpath", work / "pyinstaller-work", "--specpath", work,
         *classifier_options, *prepare_package_channel(work), MAC / "scripts" / "engine_entry.py"], env=env)
    run(["swift", "test", "--scratch-path", work / "swift"], cwd=MAC, env=env)
    run(["swift", "build", "--scratch-path", work / "swift", "-c", "release", "-Xswiftc", "-g", "--product", "BoxCop"], cwd=MAC, env=env)
    bin_path = subprocess.check_output(["swift", "build", "--scratch-path", str(work / "swift"), "-c", "release", "--show-bin-path"], cwd=MAC, env=env, text=True).strip()
    # Preserve matching symbols for the UUID/offset-only crash reports. Keep them
    # outside the shipped app/DMG; no runtime dependency or symbol upload service.
    symbols = work / "BoxCop.dSYM"
    run(["xcrun", "dsymutil", Path(bin_path) / "BoxCop", "-o", symbols], cwd=MAC, env=env)
    run(["xcrun", "dwarfdump", "--uuid", symbols], cwd=MAC, env=env)
    staged = work / "BoxCop.app"
    contents = staged / "Contents"
    (contents / "MacOS").mkdir(parents=True)
    (contents / "Resources").mkdir()
    shutil.copy2(Path(bin_path) / "BoxCop", contents / "MacOS" / "BoxCop")
    embed_sparkle(work / "swift", contents)
    info = plistlib.loads((MAC / "Resources" / "Info.plist").read_bytes())
    info["BoxCopReleaseProfile"] = profile
    info["BoxCopReleaseChannel"] = channel
    info.update(metadata)
    (contents / "Info.plist").write_bytes(plistlib.dumps(info))
    shutil.copy2(MAC / "Resources" / "BoxCop.icns", contents / "Resources" / "BoxCop.icns")
    shutil.copy2(MAC / "Resources" / "BoxCopMark.svg", contents / "Resources" / "BoxCopMark.svg")
    shutil.copytree(ROOT / "adapters" / "browser-context", contents / "Resources" / "browser-context")
    shutil.copy2(ROOT / "docs" / "getting-started.md", contents / "Resources" / "BoxCop Guide.md")
    shutil.copytree(work / "frozen" / "boxcop-engine", contents / "Resources" / "engine", symlinks=True)
    from bundle_inference import bundle_runtime
    bundle_runtime(contents / "Resources" / "inference", work, run)
    native, engine = validate_bundle_layout(staged)
    for binary in (native, engine):
        # lipo's -verify_arch takes a variadic arch list, so the input file must come first.
        run(["/usr/bin/lipo", binary, "-verify_arch", platform.machine()], env=env)
    # Smoke uses an unrelated cwd and no installed Python or PYTHONPATH fallback.
    run([python, MAC / "scripts" / "smoke_engine.py", "--engine", engine, "--scratch", work / "smoke"], cwd=work, env=env, timeout=60)
    provisioned = None
    if profiles:
        from protected_bundle import embed
        run(["swift", "build", "--scratch-path", work / "swift", "-c", "release", "--product", "BoxCopNetworkFilter"], cwd=MAC, env=env)
        provisioned = embed(staged, native, Path(bin_path) / "BoxCopNetworkFilter", profiles, extension_version)
    sign_bundle(staged, identity=signing_identity, hardened=profile in {"limited-development", "distribution"} and signing_identity != "-", provisioned=provisioned)
    if profile == "limited-development":
        verify_limited_development_bundle(staged)
    if provisioned:
        for target, expected in provisioned.items():
            result = subprocess.run(["/usr/bin/codesign", "-d", "--entitlements", ":-", str(target)], capture_output=True, check=True)
            actual = plistlib.loads(result.stdout)
            if any(actual.get(key) != value for key, value in expected.items()) or actual.get("com.apple.developer.endpoint-security.client") or actual.get("com.apple.security.get-task-allow"):
                raise BuildError("Protected signature entitlements do not match the network-only distribution contract")
    # Exercise the signed inference runtime without downloading/loading any weights.
    run([contents / "Resources/inference/llama-server", "--version"], cwd=work, env=env, timeout=30)
    # Exercise the actual hardened/signed engine, not just its unsigned predecessor.
    run([python, MAC / "scripts" / "smoke_engine.py", "--engine", engine, "--scratch", work / "signed-smoke"], cwd=work, env=env, timeout=60)
    package_status = json.loads(subprocess.check_output([str(engine), '--package-setup', 'status'], cwd=work, env=env, text=True, timeout=30))
    if package_status.get('configured') != bool(os.environ.get('BOXCOP_PACKAGE_FEED_URL')):
        raise BuildError('Bundled package feed trust configuration did not survive freezing/signing')
    observed_profile = subprocess.check_output([str(native), "--release-profile"], cwd=work, env=env, text=True, timeout=10).strip()
    if observed_profile != profile:
        raise BuildError("Packaged release profile does not match requested profile")
    observed_channel = subprocess.check_output([str(native), "--release-channel"], cwd=work, env=env, text=True, timeout=10).strip()
    if observed_channel != channel:
        raise BuildError("Packaged release channel does not match requested channel")
    # A GUI can stay alive with a fatal Sparkle configuration alert. Exercise the
    # actual signed bundle's updater startup without entering the GUI run loop.
    updater_startup = subprocess.check_output([str(native), "--check-updater-startup"], cwd=work, env=env, text=True, timeout=10).strip()
    if updater_startup != "UPDATER_STARTUP_PASS":
        raise BuildError("Packaged Sparkle updater failed its startup check")
    if profile in {"limited-development", "distribution"}:
        for option in ("--dev-endpoint-security-probe", "--dev-endpoint-security-service", "--dev-network-filter-enable", "--dev-agent-run"):
            denied = subprocess.run([str(native), option], cwd=work, env=env, capture_output=True, timeout=10)
            if denied.returncode != 64:
                raise BuildError("Packaged build did not reject privileged entrypoint: " + option)
    notary_id = notarize(staged, work, notary_profile) if notary_profile else None
    image = create_dmg(staged, work, python, signing_identity)
    dmg_notary_id = notarize(image, work, notary_profile) if notary_profile else None
    # Only export after the bundle and disk image pass their release checks.
    output.mkdir(parents=True, exist_ok=True)
    validate_output(output)
    final = output / "BoxCop.app"
    shutil.copytree(staged, final, symlinks=True)
    validate_bundle_layout(final)
    run(["/usr/bin/codesign", "--verify", "--deep", "--strict", "--verbose=2", final])
    shutil.copy2(image, output / "BoxCop.dmg")
    shutil.copytree(symbols, output / "BoxCop.dSYM")
    evidence = {"created_at": datetime.now(timezone.utc).isoformat(), "platform": "macOS", "architecture": platform.machine(),
                "version": info["CFBundleShortVersionString"], "build_version": str(extension_version or info["CFBundleVersion"]),
                "sparkle_version": "2.10.1", "updater_startup": "passed", "source_commit": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip(),
                "bundle": str(final), "package": str(output / "BoxCop.dmg"), "dmg_notary_submission_id": dmg_notary_id, "profile": profile, "channel": channel, "endpoint_security": "not_required_for_network_protection" if profile == "distribution" else ("excluded" if profile == "limited-development" else "development_optional"),
                "notarization": "accepted_and_stapled" if notary_profile else "NOT_RUN", "notary_submission_id": notary_id,
                "notarized_package": bool(notary_profile), "hardened_runtime": profile in {"limited-development", "distribution"} and signing_identity != "-", "signing": "ad-hoc; not notarized" if signing_identity == "-" else ("Developer ID signed; notarized" if notary_profile else "certificate-signed; not notarized"), "engine_subprocess_smoke": "passed",
                "classifier_runtime_smoke": "passed_before_and_after_signing", "classifier_backend": "minilm-head-v1",
                "bundled_inference": "llama.cpp 7071ba378afa96dcd69c41e1ec2b4912364dbee4; signed runtime smoke passed; weights downloaded on demand",
                "swift_tests": "passed", "signature_verification": "passed", "native_interactive_acceptance": "NOT_RUN"}
    (output / "build-evidence.json").write_text(json.dumps(evidence, indent=2) + "\n")
    print(json.dumps(evidence, indent=2))
    return final


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True, help="New output directory; existing bundles are never overwritten")
    parser.add_argument("--signing-identity", default="-", help="Keychain code-signing identity (prefer certificate SHA-1); default ad-hoc. Use the same identity across builds to preserve app identity.")
    parser.add_argument("--profile", choices=("development", "limited-development", "distribution"), default="distribution")
    parser.add_argument("--notary-profile", help="Existing notarytool keychain profile; requires distribution profile and Developer ID signing")
    parser.add_argument("--app-profile", type=Path)
    parser.add_argument("--network-profile", type=Path)
    parser.add_argument("--channel", choices=("beta", "stable"), default="beta")
    parser.add_argument("--extension-version", help="Increasing positive system-extension build version")
    args = parser.parse_args(argv)
    try:
        build(args.output, signing_identity=args.signing_identity, profile=args.profile, notary_profile=args.notary_profile, protection_profiles={"app": args.app_profile, "network": args.network_profile}, extension_version=args.extension_version, channel=args.channel)
    except (BuildError, subprocess.SubprocessError, OSError) as exc:
        print(f"Build stopped: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
