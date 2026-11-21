#!/usr/bin/env python3
"""Build a real macOS-only application; Linux tests exercise guards, not signing."""
import argparse
import ast
import base64
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
from urllib.parse import urlsplit
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
    # Commands contain build paths only, never user data.
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


# Import name -> pinned distribution name, where the two differ.
DISTRIBUTIONS = {"yaml": "pyyaml", "semantic_version": "semantic-version", "pydantic_core": "pydantic-core"}
ENTRY_MODULE = "server.desktop"


def pinned_distributions(mac=MAC):
    """Distributions the build installs from its hash-locked requirement files."""
    names = set()
    for filename in ("requirements-build.txt", "requirements-packages.txt"):
        for line in (mac / filename).read_text().splitlines():
            match = re.match(r"([A-Za-z0-9][A-Za-z0-9._-]*)==", line)
            if match:
                names.add(re.sub(r"[-_.]+", "-", match.group(1)).lower())
    return names


def _module_file(root, name):
    """The source file of a checkout module, its directory for a namespace package, or None."""
    if not name:
        return None
    base = root.joinpath(*name.split("."))
    for candidate in (base.with_suffix(".py"), base / "__init__.py"):
        if candidate.is_file():
            return candidate
    return base if base.is_dir() and any(base.glob("*.py")) else None


def _imports(tree):
    """Yield (level, module, names, optional) for every import, including lazy ones."""
    def visit(node, optional):
        if isinstance(node, ast.Import):
            for alias in node.names:
                yield 0, alias.name, [], optional
        elif isinstance(node, ast.ImportFrom):
            yield node.level, node.module or "", [alias.name for alias in node.names], optional
        elif isinstance(node, ast.Try):
            caught = {name.id for handler in node.handlers for name in ast.walk(handler.type or ast.Name("BaseException"))
                      if isinstance(name, ast.Name)}
            guarded = optional or bool(caught & {"ImportError", "ModuleNotFoundError", "Exception", "BaseException"})
            for child in node.body:
                yield from visit(child, guarded)
            for child in (*node.handlers, *node.orelse, *node.finalbody):
                yield from visit(child, optional)
        else:
            for child in ast.iter_child_nodes(node):
                yield from visit(child, optional)
    yield from visit(tree, False)


def engine_imports(root=None, entry=ENTRY_MODULE):
    """Follow the engine's own imports from its entry module.

    Returns (local modules, required third-party modules, optional third-party modules).
    Optional means the import sits in a try block that handles ImportError.
    """
    root = ROOT if root is None else Path(root)
    local, required, optional = set(), set(), set()
    queue = [entry]
    while queue:
        name = queue.pop()
        if name in local:
            continue
        path = _module_file(root, name)
        if path is None:
            raise BuildError(f"Engine module not found: {name}")
        local.add(name)
        if path.is_dir():
            continue
        package = name if path.name == "__init__.py" else name.rpartition(".")[0]
        for level, module, names, guarded in _imports(ast.parse(path.read_text(), filename=str(path))):
            if level:
                parts = package.split(".") if package else []
                parts = parts[:len(parts) - (level - 1)]
                module = ".".join(parts + ([module] if module else []))
            top = module.split(".")[0]
            if _module_file(root, top) is None:
                if top and top not in sys.stdlib_module_names and top != "__future__":
                    (optional if guarded else required).add(top)
                continue
            # `from package import name` may name a submodule or an attribute.
            targets = [module] + [module + "." + item for item in names]
            for target in targets:
                if _module_file(root, target) is not None:
                    # Importing a.b.c also imports a and a.b.
                    pieces = target.split(".")
                    queue.extend(".".join(pieces[:index]) for index in range(1, len(pieces) + 1))
    return local, required, optional - required


def engine_freeze_options(root=None, mac=MAC):
    """PyInstaller options derived from what the engine imports.

    Fails when the engine imports a third-party module that no hash-locked
    requirement file installs: such a build would pass here and crash on a user's Mac.
    """
    root = ROOT if root is None else Path(root)
    local, required, optional = engine_imports(root)
    pinned = pinned_distributions(mac)
    def distribution(module):
        return re.sub(r"[-_.]+", "-", DISTRIBUTIONS.get(module, module)).lower()
    missing = sorted(module for module in required if distribution(module) not in pinned)
    if missing:
        raise BuildError("The engine imports modules that are not pinned in requirements-build.txt or "
                         "requirements-packages.txt: " + ", ".join(missing))
    options = ["--add-data", str(root / "server/assets") + ":server/assets"]
    files = {name for name in local if _module_file(root, name).is_file()}
    for module in sorted(files | required | {name for name in optional if distribution(name) in pinned}):
        options += ["--hidden-import", module]
    return options


def prepare_package_channel(work):
    """Embed the official trust pin or an explicitly configured custom channel."""
    import importlib.util
    spec = importlib.util.spec_from_file_location('boxcop_package_channel', ROOT / 'server/package_channel.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    url = os.environ.get('BOXCOP_PACKAGE_FEED_URL') or None
    public = os.environ.get('BOXCOP_PACKAGE_FEED_PUBLIC_KEY_BASE64') or None
    if not url and not public:
        url = 'https://raw.githubusercontent.com/LIT-Protocol/boxcop/package-feed/policy.json'
        public = (MAC / 'Resources/package-feed-public-key.txt').read_text().strip()
    if not url or not public:
        raise BuildError('Package feed URL and public key must be configured together')
    try:
        value = module.validate_channel(dict(schema='boxcop.package-channel.v1', url=url, public_key=public,
            minimum_sequence=int(os.environ.get('BOXCOP_PACKAGE_FEED_MINIMUM_SEQUENCE') or '1')))
    except (ValueError, KeyError) as exc:
        raise BuildError('Invalid package feed configuration: ' + str(exc)) from exc
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


def validate_update_feed(feed, key):
    """An update feed is an HTTPS URL plus the Ed25519 public key that signs it."""
    url = urlsplit(feed)
    if (feed != feed.strip() or any(character.isspace() for character in feed) or url.scheme != 'https'
            or not url.hostname or url.username or url.password or url.query or url.fragment
            or not url.path.endswith('.xml')):
        raise BuildError('BOXCOP_UPDATE_FEED_URL must be a credential-free HTTPS URL of an appcast .xml file')
    try:
        decoded = base64.b64decode(key, validate=True)
    except ValueError:
        decoded = b''
    if len(decoded) != 32:
        raise BuildError('BOXCOP_UPDATE_PUBLIC_KEY must be a base64 Ed25519 public key')


def release_metadata(source=None):
    """Version and update settings supplied by the release, never baked into the checkout.

    BoxCop has no update feed yet. A build gets SUFeedURL and SUPublicEDKey only
    when both variables are set; without them the app does not start its updater.
    """
    source = os.environ if source is None else source
    metadata = {}
    version = release_version(source)
    if version:
        metadata['CFBundleShortVersionString'] = version
    feed = source.get('BOXCOP_UPDATE_FEED_URL') or None
    key = source.get('BOXCOP_UPDATE_PUBLIC_KEY') or None
    if feed or key:
        if not feed or not key:
            raise BuildError('BOXCOP_UPDATE_FEED_URL and BOXCOP_UPDATE_PUBLIC_KEY must be set together')
        validate_update_feed(feed, key)
        metadata['SUFeedURL'] = feed
        metadata['SUPublicEDKey'] = key
    return metadata


def check_updater_startup(output, feed_configured):
    """The app's own report must agree with what the build put in the bundle."""
    if feed_configured and output != "UPDATER_STARTUP_PASS":
        raise BuildError("Packaged Sparkle updater failed its startup check")
    if not feed_configured and not output.startswith("UPDATER_STARTUP_SKIPPED"):
        # A pass here would mean the app found a feed the build did not configure.
        raise BuildError("Packaged app started an updater although the build has no update feed")


def packaged_entrypoints_to_reject(sources=None):
    """Lab-only command-line switches that still exist in the Swift sources.

    Packaged builds must answer each with exit status 64. The list is read from
    the sources so the check follows the app as lab switches are removed.
    """
    sources = MAC / "Sources" if sources is None else Path(sources)
    text = "".join(path.read_text(errors="replace") for path in sorted(sources.rglob("*.swift")))
    return sorted(set(re.findall(r'"(--dev-network-filter-[a-z-]+)"', text)))


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
        # Limited development builds must never carry privileged entitlements.
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
    # Fail on an unpinned engine dependency before any filesystem write.
    freeze_options = engine_freeze_options()
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
    run([python, "-m", "pip", "install", "--require-hashes", "--only-binary=:all:",
         "-r", MAC / "requirements-packages.txt"], env=env)
    run([python, "-m", "PyInstaller", "--noconfirm", "--clean", "--onedir", "--name", "boxcop-engine", "--paths", ROOT,
         "--distpath", work / "frozen", "--workpath", work / "pyinstaller-work", "--specpath", work,
         *freeze_options, *prepare_package_channel(work), MAC / "scripts" / "engine_entry.py"], env=env)
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
    shutil.copytree(work / "frozen" / "boxcop-engine", contents / "Resources" / "engine", symlinks=True)
    from bundle_inference import bundle_runtime, REVISION as inference_revision
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
            if any(actual.get(key) != value for key, value in expected.items()) or actual.get("com.apple.developer.endpoint-security.client") != expected.get("com.apple.developer.endpoint-security.client") or actual.get("com.apple.security.get-task-allow"):
                raise BuildError("Signed entitlements do not match the network-extension distribution contract")
    # Exercise the signed inference runtime without downloading/loading any weights.
    run([contents / "Resources/inference/llama-server", "--version"], cwd=work, env=env, timeout=30)
    # Exercise the actual hardened/signed engine, not just its unsigned predecessor.
    run([python, MAC / "scripts" / "smoke_engine.py", "--engine", engine, "--scratch", work / "signed-smoke"], cwd=work, env=env, timeout=60)
    # Ask the signed engine whether it carries the feed pin. A scratch home keeps the
    # build from reading the builder's own BoxCop state.
    status_home = work / "status-home"
    status_home.mkdir(mode=0o700)
    package_status = json.loads(subprocess.check_output(
        [str(engine), "--protection-status", "--data-dir", str(status_home / "data")],
        cwd=work, env=dict(env, HOME=str(status_home)), text=True, timeout=30))
    package_feed = json.loads((work / 'channel.json').read_bytes())['url']
    if package_status.get("package", {}).get("configured") is not True:
        raise BuildError('Bundled package feed trust configuration did not survive freezing/signing')
    observed_profile = subprocess.check_output([str(native), "--release-profile"], cwd=work, env=env, text=True, timeout=10).strip()
    if observed_profile != profile:
        raise BuildError("Packaged release profile does not match requested profile")
    observed_channel = subprocess.check_output([str(native), "--release-channel"], cwd=work, env=env, text=True, timeout=10).strip()
    if observed_channel != channel:
        raise BuildError("Packaged release channel does not match requested channel")
    # A GUI can stay alive with a fatal Sparkle configuration alert. Exercise the
    # actual signed bundle's updater startup without entering the GUI run loop.
    # With an update feed the app must start real Sparkle and report a pass.
    # Without one it must exit 0 without starting the updater.
    updater_startup = subprocess.check_output([str(native), "--check-updater-startup"], cwd=work, env=env, text=True, timeout=10).strip()
    update_feed = info.get("SUFeedURL")
    check_updater_startup(updater_startup, bool(update_feed))
    if profile in {"limited-development", "distribution"}:
        for option in packaged_entrypoints_to_reject():
            denied = subprocess.run([str(native), option], cwd=work, env=env, capture_output=True, timeout=10)
            if denied.returncode != 64:
                raise BuildError("Packaged build did not reject lab entrypoint: " + option)
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
    hardened = profile in {"limited-development", "distribution"} and signing_identity != "-"
    signing = "ad-hoc; not notarized" if signing_identity == "-" else (
        "Developer ID signed; notarized" if notary_profile else "certificate-signed; not notarized")
    evidence = {
        "created_at": datetime.now(timezone.utc).isoformat(), "platform": "macOS", "architecture": platform.machine(),
        "version": info["CFBundleShortVersionString"], "build_version": str(extension_version or info["CFBundleVersion"]),
        "source_commit": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip(),
        "bundle": str(final), "package": str(output / "BoxCop.dmg"), "profile": profile, "channel": channel,
        "network_extension": "embedded" if provisioned else "not_included",
        "package_feed": package_feed,
        "update_feed": update_feed or "not_configured",
        "updater_startup": "passed" if update_feed else "passed_updater_disabled_without_feed",
        "sparkle_version": "2.10.1",
        "signing": signing, "hardened_runtime": hardened, "signature_verification": "passed",
        "notarization": "accepted_and_stapled" if notary_profile else "NOT_RUN",
        "notarized_package": bool(notary_profile), "notary_submission_id": notary_id,
        "dmg_notary_submission_id": dmg_notary_id,
        "engine_self_test": "passed_before_and_after_signing", "engine_subprocess_smoke": "passed",
        "bundled_inference": f"llama.cpp {inference_revision}; signed runtime smoke passed; weights downloaded on demand",
        "swift_tests": "passed", "native_interactive_acceptance": "NOT_RUN"}
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
