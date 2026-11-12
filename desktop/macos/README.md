# BoxCop for macOS

The Swift package for the BoxCop app. The product is described in the
[repository README](../../README.md); this page is for working on the app.

## Targets

| Target | Kind | Contents |
| --- | --- | --- |
| `BoxCopCore` | Library | Engine client and pipe protocol, layer status rules, event feed, network activity models and journals, journal encryption, hook supervisor. No UI. |
| `BoxCop` | Executable | The menu bar app and its windows, the command-line modes, Sparkle updates. |
| `BoxCopNetworkFilter` | Executable | The network system extension: records new connections and blocks hosts on the threat list. |
| `BoxCopProbe` | Executable | A small command-line client for the engine, used by tests. |

The Python engine is not part of this package. The app runs it as a child
process: `Contents/Resources/engine/boxcop-engine` in a built app, or the engine
you point it at when running from source.

Requirements: macOS 14 or later, Xcode Command Line Tools (Swift 5.9 or later).
Sparkle 2.10.1 is the only package dependency.

## Tests

```sh
swift test --package-path desktop/macos
```

CI runs them through `desktop/macos/scripts/ci_swift_tests.sh`, which streams output and fails
a hung run after a deadline with a sample of the stuck process:

```sh
bash desktop/macos/scripts/ci_swift_tests.sh 120 /tmp/boxcop-swift-diagnostics
```

## Running from source

A `swift run` build has no bundled engine, so tell the app where one is. The
variables are honored only outside an `.app` bundle; a built app always uses its
own engine and ignores them.

```sh
python3.12 -m venv .venv && .venv/bin/python -m pip install -r requirements.txt

export BOXCOP_ENGINE_EXECUTABLE="$PWD/.venv/bin/python"
export BOXCOP_ENGINE_ARGUMENTS="[\"-I\",\"-B\",\"$PWD/desktop/macos/scripts/engine_entry.py\"]"
export BOXCOP_DATA_DIR="$PWD/.context/dev-data"     # optional: keep development data out of ~/Library

swift run --package-path desktop/macos BoxCop
```

| Variable | Meaning |
| --- | --- |
| `BOXCOP_ENGINE_EXECUTABLE` | Absolute path of the program to run as the engine. Required when running from source. |
| `BOXCOP_ENGINE_ARGUMENTS` | Optional JSON array of arguments placed before the engine's own, here the source launcher. |
| `BOXCOP_DATA_DIR` | Optional absolute data directory instead of `~/Library/Application Support/BoxCop`. |

A source run has no network extension, because macOS only loads one from a
Developer ID signed app, so outbound control shows "Unavailable". Turning on the
install gate, containment or agent checks from a source run still edits your
real `~/.npmrc` and agent settings. Do that in the [lab VM](../../docs/vm-lab.md).

## Command-line modes

```sh
BoxCop --status            # every layer's state as a checklist; reads only
BoxCop --status --json     # the same as boxcop.status.v1 JSON
BoxCop --release-profile   # development, limited-development or distribution
BoxCop --release-channel   # beta or stable
BoxCop --check-updater-startup
BoxCop --host-agent-hook claude|codex|cursor            # called by agent hooks
BoxCop --host-agent-integrations status|install|remove
BoxCop --export-journal workflow|network|network-summary SOURCE NEW-OUTPUT-DIRECTORY
```

`--status` exits 0 when at least one enforcing layer is on, and 1 otherwise. A
layer is "on" only while it is enforcing; the rules are in
`Sources/BoxCopCore/ProtectionStatus.swift`.

`--check-updater-startup` prints `UPDATER_STARTUP_PASS` after starting real
Sparkle when the bundle names an update feed, and `UPDATER_STARTUP_SKIPPED` when
it does not. Both exit 0. The build checks that the answer matches what it put in
the bundle.

Switches that start with `--dev-network-filter-` are for lab builds. Packaged
builds refuse them with exit status 64, and the build verifies that.

## Interface previews

```sh
BoxCop --dev-interface-preview /absolute/output/directory
```

This renders the app's screens with sample data to PNG files, without starting
the engine or touching real state. Use it to review interface changes; CI
uploads the result with each build.

## Building the app

The build scripts are in `scripts/`. They are described in
[docs/releasing.md](../../docs/releasing.md).

```sh
# Signed, notarized, with the network extension (needs certificate and profiles):
./build.sh

# Ad-hoc signed, without the network extension:
python3.12 desktop/macos/scripts/build_app.py --profile limited-development --output /tmp/boxcop-dev
```

| Script | Purpose |
| --- | --- |
| `build_app.py` | The whole build: freezes the engine, builds and tests the Swift products, assembles, signs, checks, notarizes and packages. |
| `engine_entry.py` | Entry point of the frozen engine; also runs the engine from source. |
| `smoke_engine.py` | Runs the built engine's self-test and a short pipe session from an unrelated directory. |
| `bundle_inference.py` | Builds the pinned llama.cpp runtime for smart triage. |
| `protected_bundle.py` | Validates provisioning profiles and embeds the network extension. |
| `refresh_threat_domains.py` | Updates the bundled threat list in `Resources/ThreatDomains`. |
| `ci_swift_tests.sh`, `ci_launch_smoke.sh` | CI test runner and first-launch smoke test. |
| `ci_signing.py`, `release.py` | Signing credentials and publication for the Release workflow. |
| `vm_control.py` | Screenshots, clicks and typing in the lab VM. |

What the build puts in `BoxCop.app`:

```text
Contents/MacOS/BoxCop
Contents/Resources/engine/boxcop-engine      the frozen Python engine
Contents/Resources/inference/llama-server    the local model runtime
Contents/Frameworks/Sparkle.framework
Contents/Library/SystemExtensions/local.sentinel.endpoint.network-filter.systemextension   distribution builds only
```

The bundle identifiers `local.sentinel.endpoint` and
`local.sentinel.endpoint.network-filter` are unchanged from the app BoxCop was
ported from. The Developer ID provisioning profiles are bound to them.

## Resources

- `Resources/Info.plist`: the app's metadata. It names no update feed; the build
  adds one only when `BOXCOP_UPDATE_FEED_URL` and `BOXCOP_UPDATE_PUBLIC_KEY` are
  set.
- `Resources/BoxCop.icns`, `Resources/BoxCopMark.svg`: icon and menu bar mark.
- `Resources/ThreatDomains/`: the bundled threat list, its license, notice and
  pinned manifest. The build copies it into the network extension.
- `Resources/dmg/background.svg`: the installer window artwork, 660 by 360
  points. After editing it, render `background.png` at 660x360 and
  `background@2x.png` at 1320x720 from the SVG and check both by eye. The icon
  positions in `build_app.py` (`DMG_ICONS`) must match the arrow in the artwork.
