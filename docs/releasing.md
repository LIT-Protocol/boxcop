# Building and releasing BoxCop

There are three ways to build the app. All of them produce `BoxCop.app`,
`BoxCop.dmg`, `BoxCop.dSYM` and `build-evidence.json` in a new output directory,
and never overwrite an existing build.

| Build | Command | Signing | Network extension |
| --- | --- | --- | --- |
| Distribution, local | `./build.sh` | Developer ID, notarized | Included |
| Limited development | `python3.12 desktop/macos/scripts/build_app.py --profile limited-development --output DIR` | Ad-hoc | Not included |
| Release | the **Release BoxCop** workflow | Developer ID, notarized | Included |

Every build needs macOS 14 or later, Xcode Command Line Tools, CMake and
Python 3.12. The build creates its own virtual environment from hash-locked
requirement files, freezes the Python engine with PyInstaller, runs the Swift
tests, builds the llama.cpp runtime from a checksum-pinned source archive, signs
everything, and then exercises the signed result: the engine self-test, the
packaged release profile and channel, and the updater startup check.

## Local distribution build

```sh
./build.sh                 # output: ~/Downloads/BoxCop-beta-<timestamp>
./build.sh /path/to/new/output/directory
```

`build.sh` needs:

- A **Developer ID Application** certificate with its private key in the Keychain.
  With more than one, set `BOXCOP_SIGNING_IDENTITY` to the certificate's SHA-1.
- The two **provisioning profiles**, by default
  `~/.sentinel-lab/profiles/BoxCop_Developer_ID.provisionprofile` and
  `~/.sentinel-lab/profiles/BoxCop_Network_Developer_ID.provisionprofile`. Override
  with `BOXCOP_APP_PROFILE` and `BOXCOP_NETWORK_PROFILE`.
- **Notarization credentials** saved in the Keychain with
  `xcrun notarytool store-credentials`, by default under the profile name
  `sentinel-beta`. Override with `BOXCOP_NOTARY_PROFILE`.

The signing profiles live in `~/.sentinel-lab` by default. The profiles are bound to the bundle identifiers `local.sentinel.endpoint`
and `local.sentinel.endpoint.network-filter`, which is why BoxCop keeps those
identifiers. The build checks each profile's identifier, team, expiry,
entitlements and certificate before it starts.

Other variables:

| Variable | Meaning |
| --- | --- |
| `BOXCOP_CHANNEL` | `beta` (default) or `stable`. Both include every layer. |
| `BOXCOP_VERSION` | Display version, `major.minor.patch`. |
| `BOXCOP_EXTENSION_VERSION` | Build number shared by the app and the extension. Defaults to the current Unix time, so later builds replace earlier ones. |
| `BOXCOP_PYTHON` | Python 3.12 executable. Default `python3.12`. |
| `BOXCOP_PACKAGE_FEED_URL`, `BOXCOP_PACKAGE_FEED_PUBLIC_KEY_BASE64`, `BOXCOP_PACKAGE_FEED_MINIMUM_SEQUENCE` | The signed package malware feed. No feed is configured by default; see [package-registry-firewall.md](package-registry-firewall.md). |
| `BOXCOP_UPDATE_FEED_URL`, `BOXCOP_UPDATE_PUBLIC_KEY` | In-app updates. Unset by default; see below. |

The script never falls back to ad-hoc signing and does not install, launch or
publish anything.

## Limited-development build

```sh
python3.12 desktop/macos/scripts/build_app.py --profile limited-development --output /tmp/boxcop-dev
```

This needs no certificate. It is ad-hoc signed, has no network extension, and the
build fails if a system extension or a restricted entitlement ends up in the
bundle. CI makes this build on every pull request. To give it a working install
gate, export the three `BOXCOP_PACKAGE_FEED_*` variables first.

## In-app updates

BoxCop has no update feed yet. The checked-in `Info.plist` names no feed, and a
build without one does not start its updater: `BoxCop --check-updater-startup`
prints `UPDATER_STARTUP_SKIPPED`, exits 0, and the app offers no update check.
The build fails if a bundle without a feed reports anything else.

A build gets in-app updates only when both of these are set:

- `BOXCOP_UPDATE_FEED_URL`: the HTTPS URL of a Sparkle appcast, ending in `.xml`.
- `BOXCOP_UPDATE_PUBLIC_KEY`: the base64 Ed25519 public key that signs it, from
  Sparkle's `generate_keys`.

The build then writes `SUFeedURL` and `SUPublicEDKey` into the bundle and requires
`--check-updater-startup` to start real Sparkle and report `UPDATER_STARTUP_PASS`.
The appcast must be signed, and updates are verified before extraction; those two
settings are fixed in `Info.plist`. Installing an update always needs the user's
action.

No update domain is built in. To host a feed, serve `appcast.xml` at the feed URL
and each release's DMG at `<feed directory>/v<VERSION>/`, which is the layout the
release script signs for.

## The Release workflow

**Actions → Release BoxCop → Run workflow**, on `main`. Leave the version blank to
increment the patch number of the highest published version, or enter one.

```sh
gh workflow run release.yml --ref main
gh workflow run release.yml --ref main -f version=0.2.0
```

The workflow is manual only. It:

1. Checks that every secret and variable below exists, and stops with their names
   when any are missing. **They are not configured yet**, so the workflow stops
   here today.
2. Confirms it runs from `main` in `LIT-Protocol/boxcop` (repository ID
   `1455881957`; forks have a different ID) and that the version is new.
3. Refreshes the bundled threat list and fails if upstream is older than two days.
4. Runs the Python tests, then `./build.sh` with temporary signing credentials.
5. Runs the first-launch smoke test on the signed app.
6. Generates and signs the appcast, then publishes `v<VERSION>` as a GitHub
   release with the DMG, `appcast.xml`, debug symbols, `SHA256SUMS`,
   `build-evidence.json`, the launch smoke log and the threat list manifest.

Tags and releases are never overwritten, and versions must increase.

### Required secrets

Settings → Secrets and variables → Actions → Secrets:

| Secret | Value |
| --- | --- |
| `BOXCOP_CERTIFICATE_BASE64` | Base64 of the password-protected PKCS#12 export of the Developer ID Application certificate and its private key |
| `BOXCOP_CERTIFICATE_PASSWORD` | That export's password |
| `BOXCOP_APP_PROFILE_BASE64` | Base64 of the app provisioning profile |
| `BOXCOP_NETWORK_PROFILE_BASE64` | Base64 of the network extension provisioning profile |
| `BOXCOP_NOTARY_APPLE_ID` | Apple ID used for notarization |
| `BOXCOP_NOTARY_PASSWORD` | App-specific password for that Apple ID |
| `BOXCOP_TEAM_ID` | The 10-character Apple team ID the certificate belongs to |
| `BOXCOP_SIGNING_IDENTITY` | SHA-1 fingerprint of the Developer ID Application certificate |
| `BOXCOP_SPARKLE_PRIVATE_KEY` | Base64 Ed25519 private key that signs updates, exported by Sparkle's `generate_keys` |

### Required variables

Settings → Secrets and variables → Actions → Variables:

| Variable | Value |
| --- | --- |
| `BOXCOP_UPDATE_FEED_URL` | The appcast URL. Required: a published release that names no feed could never update itself. |
| `BOXCOP_UPDATE_PUBLIC_KEY` | The public half of `BOXCOP_SPARKLE_PRIVATE_KEY` |

Optional: `BOXCOP_PACKAGE_FEED_URL`, `BOXCOP_PACKAGE_FEED_PUBLIC_KEY_BASE64` and
`BOXCOP_PACKAGE_FEED_MINIMUM_SEQUENCE` override the default package feed.

[ci-signing.md](ci-signing.md) explains how the workflow handles the signing
secrets.

### The update signing key

Installed apps trust the public key they were built with. Generate the key pair
once, keep the private key in the repository secret and in one offline backup,
and never replace it casually: an app built with the old public key rejects
updates signed with a new one. Publication verifies that the secret matches the
public key in the bundle before it signs anything.

### Failed runs

A failure before publication leaves no release. If asset upload succeeds and
publishing fails, a draft release and tag can remain. Inspect and remove that
draft and tag before retrying the same version, or choose a new version. Never
overwrite a published version.

## What a build proves

`build-evidence.json` records the source commit, profile, channel, signing and
notarization result, the package and update feeds, and the checks that ran. A
passing build proves packaging, signatures, the engine self-test and first launch.
It does not prove that a layer protects anything: the network extension, package
routing and agent hooks are accepted interactively in the
[VM lab](vm-lab.md).

To run the updater regression against a freshly built executable:

```sh
swift build --package-path desktop/macos --product BoxCop
BOXCOP_UPDATER_TEST_EXECUTABLE="$PWD/desktop/macos/.build/debug/BoxCop" \
  .venv/bin/python -m pytest -q tests/test_release.py -k packaged_sparkle_startup
```

## Endpoint Security credential protection

The network extension now also uses Endpoint Security. Its Developer ID profile
must include `com.apple.developer.endpoint-security.client = true` for
`local.sentinel.endpoint.network-filter`; older network-only profiles fail
validation. Regenerate the profile after Apple's capability approval and supply
it through `BOXCOP_NETWORK_PROFILE` (or `--network-profile`). Do not add the ES
entitlement to the containing app. Run the signed VM acceptance gate in
[credential-protection.md](credential-protection.md) before distributing this change.

Local refreshed profiles are stored at `~/.sentinel-lab/profiles/` under the
filenames used by `build.sh`. The GitHub Actions `BOXCOP_NETWORK_PROFILE_BASE64`
secret must also contain the refreshed ES-enabled profile before a release build;
updating the local file does not update that secret. Signed beta acceptance is
recorded in [credential protection](credential-protection.md).
