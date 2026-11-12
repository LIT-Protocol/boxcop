# Publishing BoxCop for macOS

Run **Actions → Release BoxCop → Run workflow**, select `main`, and leave the version
blank to increment the highest published version's patch number (for example,
`0.1.0` → `0.1.1`). With no published versions it starts at `0.1.0`. Drafts do not
determine the next version, but an existing draft or tag at that version still
blocks publication. You can enter an explicit numeric version such as `0.2.0`
instead. The workflow is manual only. It builds the exact
main commit selected at dispatch, tests, signs and notarizes the Apple silicon
app and DMG, checks first launch, then publishes `v<VERSION>` with release notes,
the DMG, a signed `appcast.xml`, SHA-256 checksums and build evidence. Releases are
serialized and existing tags/releases are never overwritten. Versions must increase.

```sh
# Run from an BoxCop checkout; gh resolves its current repository owner.
gh workflow run release.yml --ref main
# Or choose a version explicitly:
gh workflow run release.yml --ref main -f version=0.2.0
```

The app remains beta quality (`BOXCOP_CHANNEL=beta`). GitHub releases are published
as normal/latest releases, rather than GitHub prereleases. Release preflight checks
GitHub's permanent repository ID (`1434713741`) and the approved owner/name, then
exports `BOXCOP_UPDATE_FEED_URL=https://getallay.ai/updates/appcast.xml` for the
bundle builder. The signed appcast uses versioned Railway download routes. GitHub
publication still uses the current repository owner. Publication rejects a bundle
whose feed URL differs. Do not manually mark an unrelated release as latest.

Share `https://getallay.ai/download` for the latest installer. Railway resolves the
latest published stable release within 60 seconds, using a backend-only read token
for the private repository. The route is unlisted but public to anyone with its URL;
it is not linked from the website. See [backend configuration](../team/DEPLOYMENT.md#private-repository-app-distribution).
Deploy and configure that backend before publishing the first release with these
URLs. Existing installations using GitHub feeds need a one-time manual upgrade;
private GitHub URLs cannot redirect unauthenticated installed apps to the new feed.
Only Apple silicon is currently published; Intel builds do not start update checks.
Adding stable/beta feeds or Intel release assets requires explicit feed routing.

Existing users manually install the first updater-enabled DMG. Subsequent releases
are offered through Sparkle's standard **Install and Relaunch** flow. Automatic
checks are on by default and can be disabled in the menu bar; automatic installation
is disabled. The app's normal termination handler drains the sidecar before exit.
On launch, only an already-enabled older network extension is submitted for
replacement. macOS may still require approval or reboot; Connections shows its
status and provides manual retry. User data remains outside the replaced app bundle.

## Repository identity

The organization was renamed from `Ember-Sovereignty` to `boxcophq`. Release preflight
accepts both names only with the original repository ID `1434713741`; forks cannot
pass that check. New builds use the owner-independent Railway feed. Preserve the
Sparkle key, bundle IDs and versioned release assets. GitHub redirects do not grant
access to private releases; old installed apps need the manual migration above.

## Signing and version identity

The existing Apple signing/notarization secrets remain required. Additionally,
`BOXCOP_SPARKLE_PRIVATE_KEY` is a repository Actions secret containing the base64
Ed25519 seed exported by Sparkle's `generate_keys`. Its public key is pinned as
`SUPublicEDKey` in `desktop/macos/Resources/Info.plist`. Both the update archive and
feed are signed, and `SURequireSignedFeed` is enabled. Publication verifies that the
secret matches the bundled public key and verifies the generated signatures.
Never regenerate or replace this key casually: installed apps trust the original.
The initial key is backed up in the maintainer's login Keychain under Sparkle
account `boxcop-updates`. Temporary private-key exports must not enter the repository.

`BOXCOP_VERSION` sets the display version. The increasing Unix-timestamp build
number is shared by the app and network extension, preserving compatibility with
existing local distribution builds. Sparkle is pinned to 2.10.1 in Package.swift
and Package.resolved; its checksum-verified SPM artifact supplies both the embedded
framework and release tools. The build seals nested helpers before the framework
and app. Unneeded sandbox XPC services are removed.

## Failed runs and validation limits

Failures before publication leave no public release. If uploading succeeds but
publishing fails, the draft and tag may remain; inspect and deliberately remove
that incomplete draft/tag before retrying the same version, or choose a new version.
Never overwrite a published version. Each feed contains the newest full update;
older installers remain available through their versioned Railway routes.

CI covers release preflight, signature integrity, native compilation and tests,
Sparkle startup in the signed app, notarization, Gatekeeper, and launch. The
`--check-updater-startup` command exits before Sparkle's scheduled update cycle
runs; startup errors fail the build before notarization or publication. An actual old-to-new install/relaunch and
macOS extension replacement still require interactive acceptance on a real Mac.

The initial updater configuration enabled `SURequireSignedFeed` without its
required `SUVerifyUpdateBeforeExtraction` setting. Affected builds (including
v0.1.0) cannot start Sparkle and must be replaced manually with a fixed release.
Both settings must remain enabled. To run the native regression that checks both
the broken and corrected configurations in separately signed temporary bundles:

```sh
swift build --package-path desktop/macos --product BoxCop
BOXCOP_UPDATER_TEST_EXECUTABLE="$PWD/desktop/macos/.build/debug/BoxCop" \
  .venv/bin/python -m pytest -q tests/test_release.py -k packaged_sparkle_startup
```
