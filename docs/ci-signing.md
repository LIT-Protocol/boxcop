# Signed macOS builds in GitHub Actions

The `macOS app` workflow produces a signed, notarized **distribution** build (beta channel) on pushes
to `main` and explicit manual runs. Pull requests produce ad-hoc limited development builds without
signing credentials. Manual runs use the selected branch; only dispatch trusted
source. This build workflow uploads the DMG and evidence as Actions artifacts. The separate
manual [Release BoxCop workflow](releasing.md) publishes GitHub Releases and signed
Sparkle update feeds from `main`.

The workflow imports the Developer ID identity into a temporary keychain, supplies
both profiles, invokes `build.sh`, and verifies signatures, notarization/stapling,
Gatekeeper and first-launch consent behavior. It does not activate the network
extension or qualify live filtering. Local and CI builds default to the same
Unix-timestamp extension build version scheme, so later builds can replace earlier
installations from either source.
`BOXCOP_EXTENSION_VERSION` can override it with an increasing positive integer.

The [first signed CI run](https://github.com/Ember-Sovereignty/BoxCop/actions/runs/41533356828)
passed on November 2, 2026: app/DMG signing, notarization and stapling, Gatekeeper,
launch smoke and credential cleanup. All six secrets are configured. The
[recorded build evidence](../artifacts/boxcop-protected-ci-build-v1.json) identifies
the source commit and DMG digest. This run used the PR branch; automatic signed
builds on `main` start after the workflow change is merged.

## Repository secrets

Configure these in the `BoxCop` repository under Settings → Secrets and
variables → Actions:

| Secret | Value |
| --- | --- |
| `BOXCOP_CERTIFICATE_BASE64` | Base64 of the password-encrypted PKCS#12 export of the Developer ID Application certificate **and private key** |
| `BOXCOP_CERTIFICATE_PASSWORD` | Export password |
| `BOXCOP_APP_PROFILE_BASE64` | Base64 of `Allay_Developer_ID.provisionprofile` |
| `BOXCOP_NETWORK_PROFILE_BASE64` | Base64 of `Allay_Network_Developer_ID.provisionprofile` |
| `BOXCOP_NOTARY_APPLE_ID` | Apple ID email used for notarization |
| `BOXCOP_NOTARY_PASSWORD` | Apple app-specific password for notarization |

The current team is `QWER3PMRVZ`; the expected signing fingerprint is
`8D5650DE08B51DDACD873C92D767F43B4654AFA6`. On certificate rotation, update these
public identifiers in `desktop/macos/scripts/ci_signing.py`, regenerate both
profiles for the new certificate, and replace the relevant secrets together.
Missing secrets fail the signed build; there is no unsigned fallback.

The canonical local credentials/configuration directory is `~/.sentinel-lab/`.
Downloaded profiles live in `profiles/`; private CI transfer files belong in `ci/`
with directory mode 0700 and file mode 0600. The original signing identity stays
in Keychain. Do not commit credentials or put secret values in command arguments,
logs, workflow inputs or artifacts. Upload with `gh secret set NAME` via standard
input. A separate Apple app-specific password can be revoked independently from
local notarization credentials.

## Runner cleanup and artifacts

Secret environment variables are passed only to the credential installation step.
`ci_signing.py` suppresses credential-command output, restores the original keychain
search list and deletes the temporary keychain and profiles in an `always()` cleanup
step. Artifacts include only named distribution/evidence files; the credential
directory is outside the artifact directory. The runner must be disposable: a hard
machine termination can prevent cleanup from executing.

`BOXCOP_KEYCHAIN_PATH` makes both the build preflight and notarization submissions
use the temporary keychain explicitly. Ordinary local builds continue using the
existing `sentinel-beta` Keychain profile.

After a successful workflow, download `BoxCop-macOS-arm64` from the run's
Artifacts section. Check `build-evidence.json` for profile `distribution`, channel `beta`, notarization
`accepted_and_stapled` and signature verification `passed`. Interactive installation,
filter approval and real receiver effects remain the [network release gates](outgoing-connections.md).
