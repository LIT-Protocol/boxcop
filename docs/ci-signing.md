# Signing credentials in GitHub Actions

Ordinary CI (`.github/workflows/ci.yml`) uses no signing secrets. It runs the
Python tests on Linux and, on a GitHub-hosted Mac, the Swift tests, an ad-hoc
signed limited-development build and the first-launch smoke test. The DMG and
build evidence are uploaded as the `BoxCop-limited-development-arm64` artifact.

Only the manual [Release BoxCop workflow](releasing.md) signs. This page describes
how it handles the credentials. The secrets themselves are listed in
[releasing.md](releasing.md#required-secrets). They are not configured yet; until
they are, the workflow stops at its first step and names what is missing.

## What `ci_signing.py` does

`desktop/macos/scripts/ci_signing.py` has three commands and runs only on a GitHub
Actions runner.

- `check` reports which required secrets are missing, by name, and fails if any
  are. It runs before any build work.
- `install` creates a temporary keychain with a random password under
  `$RUNNER_TEMP/boxcop-signing`, imports the certificate, writes both provisioning
  profiles there with mode 0600, stores the notarization credentials in that
  keychain under the profile name `boxcop-ci`, and deletes the decoded
  certificate file. It then exports the paths `build.sh` needs
  (`BOXCOP_KEYCHAIN_PATH`, `BOXCOP_NOTARY_PROFILE`, `BOXCOP_APP_PROFILE`,
  `BOXCOP_NETWORK_PROFILE`, `BOXCOP_SIGNING_IDENTITY`) to later steps.
- `cleanup` restores the original keychain search list and deletes the temporary
  keychain and directory. The workflow runs it in an `always()` step.

The team ID and certificate fingerprint come from the `BOXCOP_TEAM_ID` and
`BOXCOP_SIGNING_IDENTITY` secrets. Nothing about the signing identity is
hard-coded in the repository. The build separately verifies that the selected
certificate is one of the certificates inside each provisioning profile.

## Handling rules

- Secret values are passed as environment variables only to the steps that need
  them, never as command arguments or workflow inputs.
- `ci_signing.py` captures the output of every credential command and reports
  only the name of a failing tool. Error messages name missing secrets but never
  include a value.
- The credential directory is outside the directory that is uploaded as an
  artifact.
- Use a disposable runner. If a runner is killed mid-job, `cleanup` does not run.
- There is no unsigned fallback. A missing or malformed secret fails the run.

## Preparing the secrets

On the Mac that holds the Developer ID certificate, export the certificate and
its private key from Keychain Access as a password-protected `.p12` file. Keep
the transfer files in `~/.sentinel-lab/ci/` (directory mode 0700, files 0600),
never in the repository. Upload each value through standard input so it does not
enter shell history:

```sh
base64 -i ~/.sentinel-lab/ci/identity.p12 | gh secret set BOXCOP_CERTIFICATE_BASE64 --repo LIT-Protocol/boxcop
base64 -i ~/.sentinel-lab/profiles/BoxCop_Developer_ID.provisionprofile | gh secret set BOXCOP_APP_PROFILE_BASE64 --repo LIT-Protocol/boxcop
base64 -i ~/.sentinel-lab/profiles/BoxCop_Network_Developer_ID.provisionprofile | gh secret set BOXCOP_NETWORK_PROFILE_BASE64 --repo LIT-Protocol/boxcop
gh secret set BOXCOP_CERTIFICATE_PASSWORD --repo LIT-Protocol/boxcop   # prompts for the value
```

Find the certificate fingerprint for `BOXCOP_SIGNING_IDENTITY` with
`security find-identity -v -p codesigning`. Use a separate app-specific password
for CI notarization so it can be revoked without affecting local builds.

When the certificate is rotated, regenerate both provisioning profiles for the
new certificate and replace the certificate, profile and fingerprint secrets
together.

## After a successful release run

Check the release's `build-evidence.json` for profile `distribution`,
notarization `accepted_and_stapled` and signature verification `passed`. CI does
not activate the network extension. Installing the build, approving the filter
and exercising each layer happen in the [VM lab](vm-lab.md).
