# Beta release readiness review

Reviewed 2026-11-13 against main after the credential-protection PR.

## Fixes in this PR

- A release workflow run now defaults to rehearsal: full signing, notarization,
  launch smoke and Sparkle verification, with downloadable artifacts. Publishing
  requires selecting the publish input. Merging remains ordinary CI.
- Uninstall propagates filter/deactivation failure and restart requirements.
  The app no longer tells users to delete it when system protection removal fails.
  Successful removal clears the local credential-protection wanted indicator.
- Onboarding points to optional credential protection and its separate FDA/restart
  steps. Credential defaults are visible before expandable coverage limitations.
- Pause/removal text includes credential protection. Privacy copy distinguishes
  local decisions from network downloads; Protections no longer describes every
  advisory/health feature as enforcing.

## External release prerequisites

The repository is now public (verified after the owner changed visibility).
Repository Actions configuration lists
both profiles, notarization credentials, team, certificate identity, and the
Sparkle private/public keys. These names do not validate secret contents.
`BOXCOP_CERTIFICATE_BASE64` and `BOXCOP_CERTIFICATE_PASSWORD` are still absent
from repository configuration. Organization
secrets could supply credentials separately; the workflow checks actual availability.

The owner selected public GitHub Release downloads. `BOXCOP_UPDATE_FEED_URL` is
set to `https://github.com/LIT-Protocol/boxcop/releases/latest/download/appcast.xml`.
This PR maps that feed to version-specific DMG asset URLs, keeping installed
clients on an immutable signed artifact. The feed becomes live on first publication.

The package intelligence feed variables are also unset. Without a configured feed,
the install gate is unavailable, as documented. Decide the beta's intended coverage
before distributing it; the prior VM's install-gate listener also needs investigation.

## Validation and merge test

- Swift suite: 143 passed.
- Release/signing/packaging tests: 141 passed, three skipped (two need a packaged
  updater executable; one is platform-dependent). Rehearsal tests exercise signed appcast validation and assert
  zero GitHub publication commands; publication behavior remains tested separately.
- Native fixture rendering reviewed in light/dark mode for onboarding and Settings.
- The new uninstall path has compile coverage but has not been exercised with
  actual macOS deactivation approvals. Test cancellation, restart-required and success
  paths in the dedicated VM using the rehearsal build. Do not uninstall on the host.

After merge and configuration, dispatch `release.yml` from main with publish false.
Download the rehearsal artifact, install in the VM, verify first-run setup, credential
FDA, pause/resume, update UI and uninstall feedback. Then dispatch with publish true
for the chosen version. This review does not claim a successful CI notarization,
public feed deployment, or an end-to-end installed-app update yet.
