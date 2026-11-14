# Beta release readiness review

Reviewed 2026-11-13 against main after the credential-protection PR.

## Fixes in this PR

- Release runs perform full signing, notarization, launch smoke and Sparkle
  verification, then publish to GitHub Releases. Per the owner's follow-up request,
  the rehearsal option was removed; manual dispatch always publishes on success.
  Merging remains ordinary CI.
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
The certificate export and password secrets were subsequently configured. The
workflow still needs to verify that the encrypted export and password match.

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
  updater executable; one is platform-dependent). These counts describe the original
  review; publication tests now cover the always-publish path with both custom and
  GitHub feeds.
- Native fixture rendering reviewed in light/dark mode for onboarding and Settings.
- The new uninstall path has compile coverage but has not been exercised with
  actual macOS deactivation approvals. Test cancellation, restart-required and success
  paths in the dedicated VM using the signed release build. Do not uninstall on the host.

After merge and configuration, dispatch `release.yml` from main for the chosen
version. Download the published DMG from GitHub Releases and install it in the VM
to verify first-run setup, credential FDA, pause/resume, update UI and uninstall
feedback. This review does not claim a successful CI notarization, public feed
deployment, or an end-to-end installed-app update yet.
