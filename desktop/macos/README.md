# BoxCop for macOS

**Focus and alert visibility:** Focus can suppress macOS banners without pausing
BoxCop. Pending draft, email, code, PDF and software reviews have a neutral menu-bar
count and review links. Orange continues to mean protection needs attention.
Enabled draft/email/code/PDF notifications can use a compact BoxCop heads-up instead
of a macOS notification. Heads-ups require macOS banner permission and preserve each
producer's notification preference, deduplication and rate limit. They dismiss after
8 seconds (hover pauses the timer; bursts are capped at 20 seconds), or remain when
the separate **Keep heads-ups on screen until I dismiss them** preference is enabled.
There is no Focus detection. Software findings retain standard macOS notifications;
AI workflow findings stay in Activity. Existing security panels are unchanged.
VoiceOver uses native notifications and the menu count to preserve reading focus.
Live macOS 14 acceptance found a missed Chrome screen-capture session; sharing
suppression remains unqualified.
See [delivery rules and verification limits](../../docs/alert-visibility.md).

Paste guard defaults to allowing Command-V. Paste size is unrestricted; the
4,096-scalar inspection budget only bounds background checking. Oversized or
unsupported content, pending checks, warnings, and engine failures do not hold a
paste. Only an explicit block decision for the current clipboard and destination
stops it, including repeated keys. If a check has not finished, the first paste
can pass before a secret is detected; a later block applies to subsequent pastes.

The October 29 arm64 beta has [signed/notarized SIP-enabled acceptance](../../artifacts/boxcop-beta-acceptance.json).
Builds from changed source need their own release qualification; default ad-hoc builds
do not inherit that evidence. See [current scenario evidence](../../docs/scenario-qualification.md).

Current source adds a **Protected presentation** control in Connections.
Select an exact source window and share only the generated **BoxCop Protected Presentation**
window. Capture → OCR → policy → display operates on the same immutable image; unknown,
sensitive or expired results display a neutral slate. The output has no source title or
raw reasons. Direct source/desktop sharing remains unprotected, and OCR is heuristic.
See [sharing acceptance and reproduction](../../docs/screen-share-evaluation.md).

**Release channels:** `beta` (default) and `stable` include the same shipping
protections, including the standalone Network Extension. Select the channel with
`BOXCOP_CHANNEL`; it is recorded separately in the signed bundle and build evidence.
Experimental features can be added independently; the beta label removes no protection.

**Build capabilities:** `distribution` requires Developer ID signing, notarization,
and app/network provisioning profiles. `limited-development` is an explicit ad-hoc
validation build without system extensions, used by PR CI. `development` retains
privileged lab entrypoints and automatic development collection; it is not a release.
Packaged distribution and limited development builds use opt-in monitoring and reject
privileged lab entrypoints. Neither includes the Endpoint Security lab service.
Existing consent choices are preserved across channel changes.

The former `beta`/`protected` profile names and `BOXCOP_PROFILE` are retired. Use
`./build.sh` for a full beta distribution, or `BOXCOP_CHANNEL=stable ./build.sh` for
stable. See [provisioning and release gates](../../docs/outgoing-connections.md).

Apple silicon distribution builds include Sparkle updates. Use **Check for Updates…**
in the menu bar, or leave automatic checks enabled to check on every launch and hourly
while running. Available updates open Sparkle's update window; choose **Install and Relaunch**
when prompted. Disabling automatic checks disables both launch and scheduled checks.
Automatic installation is disabled. Settings and consent choices survive
updates; an already-enabled older network extension is submitted to macOS for replacement
on launch. macOS can require approval or a restart. Development and Intel builds do not
start the updater. See [publishing releases](../../docs/releasing.md).

For repeatable distribution builds from the repository root, use `./build.sh`.
GitHub Actions also supports [signed distribution builds](../../docs/ci-signing.md)
on `main` and manual runs, using repository secrets and a temporary keychain.
It automatically selects the sole valid Developer ID Application identity and
uses the saved `sentinel-beta` notarytool Keychain profile. If more than one
identity is installed, set `BOXCOP_SIGNING_IDENTITY` to the intended certificate
SHA-1. `BOXCOP_NOTARY_PROFILE` and `BOXCOP_PYTHON` override the Keychain profile and
Python 3.12 executable. The canonical directory for local credentials and private
configuration is `~/.sentinel-lab/`; distribution provisioning profiles live in its `profiles/`
subdirectory. Signing private keys and notarization secrets remain in Keychain.
See [profile filenames and overrides](../../docs/outgoing-connections.md#build-provisioning).
Both provisioning profiles are required by default; missing profiles stop the build.
The extension build number defaults to the current Unix timestamp, shared with CI;
`BOXCOP_EXTENSION_VERSION` can override it with an increasing positive integer.
Use the lower-level `--profile limited-development` only for development validation.
The output defaults to a new timestamped folder in Downloads, or pass an explicit
new output directory. Share the resulting `BoxCop.dmg`. It opens as a fixed installer window that
shows BoxCop, an arrow and the `Applications` shortcut; drag BoxCop across, then eject the disk image and launch BoxCop from Applications. This builds the current
working tree, including local changes, and does not install or publish it.

```sh
./build.sh
./build.sh /absolute/new-distribution-release
```

Every build downloads and verifies the pinned MiniLM artifacts in its isolated
build directory and bundles the hash-locked inference runtime. It does not depend
on a developer's `.local` model cache. Frozen classifier inference must pass
before and after signing; missing model files or dependencies stop the build.
Qwen workflow review uses the bundled llama.cpp runtime and downloads its pinned weights on first use; no Ollama installation is needed.

The lower-level builder remains available:

```sh
# Local validation artifact: ad-hoc signed, unhardened, NOT for distribution.
python3.12 desktop/macos/scripts/build_app.py --profile limited-development --output /absolute/new-limited-development-build

# Full distribution; channel changes do not change protection capabilities.
BOXCOP_CHANNEL=stable ./build.sh

# Nonprivileged regression suite and complete scenario/defer ledger.
python -m tools.evals.beta_suite --output /absolute/new-beta-evidence
```

Ad-hoc local builds cannot validate hardened library loading because they have no
Team ID; they are explicitly unhardened and not distributable.
The certificate path uses secure timestamps, hardened runtime, post-signing engine
smoke tests, restricted-entitlement checks, notarization acceptance, stapling and
Gatekeeper assessment for both the app and DMG before exporting the disk image. A rejected submission never
publishes the app. Interactive SIP-enabled TCC/guard/browser/vendor acceptance is
still required; neither signing nor component regressions establish full coverage.

[Beta scenario scope](../../artifacts/beta-scenario-scope.json) preserves all 137
workbook contracts: 17 are deferred for ES-dependent native enforcement (including
D10's current ES-backed network control); 120 remain eligible but unqualified.
The beta scenario test set excludes deferred rows. Existing pure core/hook tests
may test narrower reusable components, including components useful to deferred
scenarios; no ES service or privileged lab suite is invoked by the beta runner.
Seven explicit risky/benign policy-route regressions are linked to workbook IDs;
provider, browser, agent, classifier and workflow suites supply additional component
regressions. Gaps in non-ES scenarios remain backlog, not entitlement exclusions.


**Development default (2026-10-26):** opening BoxCop now starts monitoring and
all implemented collectors automatically, including the browser receiver, AX
selected text, clicks, home-folder changes, risk screenshots and diagnostic logs.
The main window has Pause/Resume, status and recent activity; detailed controls
are under Advanced. macOS permissions still apply. The Chrome extension defaults
to all HTTP(S) sites and selected-text collection; reload it and existing tabs
once after updating. Older opt-in instructions below describe the production
settings preview (`--production-mode`), not the development launch defaults.


A native **menu-bar endpoint prototype**, not a webview around the lab. It reuses the existing policy engine in a bundled child process over private inherited pipes. No HTTP service, developer API token, separate Python installation, or SSH tunnel is needed by the packaged app.

**Start here:** [user installation, verification, privacy and removal](../../docs/getting-started.md).
The main app now includes a coverage/setup panel, bundled browser extension and offline guide.
Development defaults above are current; `--production-mode` is an opt-in settings preview,
not a signed production release.

**Validation:** real GUI paste, supported agent CLI hooks and configured privileged
controls have been exercised in the dedicated VM. Production signing, supported
privileged installation and host acceptance remain outstanding. See
[readiness review](../../research/user-readiness-review.md).

The standard build includes user-level clipboard guarding, collection, agent hooks
and advisory inventory. It does not install the root service or network filter.
Command-V guarding is not universal paste or network mediation. Agent hooks remain
active when app collection is paused or the GUI quits, while the app stays installed.

## Build on a Mac

Prerequisites for the **builder**: macOS 14+, Apple Command Line Tools/Xcode with Swift 5.9 or newer, and Python 3.12. App users do not need Python. The first build downloads hash-locked Python packages from PyPI; the installed app makes no such download.

From the repository root:

```sh
python3.12 desktop/macos/scripts/build_app.py \
  --output "$HOME/Desktop/BoxCop-build-01"
```

Use a new output directory each time. The script refuses to overwrite an existing app/archive, refuses Linux, and checks its native binaries really are Mach-O. It runs Swift tests, builds the native executable and standalone Python sidecar for the current Mac architecture, exercises that sidecar from an unrelated directory, signs nested code ad hoc, verifies the signature, and creates:

- `BoxCop.app`
- `BoxCop.dmg` (compressed disk image with BoxCop.app, an Applications shortcut, the BoxCop volume icon and a Retina background. The pinned `dmgbuild` in `requirements-dmg.txt` writes the Finder layout directly, so it needs no Finder automation. Edit `Resources/dmg/background.svg`, then export `background.png` at 660×360 and `background@2x.png` at 1320×720. Keep the arrow between the icon positions in `DMG_ICONS`.)
- `build-evidence.json` — records what actually ran; interactive native acceptance remains `NOT_RUN` until performed separately.

The build is architecture-specific, not a universal binary. Run separate verified builds for Apple Silicon and Intel before claiming both. Build intermediates remain in `.build-artifacts/` for diagnosis and are Git-ignored.

**Signing:** the builder defaults to the full distribution profile and fails without its signing and provisioning requirements. Ad-hoc builds require an explicit development profile. `./build.sh` produces a full distribution candidate using locally configured credentials. The repository contains no credentials. The recorded October 29 beta passed notarization and scoped VM acceptance; a changed build needs its own verification. Do not disable Gatekeeper or SIP or remove quarantine to make a downloaded artifact run.

### CI builds (WarpBuild Macs)

`.github/workflows/macos-app.yml` runs the same `build_app.py` on the WarpBuild runner `warp-macos-26-arm64-6x` (Apple Silicon, arm64). All CI jobs, including `release.yml`, run on WarpBuild runners. The Intel (x86_64) job is disabled because WarpBuild has no Intel macOS runners. First, `scripts/ci_swift_tests.sh` runs the Swift tests with streamed output and a 120 s deadline per run, and repeats the real-process tests. If a run hangs, the script records `sample` call graphs and fails. Each job then builds the native app and frozen engine, smoke-tests the bundled engine from an unrelated directory, signs ad hoc, verifies the signature, then runs `scripts/ci_launch_smoke.sh`. The launch smoke opens the app and checks that it stays running and starts no engine and no audit database before consent. The run uploads `BoxCop-macOS-arm64` / `BoxCop-macOS-x86_64` artifacts containing `BoxCop.dmg`, `build-evidence.json`, bundle details, the launch-smoke log, a first-run screenshot and the Swift test logs. To download one from an BoxCop checkout: `gh run download RUN_ID -n BoxCop-macOS-arm64`. On a pull request, a failed upload, such as when the organization's artifact storage quota is used up, does not fail the job; the run's annotations show the upload error and the run has no artifact to download.

A CI artifact is an **ad-hoc, non-notarized development build**. A downloaded copy is quarantined, so macOS blocks the first open. Use **System Settings → Privacy & Security → Open Anyway** for that one app. Do not disable Gatekeeper or strip quarantine. You can also build locally with the command above; a local build is not quarantined. CI does not grant Accessibility, read a clipboard or press Command-V, so the interactive checklist in `docs/macos-validation.md` is still required.

After a successful native build, put the app in `/Applications` or `~/Applications` before granting permissions or opting into login startup. Follow `../../docs/macos-validation.md` from the repo root (`docs/macos-validation.md`) to validate the installed copy. Do not perform testing with real patient, personnel, or credential data.

## Data and trust

- Native data lives in `~/Library/Application Support/BoxCop/`, independently of the lab's `.local/` directory. The sidecar creates private state, with no raw clipboard previews or persistent content fingerprints.
- The existing Engine/Store retains timestamps, sanitized structured metadata, policy IDs, labels and decisions. Sensitive clipboard text is transient while evaluating. Memory, OS clipboard, swap, crash dumps and user backups are not secure-erasure guarantees.
- App identity is observed; role remains a user-selected declaration. Decisions are narrow deterministic heuristics. `allow` means no enabled rule matched, not that the content is safe.
- Local AI review runs on the Mac. [Crash reports and written alert feedback](../../docs/product-reports.md) are separate optional submissions to BoxCop, without attached monitored content or usage analytics. Crash reporting is off by default.
- Team reporting for company-managed Macs is an explicit engine mode (`--team-reporting`) in current source, not in any recorded build, and has no native enrollment UI or background scheduler. A separate [web management console and TypeScript/PostgreSQL service](../../team/README.md) manage enrollment and audit metadata. After a confirmed enrollment the Mac reporter reads the local audit read-only and sends only allowlisted decision metadata. See [team reporting](../../docs/team-reporting.md).
- A same-user malicious program, root, compromised app bundle or OS is outside the pipe trust boundary. Separately provisioned privileged layers have their own policy boundary.
- No automatic audit expiry has been added. Pause first before intentionally managing stored audit data; do not assume quitting deletes history.

## Development checks

Portable Swift core tests:

```sh
cd desktop/macos
swift test
```

Python desktop/packaging tests (from repo root):

```sh
env -u PYTHONPATH -u PYTHONHOME PYTHONDONTWRITEBYTECODE=1 \
  .venv/bin/python -m pytest -p no:cacheprovider \
  tests/test_desktop.py tests/test_macos_packaging.py -q
```

Linux Swift tests can use the pinned official image `swift@sha256:73f569f5536fe3c9ad5109eb4622c5560af7424d55304955190e5fbccc047b86`. They test portable code, **not AppKit, SwiftUI, event taps, TCC or macOS signing**.

A standalone engine can be checked with `scripts/smoke_engine.py --engine ABSOLUTE_EXECUTABLE --scratch NEW_PRIVATE_DIRECTORY`. It sends fake inputs to the actual executable, checks clean/warn/block decisions and readback, and scans the resulting audit files for the fake raw marker. It reports its platform explicitly.

## Sources and interface

The frozen pipe protocol and file ownership are in `docs/plans/2026-10-23-macos-endpoint.md`. Primary API references:

- Apple NSPasteboard: https://developer.apple.com/documentation/appkit/nspasteboard
- Apple pasteboard access behavior: https://developer.apple.com/documentation/appkit/nspasteboard/accessbehavior-86972
- Apple event tap: https://developer.apple.com/documentation/coregraphics/cgevent/tapcreate(tap:place:options:eventsofinterest:callback:userinfo:)
- Apple login-item registration: https://developer.apple.com/documentation/servicemanagement/smappservice/register()
- PyInstaller platform requirements: https://pyinstaller.org/en/stable/operating-mode.html

## Development diagnostics and real GUI harness

Paste-protection lifecycle diagnostics are always written to the macOS unified log
under `app.boxcop.monitoring` (categories `paste-tap` and `recovery`):

```sh
/usr/bin/log show --last 1h --style compact --info --predicate 'subsystem == "app.boxcop.monitoring"'
```

These entries record Secure Input, Accessibility loss, tap timeout/user-input
notifications, creation failures, retry delays, and successful starts. They contain
no clipboard contents, keystrokes, or window titles. Paste-tap recovery is separate
from engine recovery: while monitoring and paste protection remain enabled, it
retries after 2 seconds with exponential backoff capped at 60 seconds, waiting for
Accessibility access and Secure Input to clear. A stable minute resets the backoff;
pause or disabling paste protection cancels recovery. Manual Retry remains available.

Enable **Write local development log** in the app, or launch a development bundle with
`BOXCOP_DEV_LOG=1`. The log is
`~/Library/Application Support/BoxCop/development.jsonl` (0600, encrypted, bounded to 1 MiB).
See [journal encryption and export](../../docs/journal-encryption.md).
It records shortcut presses, clipboard revisions, process IDs, tickets, engine decisions,
gate resolution/staleness and actual pass-through decisions. It contains no clipboard
text, window titles or URLs. It cannot prove the destination inserted text. Disabling
logging stops new entries; the existing file remains. At the size limit older entries
are discarded. Queue drops/write failures are shown in the UI.

The **Retry shortcut guard** button now clears cached failures and restarts the gate
when it is already active. Checks run asynchronously; paste remains allowed until
a completed block decision is available for the current clipboard and destination.

The paste test lives inside **BoxCop.app**, using its existing Accessibility
identity. Enable development logging, then click **Run in-app paste test**. It
opens a dedicated text field in BoxCop and sends actual Command-V events through
the same event tap and policy engine. No separate harness app is installed.

For automation, quit BoxCop and launch with explicit dev flags:

```sh
python3.12 desktop/macos/scripts/paste_harness.py --report "$PWD/.context/paste-report-NEW.json"
# Equivalent launch flags:
open -n /Applications/BoxCop.app --args --dev-paste-test --dev-report "$PWD/.context/paste-report-NEW.json"
```

The test requires existing monitoring/guard consent and BoxCop's Accessibility
permission. The explicit dev invocation starts the consented monitoring session,
enables diagnostic logging, and leaves BoxCop running after completion. It never
grants permissions or changes consent. The UI button writes its report to
`~/Library/Application Support/BoxCop/paste-test.json`.

The test overwrites the clipboard with fake text, waits for prepared decisions,
and checks that harmless pastes insert while known credential blocks stay held. It
aborts if the test window loses focus or the guard becomes inactive. A BLOCKED
result is not a pass. This validates a native text target inside BoxCop, not all
third-party apps; Conductor-specific behavior still needs a separate reproduction.

For VM acceptance, use a logged-in macOS desktop with a checkpoint before permission
grants and another after explicitly granting Accessibility to BoxCop. Exercise
permission denial/revocation, guard allow/block, focus changes, expired retries and
pause/resume against that same built artifact. The automated GUI harness currently
covers only first-hold/second-press allow and sensitive refusal; the remaining cases
still use `docs/macos-validation.md`. The project uses a dedicated macOS VM for runtime acceptance.
A headless process smoke or passing Swift tests cannot substitute for this GUI test.

Optional window-title collection is sampled every two seconds with bounded AX messaging
timeouts, at most one read in flight, password-manager exclusion, stale-result rejection,
and explicit unavailable events. Titles are capped at 512 characters and can contain
private information. Turning collection off clears the in-memory timeline; exported
files are not deleted. Neither the timeline nor window titles are uploaded automatically.

## Collection coverage

See [collection parity and event contract](../../docs/collection-parity.md) for the v2 event format, browser/agent setup, extra native collectors, retention, tests and remaining Ent-parity gaps. These observations are not yet consumed by a model or used to relax deterministic policy.

### Personal interface

The native window follows the personal BoxCop study linked from PR #1:
Protection, Connections, Activity and Settings. Menu-bar destinations open those
same sections. Protection groups existing evidence by outcome; connection cards
expand into the existing setup and removal controls. The app still uses BoxCop
bundle IDs, installation paths and service names.

Settings now includes [personal and team modes](../../docs/team-mode.md): account-bound
invitations, automatic decision reporting and locked team settings. Team mode
requires a new server release and signed app build. Pause semantics are unchanged. The development profile and its collection defaults remain
in effect. Activity distinguishes the in-memory workflow from saved artifacts;
“Clear live view” only clears that workflow.

Render all four actual SwiftUI sections without starting collection or installing
hooks (no engine or lifecycle activation):

```sh
swift build --package-path desktop/macos
desktop/macos/.build/debug/BoxCop --dev-interface-preview "$PWD/.context/ui-preview"
```

The preview uses isolated preferences and the model's initial state. These images
verify layout, not live enforcement or macOS permission grants.

### BoxCop branding and setup

The distributed bundle is `BoxCop.app`; the executable and bundle identifier remain `BoxCop` and `local.sentinel.endpoint` to preserve TCC identity, the CLI protocol and existing local data. When upgrading from `BoxCop.app`, quit the old app first. Existing hooks and browser-host registrations that contain its absolute path must be repaired from Connections after installing BoxCop. The website mark is vendored from https://getallay.ai/mark.svg in `Resources/BoxCopMark.svg`, with matching native paths in `BoxCopMark`. The menu-bar mark is a monochrome macOS template image with a blue dot while monitoring and an orange dot when requested protection is down; the Finder icon uses the website color.

First-launch setup persists its position across permission-related restarts. Selected permission steps wait for actual macOS authorization; requesting permission alone never completes a step. Optional capabilities can be deselected before requesting permissions. The assistant stays available in Settings, and in the menu bar until setup is finished.

## Scenario implementation readiness

The [full readiness queue](../../docs/scenario-readiness.md) maps all 137 scenarios
to explicit first slices and shared controls. Start with owned presentation
qualification, then native paste and installed command hooks. General meeting,
send/upload and agent action controls require their own integration boundaries.
Direct Entire Screen sharing remains unsupported; the protected output window does
not qualify it. See [execution evidence](../../docs/scenario-qualification.md) for
current results and failures.

The owned presentation route uses native window pixel scale for OCR. A low-confidence
text region may be retried on the same image with language correction disabled;
exact text agreement and the existing 0.8 confidence threshold are required. Disagreement,
incomplete evidence and stale completion still hold the output. The generic visual
collector keeps its existing default behavior for other callers.

Detected QR codes now pause the owned presentation, including public codes. The
QR check inspects the same captured image before release; missing detector results
hold the output. OCR uses bounded 2x preprocessing for images up to 2048 pixels per
dimension, retaining the existing confidence threshold and capture expiry. General
QR detection, every-frame coverage and meeting receiver acceptance still need
broader qualification.

The VM-only controlled receiver fixture and offline frame-review commands are
documented in [screen-share evaluation](../../docs/screen-share-evaluation.md#controlled-receiver-recording-local-webrtc-checked).
The current candidate passes 28/28 local-output checks. The first local WebRTC
recording passed inspection of all 53 decoded frames; Zoom/Meet and full-contract
qualification remain open.

The separate browser paste fixture now checks eight synthetic risky/benign cases
on both first paste and retry against independent HTTP receipt bytes. An unguarded
fake-secret control proves the input and sink route works; the native preflight
checks guard readiness. See [VM instructions](../../docs/macos-vm-lab.md#browser-paste-effect-checks)
and [evidence](../../artifacts/paste-egress-v4.json). This does not qualify browser
account/origin binding, alternate paste routes or a final-send/upload gate.

The earlier paste-qualified candidate passed 49 browser paste/control checks, including clipboard
replacement, tab changes, app focus return and both common modified paste shortcuts.
The earlier Command-Option-Shift-V bypass is fixed: Command-Shift-V and
Command-Option-Shift-V now use the same fresh clipboard/app gate as Command-V.
Both risky and benign first-paste/retry effects were verified. Menu actions and
remapped shortcuts remain outside the interception boundary.

Live Terminal testing now passes 30 input checks, including substituted browser
copy text, invisible command controls, credential-file reads and destructive
commands. All text goes to an inert receiver; commands are never executed.
Typed and menu routes remain uncovered.

Expanded protected-presentation testing found a medical-record gap: a fictional
named patient record was readable by OCR but released to the owned output.
The generic health-article control remained visible. Medical-record sharing
protection is not qualified; see the live VM campaign for this failure.

Real Zoom meeting-chat testing also passes seven checks: a fake credential stays
out on first paste and retry, while an ordinary agenda link reaches the isolated
receiver. This covers native Command-V text paste; attachments and final-send
mediation remain unqualified. The non-ES campaign has 33 scenarios with scoped
live evidence, two live failures and 85 documented missing-control blockers.

The installed app also exposes the opt-in [reviewed text transfer CLI](../../docs/reviewed-transfer.md): full native preview, macOS owner authentication, and one-use exact-byte dispatch. This does not intercept other apps or authenticate provider accounts.

### Automatic background screen warnings

While monitoring runs, background screen warnings default on and resume with the
monitoring session. Screen Recording permission is required; this path never opens
a window picker or requests permission automatically. Connections has persistent,
profile-specific switches for background checks and full-screen warnings. Disabling
checks stops capture and dismisses warnings; Pause, sleep and engine failure do too.
It does not independently enable monitoring consent or launch at login.

All current displays are checked sequentially, with five seconds between completed
scans. Checks run outside meetings too. Sensitive text detected by the existing
screen policy opens an opaque, nonactivating warning over each display. Turn off
“Cover all displays” for a compact warning instead. Dismiss snoozes popups for one
minute; checks continue. A clean or unavailable sample clears the cover. No screen
pixels, OCR text or content-specific reasons are saved by this path. Protection and
Connections show permission, incomplete-sample and detection status.

This is reactive assistance, not an outgoing video gate: frames can escape before
detection, window-specific sharing may bypass the cover, and OCR can miss risks.
Full-screen warnings can appear in a desktop share. Receiver behavior has not been
qualified. The existing Protected Presentation route remains separate.

Manual acceptance for a built app: grant Screen Recording, start monitoring, and
show a synthetic `CONFIDENTIAL` heading. Check all displays receive dismissible
covers without keyboard focus changes; switch to compact mode and repeat. Check
one-minute dismissal, benign recovery, pause/resume, saved off preference after
restart, permission denial/revocation, display changes and sleep/wake. Use only fake
data. Validate desktop and specific-window sharing separately at a real receiver;
local window visibility alone does not establish receiver protection.
