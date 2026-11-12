# Try BoxCop on your Mac

BoxCop beta runs on Apple Silicon Macs with macOS 14 or later. It offers local
clipboard rules, cooperative agent hooks, optional workflow/screen observation and
software exposure findings. This beta uses Developer ID signing and Apple
notarization. It does not require Endpoint Security permission or changes to SIP.

## Install

Download the beta ZIP, extract it, and move **BoxCop.app** to **/Applications**
before opening it or granting permissions. Keep that location when updating:
browser registration and agent hooks refer to it. Quit any older BoxCop first.
The distributed beta currently supports Apple Silicon; no Intel release is included.
Users do not need Python, a model download, an API key or a subscription for local
paste protection. Keep SIP and Gatekeeper enabled. If macOS rejects the package,
stop and report the error rather than bypassing its checks.

Builders can find development and notarized-release commands in
`desktop/macos/README.md`. Ad-hoc CI/local builds are validation artifacts, not the
notarized beta download.

## First launch and verification

The beta starts stopped and uses separate consent preferences from development
builds. Nothing is automatically enrolled in agent hooks. Optional collectors are
chosen for each launch; monitoring, guard, notifications and auto-start choices
are saved separately. The **Protection**, **Connections**, **Activity** and
**Settings** pages explain active coverage.

1. In **Protection** (or **Settings → Monitoring consent**), enable monitoring
   consent, then **Start monitoring**. Monitoring records bounded local workflow
   metadata and evaluates newly copied plain text; it does not inspect the existing
   clipboard on Start. It does not enable the paste guard by itself.
2. In **Protection → Sensitive data → Command-V guard**, enable **Hold standard
   ANSI Command-V for a local rule decision**. Request Accessibility, approve
   BoxCop in macOS Settings, then use **Retry shortcut guard**. Verify the app
   reports an active guard. If unavailable, it is not intercepting paste.
3. In **Connections → Paste protection → Setup & details**, use **Test paste with
   fake data**. It replaces your clipboard and checks benign insertion and
   synthetic-sensitive refusal in BoxCop's own field. Use only fake data in
   subsequent app tests; this does not prove every destination is protected.
4. For screen/OCR observation, expand **Connections → Mac activity & collection
   choices**, choose the visual collector, and request Screen Recording. Approve
   the macOS switch; Quit & Reopen if requested, then re-enable the optional
   collector. Window-frame observation samples one window of the last external
   app at about 2 FPS. It is not continuous outgoing meeting protection.
5. For Chrome/Chromium, expand its **Connections** card, enable receiving browser
   observations, load the bundled extension folder as unpacked, register its ID,
   and reload the extension and existing tabs. Confirm an actual recent event.
   Browser observations do not block general uploads or sends.
6. For agents, explicitly select **Install / repair supported agent hooks** in
   **Connections → Agent actions**. For Codex, review/trust
   BoxCop in `/hooks`. Check callback evidence after a harmless command;
   registration alone is not enforcement. Hooks remain active after app Pause/Quit.
7. Enable **Launch at login** and auto-start only if desired. Review inventory
   findings as metadata observations, not proof of an exploit or its prevention.
8. Optional: in **Settings → Review before sending email**, turn on one advisory
   reminder per Gmail draft (Chrome/Chromium with the extension and browser receiving
   on). It never blocks sending. The reminder itself uses no subjects, recipients or
   draft text; other collectors you enable keep their own behavior. See
   docs/human-review-reminders.md in the repository.

For a harmless hook check, ask your agent to run `printf 'boxcop-check\n'` and
inspect callback state. Risky synthetic hook tests belong in a disposable test
account/VM. Never test against actual credentials or company documents.

## What actually blocks

Current source builds also offer **Connections → Protected presentation (experimental)**:
start monitoring, grant Screen Recording, refresh the window list, select a source,
and start the presentation. In the meeting picker select **BoxCop Protected Presentation**,
never the original window or entire desktop. The output displays only checked images;
recognized sensitive text or missing/low-confidence/truncated OCR produces a neutral
slate. After revising the source, fresh passing images resume automatically. Pause,
changing the source, and stopping monitoring clear the output; stop sharing in the
meeting separately when finished. Source selection and presentation do not auto-resume
after app relaunch or monitoring pause.

This new route is experimental and is not covered by the October 29 notarized-package
acceptance. OCR can miss sensitive content, including image/QR secrets; frames with no recognized text
are held. It does not filter audio/camera, enforce the meeting's source selection, or
protect direct source/desktop sharing. See [qualification](scenario-qualification.md).

| Layer | Available from standard app | Boundary |
| --- | --- | --- |
| Standard Command-V | With Accessibility and active guard | Rules can hold sensitive/unsupported pastes; menu Paste, uploads, drag/drop and direct reads bypass it |
| Agent preflight hooks | Explicit installation for supported harnesses; vendor trust may be required | Covered tool calls only; indirect scripts, unhooked tools and disabled hooks can evade it |
| Protected presentation (new source feature) | Explicit source selection, Screen Recording and active monitoring | Checks images before displaying them in BoxCop's owned output; meeting must share that output; OCR limitations remain |
| Browser context | After extension setup | Collection, not universal network/upload enforcement |
| Software exposure | Scans after finishing beta setup; refreshes every five minutes and supports manual Recheck | Findings only; no automatic uninstall, patch or execution ban |
| Privileged file/process enforcement | Separate provisioning; not installed by app builder | Tested with root policies in the VM; not automatically enabled on a user's Mac |
| Network filter | Separate signing, provider activation and root policy | Standard app build does not include/activate it; existing flows and allowed endpoints remain limitations |

Endpoint Security and its coupled privileged network control are deferred in this
beta; their implementation remains for a future provisioned release. The beta
rejects their development entrypoints. The VM's disabled-SIP development setup is
not an installation procedure. Never run VM fixture installers on your daily Mac.
Notarization validates the distribution package, not scenario coverage. Supported
paste, capture, browser and hook behavior must still pass interactive acceptance.

## Privacy, pause and recovery

Decisions run locally; no cloud model or automatic telemetry upload is required.
This beta does not include team reporting. A separate source-level pilot lets an
organization explicitly enroll a company-managed Mac and receive allowlisted policy
decision metadata, never content, commands or paths. Its separate web management
console and TypeScript/PostgreSQL service are under [`team/`](../team/README.md);
they do not add reporting to an already installed beta. See
[team reporting](team-reporting.md) in the repository.
After monitoring consent, base collection includes app focus/lifecycle metadata
and new plain-text clipboard evaluation. Window context, selected text, pointer
events, chosen-folder changes, adapter receiving, captures and diagnostics require
separate choices. Browser extension site access is broad HTTP(S) access. These
optional observations can contain private data.
Raw clipboard text is transient; this does not imply all other collected text is absent.

Data is under `~/Library/Application Support/BoxCop/`: workflow journal (bounded
64 MiB), up to 20 screenshots in captures, development log (bounded 1 MiB), inventory
cache and decision databases. Database history has no general age-based deletion.
Exports/backups remain until you remove them. Review files before sharing; do not
post the whole support directory in a public issue.

Pause stops app collectors and shortcut guarding. Agent hooks continue while the
app is paused or quit. Separately installed privileged enforcement has its own
lifecycle; pausing collection does not disable its policy. If benign pastes are held,
read the most recent decision, recheck the guard and copy fresh text. Pausing restores
normal paste behavior but removes shortcut protection. It does not override an agent denial.

## Update or remove

Before replacing the app, quit it and preserve the same /Applications path. Open
the replacement, check permissions/guard, reconnect the browser if needed and restart
agent sessions. There is no signed automatic updater or rollback service yet.

Before deleting the app, use **Remove BoxCop agent hooks** in the setup panel
(or the command below) so agents do not reference a missing executable:

```sh
/Applications/BoxCop.app/Contents/MacOS/BoxCop --host-agent-integrations remove
```

This removes BoxCop-owned hook entries, preserves other integrations and records
an opt-out from automatic registration. Restart agent sessions. Disable Launch at
login in BoxCop. Remove the BoxCop browser extension from each browser. Quit
BoxCop and move the app to Trash. Remove its Accessibility/Screen Recording entries
in System Settings if desired. To erase local history, delete the BoxCop support
directory after quitting; also remove exports/backups separately. Browser native host
manifests named `local.boxcop.collector.json` may be removed from each browser's
`NativeMessagingHosts` directory under `~/Library/Application Support/`.

If you separately installed the privileged service/filter, this procedure is not a
complete uninstall: remove/deactivate that deployment using its administrator's
installation procedure first. Do not delete a provider while its filter is active.

See docs/host-agent-protection.md, docs/software-exposure.md and
research/user-readiness-review.md in the repository for coverage and remaining work.

## Guided setup and privacy

On first launch, BoxCop opens setup. Turn on the protections you want, each with its own button, and approve what macOS asks for in System Settings. Nothing is collected until you turn something on, and Continue is always available. Paste, screen and package protection also start BoxCop's installed-software check, which is listed under Learn More. Screen Recording may require Quit & Reopen; setup returns to the same page. Use Settings → Monitoring permissions → Set up BoxCop to return later.

Paste protection reads copied text and the destination app. Window titles, selected text, clicks, home-folder changes, browser and agent events, and window captures need **Collect app activity** in Settings, or a feature that uses them.

Protection runs on your Mac and works offline. Settings → Crash reports & alert feedback offers optional crash reporting (off by default) and written feedback you explicitly send. Neither attaches monitored content or activity history, and neither collects usage analytics. Optional provider connections make requests to the services you explicitly configure; files you export or share remain under your control. See [crash reports and alert feedback](product-reports.md) for fields, retention and coverage.

BoxCop stays in the menu bar when its window closes. Look for the BoxCop mark near the clock; macOS may hide status items when the menu bar is crowded.
