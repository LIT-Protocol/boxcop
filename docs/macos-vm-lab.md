# Dedicated macOS VM lab

Two test configurations now exist: **BoxCop Lab** retains privileged development
experiments; **BoxCop Beta Acceptance** is the SIP-enabled beta VM. Use the latter
for the ordinary beta and protected-presentation qualification. Confirm `hw.model`,
SIP state and the logged-in synthetic user before running tests; do not change SIP
to make a beta test pass. Its DHCP address may differ from the `boxcop-lab` SSH
alias. Use the runner's explicit hostname override with the existing lab key/host
verification. See [presentation reproduction](screen-share-evaluation.md).

Use a dedicated Apple Virtualization macOS guest named `BoxCop Lab`, with a
synthetic test account, 8 GiB RAM and 64 GiB disk. Keep the user's existing VMs
separate. Disable clipboard sharing; share only a staging directory if needed.
Do not sign into the user's personal Gmail, Slack or Apple account in the guest.

UTM supports scripted lifecycle control through AppleScript and `utmctl`:
https://docs.getutm.app/scripting/scripting/

Check the installed version's AppleScript dictionary, not just current web docs.
UTM 4.6.4 lacks the macOS installation scripting present in 5.0.8. On a macOS 14
host, do not assume newer provisioning or Apple-backend snapshot/disposable-mode
features exist. Make a stopped clone of a prepared baseline instead of promising
snapshot reset. Guest execution/file copying through `utmctl` depends on a guest
agent; this lab uses SSH for macOS guest commands. UTM 5.0.8 labels its input
automation suite QEMU-only, so Apple-backend UI tests must run inside the guest
through guest automation or authenticated Apple VNC rather than `utmctl` input
injection. **Apple-backend VMs do have mouse/keyboard control through VNC.** The
existing `~/.sentinel-lab/vm_control.py` helper can inspect the framebuffer, click,
type, and authenticate using the private lab credentials. Point its SSH tunnel at
the acceptance VM's current IP (a workspace-local copy can add SSH's
`-oHostName=VM_IP` override). Do not confuse UTM's QEMU-only input API with a lack
of guest UI control or ask the user to perform clicks before checking this path.

One-time guest setup:

1. Complete Setup Assistant with a synthetic local account and log into the GUI.
2. Enable Remote Login for that account and configure host SSH key access.
3. Install the same `/Applications/BoxCop.app` and Chrome/Chromium extension.
4. Launch BoxCop normally, or with `--dev-request-permissions`. It requests
   Accessibility then Screen Recording and opens each relevant Settings pane.
   Approve the switches in the guest. macOS still
   owns these permissions; the harness does not bypass TCC. Ad-hoc rebuilds may
   invalidate grants, so stable signing is a remaining automation improvement.
5. Create a stopped baseline clone for repeatable test runs.

Run from the host with an SSH config alias. `--ssh-config` defaults to `~/.sentinel-lab/ssh_config`, so the same dedicated
key and known-hosts file work across worktrees without editing personal SSH settings.
The folder is 0700 and credential/key files are 0600; credentials stay outside git:

- `~/.sentinel-lab/credentials.json`: existing VM username, password and connection
  metadata. `vm_control.py` reads this file for guest VNC authentication.
- `~/.sentinel-lab/meeting-accounts.json`: test accounts for `zoom`, `google_meet`
  and `microsoft_teams`. Each service has `host` and optional `receiver` objects
  with `email` and `password`, plus `meeting_url`; Zoom also has `meeting_passcode`.
  Empty strings mean not configured. These are local plaintext files restricted
  to the host user, shared across workspaces and retained when a workspace is removed.

Read credentials only when needed for the authorized lab task. Never print their
values in logs or chat, copy them into the repository, or include them in eval
artifacts. Preserve existing values when adding services or updating templates.

For an inspected, focused guest login field, `vm_control.py --account-field
google_meet.host.password` (or the corresponding service/role/field) types the
stored value without putting it in command arguments. Stop BoxCop collection
while signing in and restart it before testing. Do not save login screenshots or
meeting URLs in the repository; keep any local diagnostic captures in `.context/`.
`--move X Y` hovers over native controls; `--drag X1 Y1 X2 Y2` arranges guest
windows so both presenter and receiver can be inspected.

```sh
python3 desktop/macos/scripts/vm_lab.py --ssh-host boxcop-lab --output .context/vm-run-001
```

The runner requires `hw.model` beginning `VirtualMac` and the SSH user logged into
the guest GUI, quits/relaunches BoxCop between its three in-app harnesses, and
retrieves collection/paste/visual reports plus synthetic collection events. It never
posts input on the host. It fails when permissions or reports are missing.

Coverage: real paste-event gating, native FSEvents/adapter transport, window capture
and OCR. The separate `tests/vm/browser-collection.cjs` and
`tests/vm/agent-collection.cjs` exercise Chromium and executed tool instrumentation
in the guest. Verified account context, upload completion and power-loss recovery
still need dedicated scenarios. A running VM is infrastructure, not proof
that these scenarios passed.

For browser capture, enable Google Chrome for Testing through the guest's normal
Privacy & Security → Screen & System Audio Recording UI, using VNC and the
private lab login when macOS requests authentication. Launch the browser via
`open -n /path/to/Browser.app --args ...`, then attach Playwright over CDP. Direct
process launch from the SSH session reported no capture access despite a valid
browser grant in the acceptance VM. The receiver harness now uses LaunchServices
starts capture before opening the separate receiver browser to preserve focus,
and binds Chromium's numeric `window:ID:0` capture label to the fixture's output
window ID. These steps do not require changing SIP or writing the TCC database.


## Browser paste effect checks

`tests/vm/paste-egress.py` requires a matching signed candidate already staged at
`/Applications/BoxCop.app` in the SIP-enabled acceptance VM, with existing monitoring
consent and Accessibility permission. Keep the original app separately for restoration.
Start with BoxCop stopped and the guest GUI unlocked; the runner checks VM identity,
both installed executable hashes, foreground application and focused textarea before
posting guest VNC Command-V. It never posts host input.

```sh
uv run --with playwright --with asyncvnc==1.3.0 --with pillow python tests/vm/paste-egress.py \
  --app .context/paste-app/BoxCop.app --hostname 192.168.64.4 \
  --output .context/paste-egress-NEW
```

The fixture uses only fake credentials and public/synthetic text. A loopback Node
server records actual HTTP request bytes independently of the browser field. The
unguarded fake-secret control must arrive before BoxCop starts; the in-app native
preflight must pass before the guarded cases run. First paste and retry are checked
for credentials, mixed redacted/live secrets, OTPs, confidential business text and
four benign contrasts. Clipboard writes explicitly use UTF-8 and are read back
before any keypress. An earlier run exposed SSH `pbcopy` locale corruption of a
Unicode dash; that was a fixture error, not an BoxCop content transformation.

Reports bind the listed implementation/harness sources, native and packaged engine
hashes, and receipt-file hash. The checked-in receipt file contains synthetic text
only. After the run, quit BoxCop and restore the original app. The runner starts
monitoring through the existing consented native test and leaves it running.
The browser route is plain-text Command-V only: account/origin authentication,
menu paste, typing, attachment upload and final send require separate controls.

The extended run also replaces prepared benign clipboard text with a fake secret
at four requested delays (0, 50, 250 and 1000 ms), checks first paste/retry, then
checks benign recovery, a second browser tab, and leaving the browser for Finder
and returning. No keys are posted to Finder. Actual clipboard-write-start-to-key
elapsed times are recorded: these are sequential transition checks, not exhaustive
race scheduling. Tabs share a browser process, so this does not prove recipient or
origin binding. A modified paste shortcut is tested separately; any received fake
secret is reported under `unsupported_routes`, never counted as protected behavior.
The standard shortcut is retested after the alternate route.

The updated candidate also guards Command-Shift-V and Command-Option-Shift-V.
The v3 fixture checks both with risky/benign first-paste and retry receipts; v2's
recorded alternate-shortcut bypass is preserved as historical evidence. This does
not intercept Edit-menu actions or arbitrary remapped shortcuts.

For broader beta fixtures, the acceptance VM now has a separate Python 3.12.13
runtime under `~/SentinelLab/python-runtime/cpython-3.12.13-macos-aarch64-none/`.
This is test infrastructure; the installed app still uses its packaged engine.
`tests/vm/audit-privacy.py` invokes that packaged hook with synthetic secrets,
checks durable decision records and scans existing diagnostics without exporting
private contents. `tools/evals/agent_incident_effects.py` requires SIP enabled and
uses only disposable files and a loopback server; known misses remain misses.

`tests/vm/terminal-paste.py` checks real Terminal Command-V into an inert Node line
receiver, never a command interpreter. It requires existing guest Automation
permission to inspect Terminal's selected tab TTY. Before every paste and Return,
it verifies that the tab's foreground process group is the exact owned receiver.
The fixture records raw input lines independently; absence of command execution
is a limitation of the paste route, not a claim of shell-effect containment.
