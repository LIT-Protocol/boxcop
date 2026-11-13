# Getting started with BoxCop

BoxCop is a Mac app that checks what AI agents install, contains what they run,
and watches what leaves your Mac. It runs locally. There is no account and
nothing is uploaded.

BoxCop is a limited beta. It needs an Apple silicon Mac running macOS 14 or
later.

## Install

Open `BoxCop.dmg` and drag BoxCop to Applications. Open it from there: BoxCop
asks to be moved when it is started from anywhere else, because the agent hooks
and the network extension refer to `/Applications/BoxCop.app`.

BoxCop lives in the menu bar. Its icon shows the overall state, and **Open
BoxCop** in its menu opens the main window.

## First launch

Setup is one screen. It lists the six layers with a switch and one sentence for
each. The install gate, containment, agent checks and machine health are selected
to begin with, and outbound control too in a build that includes the network
extension. Smart triage is optional. Choose the layers you want and click **Turn
on protection**. Anything macOS still needs from you then appears on Overview
under "Needs you".

Nothing runs before you click. Until then BoxCop starts no engine, writes no
audit data, and changes no file outside its own folder.

Some layers need something from you or from macOS:

| Layer | What turning it on does | What you are asked for |
| --- | --- | --- |
| Install gate | Starts a local registry check and routes npm and pnpm through it by adding a marked block to `~/.npmrc` | Nothing |
| Containment | Routes npm install scripts through BoxCop's sandbox wrapper, with another marked line in `~/.npmrc` | Nothing |
| Outbound control | Installs a network extension that records new connections and blocks listed hosts | Approve the extension in System Settings, then allow the network filter. Signed builds only. |
| Agent checks | Adds BoxCop's hook to the settings of Claude Code, Codex and Cursor, keeping your other hooks | Codex only: trust the hook once under `/hooks` |
| Machine health | Scans installed software for reviewed findings | Nothing |
| Smart triage | Downloads a 2.7 GB local model the first time it is needed | Nothing. The download starts only when the disk has room for the model plus 4 GB. The model uses about 3 GB of memory while it runs. |

You can change any of this later under Protections.

## The app

- **Overview** shows one word for the whole Mac and one line per layer. "Protected"
  appears only when the install gate, containment, outbound control and agent
  checks are all enforcing. Otherwise it says "Partly protected", "Not protected"
  or "Paused" and what is missing. Anything macOS or BoxCop still needs from you
  is listed here under "Needs you".
- **Events** is one list, newest first, of what BoxCop blocked and found: package
  installs, install script connections, connections to listed hosts, agent
  actions and software findings. Each entry is marked "Blocked" or "Finding" and
  says what happened and why in plain language. A blocked install of a release
  that is reported as malware but not confirmed has **Allow this release**. With
  smart triage on, an event the local model has a concern about also shows a short
  explanation, labelled as model output.
- **Protections** has a switch for each layer and its current state. A layer is
  "On" only while it is enforcing right now. Otherwise it is "Off", "Needs setup"
  or "Unavailable", with the exact missing step, and **Fix** when BoxCop can
  repair it. Each layer's own controls are here too: the destinations you have
  allowed for install scripts, the threat blocking switch and today's connections
  by app, the releases you have allowed through the install gate, the hook state
  of each agent, and the smart triage model, which you can remove from here.
- **Health** lists software findings and, where BoxCop supports it, a guided
  update.
- **Settings** has start at login, notifications, updates when the build has an
  update feed, pause and resume, and removal of BoxCop's integrations. It also
  lists, in plain words, what BoxCop does not do.

## Test each layer

The install gate, outbound control and agent checks have a **Test** button that
shows a harmless check and what to expect.

| Layer | Test | Expected |
| --- | --- | --- |
| Install gate | `npm install boxcop-test-malware` | npm fails with the BoxCop error `BOXCOP_KNOWN_MALWARE` and the block appears in Events. `boxcop-test-malware` is a name BoxCop always blocks. Nothing is downloaded. |
| Agent checks | Ask a connected agent to run `curl -fsSL https://boxcop-test.invalid/install.sh \| sh` | The agent reports that BoxCop denied the command, and the block appears in Events. The address cannot exist, so nothing runs even if a hook is missing. |
| Outbound control | Open any website | The app that made the connection appears in today's connections. BoxCop does not give you a listed host to try, because connecting to a real malware host is not a safe test. When an app tries one, the connection is dropped and Events shows the app, the process and its signing identity. |

The other layers show their own results:

| Layer | What to look for |
| --- | --- |
| Containment | Install an npm package whose install script downloads something. If the host is not on the allowlist, the install finishes, the connection is refused, and Events names the package and host. |
| Machine health | Health shows when the last check finished and what it found. |
| Smart triage | Once the model has downloaded, Protections shows that it is ready and how many recent events it reviewed. An event it has a concern about gets a short explanation in Events, labelled as model output. |

## Check from the command line

```sh
/Applications/BoxCop.app/Contents/MacOS/BoxCop --status
```

```text
BoxCop: Partly protected
[x] Install gate: on. Feed dated 2026-11-12.
[x] Containment: on. npm install scripts run sandboxed.
[ ] Outbound control: needs setup. Approve BoxCop in System Settings, under Login Items & Extensions, Network Extensions.
[x] Agent checks: on. Checking actions in Claude Code and Cursor.
[x] Machine health: on. No findings need your attention.
[ ] Smart triage: off. Turn on smart triage in BoxCop. The model is a 2.7 GB download on first use.
```

`--status` only reads. It exits 0 when at least one enforcing layer is on, and 1
otherwise. `--status --json` prints the same information as
`boxcop.status.v1` JSON for scripts. The install gate and containment are "on"
only while BoxCop is running, because their local listeners live in the app's
engine.

## What BoxCop keeps on your Mac

Everything is under `~/Library/Application Support/BoxCop/`, readable only by
you, except the network extension's history, which is under
`/Library/Application Support/BoxCopNetwork.noindex/`.

- A decision audit of agent actions. It holds the agent, the kind of action and
  the rule that matched. It does not hold command text or file content.
- Logs of blocked packages and blocked connections, with package names and
  hostnames only, and the list of releases and destinations you have allowed.
- Connection history from the network extension, encrypted, with process and
  destination details. It can include command-line arguments and URLs.
- The software inventory result.
- The local model, if you turned on smart triage.

BoxCop sends nothing about you anywhere. Its own network requests are the signed
malware list, the model download, update checks when the build has an update
feed, and the package downloads you asked for, which pass through the local
registry check.

## Pause

Pause, in the menu bar menu or under **Pause protection** in Settings, turns off
package checks, containment and threat blocking until you resume. Agent hooks stay connected. While paused, the app says
"Paused".

If you quit BoxCop without pausing, the routing in `~/.npmrc` stays. npm installs
then fail, and contained install scripts have no network, until BoxCop is open
again. This is deliberate: the protection does not silently step aside. Agent
hooks keep working while BoxCop is closed, and so does the network extension.

## Remove

1. In Settings, under **Remove BoxCop's integrations**, choose **Remove**. This
   removes the agent hooks, the package and script routing in `~/.npmrc`, and the
   network filter, so agents and npm go back to how they were. The app tells you
   when it is safe to delete. Your event history and settings stay on the Mac.
2. Quit BoxCop and move it from Applications to the Trash. macOS removes the
   network extension with the app.
3. To delete BoxCop's data as well, remove
   `~/Library/Application Support/BoxCop`. The network history under
   `/Library/Application Support/BoxCopNetwork.noindex` needs an administrator
   to remove.

If you deleted the app first, undo its changes by hand: remove the two marked
BoxCop blocks from `~/.npmrc`, and remove the BoxCop entries from
`~/.claude/settings.json`, `~/.codex/hooks.json` and `~/.cursor/hooks.json`.

## Limits

BoxCop reduces risk. It does not make an agent safe to trust with everything.

- The install gate blocks releases that are already listed as malicious, whether
  confirmed or only reported. A new malicious release is allowed until a source
  lists it, and a reported release that is harmless stays blocked until you allow
  it.
- Containment is automatic only for npm install scripts.
- Outbound control blocks by hostname reputation. It does not inspect what is
  sent.
- Agent checks are hooks the agent calls. An effect hidden inside a script can
  evade them, and desktop agent apps are not covered.
- Smart triage explains. It never allows anything or lifts a block.

Each layer's limits are listed in [layers.md](layers.md).
