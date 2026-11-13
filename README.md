# BoxCop

BoxCop is a Mac app for computers that run AI agents. Agents such as Claude Code,
Codex and Cursor work with your full access, and so does everything they install,
download or write. BoxCop checks what agents install, contains what they run, and
watches what leaves the machine. It runs locally, needs no account, and uploads
nothing. It is licensed under Apache-2.0.

**Let your AI agents work. Keep your machine protected.**

**Status: limited macOS beta.** Each layer below exists and has known limits, which
are listed next to it. BoxCop does not claim complete protection. A layer shows
"On" only while it is enforcing; otherwise it shows "Off", "Needs setup" or
"Unavailable", with the missing step. The app says "Protected" only when the four
enforcing layers are all on.

The product direction is described in
[allayhq/Allay#149](https://github.com/allayhq/Allay/issues/149).

## Who it is for

1. **Developers who use coding agents.** They feel the risk today, and most
   existing tooling targets them.
2. **Anyone who uses a desktop agent.** They cannot evaluate a script, a skill or
   an MCP server, so defaults and plain explanations matter more for them.
3. **Security and platform teams**, later. They need the same protection managed
   across many machines. BoxCop has no team features today.

## The six layers

| Risk | Layer | Built today | Current limits |
| --- | --- | --- | --- |
| An agent installs something malicious: a compromised npm or PyPI release, a fake skill | **1. Install gate** | A local registry proxy refuses npm and PyPI releases listed in a signed feed built from Datadog, OpenSSF and GitHub intelligence. Both tiers are refused: confirmed malware, and releases reported as malware but not yet confirmed. A blocked version fails in the terminal with an error that names BoxCop, while ranges and tags resolve to the highest clean version. Routing for npm and pnpm is opt-in. Skill and instruction files are checked for hostile patterns. | The reported tier includes research and borderline packages, so a legitimate release can be refused; you can allow one exact release of that tier from its event. Confirmed malware cannot be allowed. No minimum release age. No pip or uv routing in the app. No MCP server or extension checks. Skill checks are narrow patterns. |
| Allowed code behaves badly when it runs: an install script sends credentials out | **2. Containment** | npm dependency install scripts run in a sandbox. Their only network path is a local proxy that allows only hosts on its allowlist. Writes to shell and npm configuration are denied. Blocks are reported with the package and the agent that started the install. The same mechanism can run a single command contained from the command line. | Automatic only for npm install scripts. Agent-written scripts, downloaded binaries, MCP servers, pnpm, Yarn and Python installers are not contained automatically. Built on `sandbox-exec`, which Apple has deprecated. |
| Data leaves through any app: a connection to a malware host | **3. Outbound control** | A network system extension records every app's new connections with process and signing identity, and blocks hostnames on a bundled threat list. | Reputation only. No per-app rules. No payload or secret inspection. The list updates only with app releases. Needs the signed build. |
| An agent is steered by hostile content: prompt injection in a page, document or tool result | **4. Agent action checks** | Pre-action hooks for Claude Code, Codex and Cursor deny recognizable credential access, exfiltration and dangerous commands. The app shows whether each hook is installed and has been called. | Allow or deny only: there is no way to let a denied action through once. Cooperative: an effect hidden inside a script evades the hooks. No coverage of desktop agent apps. No prompt-injection detection. |
| The machine is already weak: outdated runtimes and apps | **5. Machine health** | An inventory of apps, Homebrew, Python, npm and runtimes, matched against reviewed findings. Guided updates for a few Homebrew formulae and Pillow. | Findings are hand-reviewed, not general CVE coverage. No Electron or Chromium runtime checks. No scan for plaintext secrets. |
| Too many alerts, or protection applied blindly, so the user turns everything off | **6. Smart triage** | A bundled llama.cpp runtime with a local model reviews linked activity: network history together with the install gate, containment and agent check events. It returns concerns that cite the events they rest on, and the explanation appears on those events. One model runtime runs at a time. | Advisory only. It does not yet choose which protections apply. The model is a 2.7 GB download on first use, and is not downloaded unless the disk has room for it plus 4 GB. It uses about 3 GB of memory while running. Checked with a real model on the development Mac, not yet inside the VM lab; treat it as experimental. |

[docs/layers.md](docs/layers.md) describes each layer, the files that implement it,
and the reference tools we compare against.

## Smart triage

Strong protection has a cost. Sandboxing everything breaks things, and prompting
for everything trains people to click Allow. The plan is to apply heavy protection
only to what is new or suspicious and let the rest run quietly.

1. **Deterministic signals decide most cases.** Known-bad is blocked. Long-used,
   signed software runs normally. Something is "new" when it is first seen on this
   Mac, recently published, unsigned, just downloaded, written by an agent in this
   session, or contacting a destination never seen before.
2. **New things are contained by default.** They run inside the containment layer
   with a narrow allowlist. This needs no model.
3. **The model reviews what is left.** It reads the script or package, the chain
   that led to it (agent, command, script, connection) and what it tried to do.
   It explains the event in plain language, recommends allow, keep contained or
   block, and drafts the narrowest exception that would let legitimate work continue.

Today only the explanation and review parts of step 3 exist. Steps 1 and 2 are on
the [roadmap](docs/roadmap.md).

Rules for the model:

- **It may tighten protection on its own, never loosen it.** Loosening needs the
  user. The model reads attacker-controlled text, so a prompt injection must not be
  able to grant access. In the code, no model output changes a policy, allows an
  action or lifts a block.
- **Local by default.** The inference runtime ships in the app and the model runs
  on this Mac.
- **Fails safe.** If the model is unavailable, the deterministic layers still apply.

## Install and build

BoxCop has no public download yet, and this repository is not public yet. With
access to it, build BoxCop on a Mac running macOS 14 or later with Xcode Command Line Tools, CMake and Python 3.12.

**Signed build with every layer.** This needs a Developer ID Application
certificate, the two provisioning profiles and saved notarization credentials; see
[docs/releasing.md](docs/releasing.md).

```sh
./build.sh
```

The result is a new `BoxCop-beta-<timestamp>` folder in `~/Downloads` containing
`BoxCop.app`, `BoxCop.dmg`, `BoxCop.dSYM` and `build-evidence.json`.

**Limited-development build.** Ad-hoc signed, no certificate needed. It has every
layer except outbound control, because macOS only loads a network extension from a
Developer ID signed app.

```sh
python3.12 desktop/macos/scripts/build_app.py --profile limited-development --output /tmp/boxcop-dev
```

`build.sh` configures the install gate's malware feed for you. For a
limited-development build, set the three `BOXCOP_PACKAGE_FEED_*` variables shown
in [docs/package-registry-firewall.md](docs/package-registry-firewall.md); without
them the install gate shows "Unavailable".

**Tests.**

```sh
python3.12 -m venv .venv
.venv/bin/python -m pip install -r requirements.txt
.venv/bin/python -m pytest -q tests
swift test --package-path desktop/macos
```

[docs/getting-started.md](docs/getting-started.md) covers first launch, the
built-in test for each layer, `BoxCop --status` and removal.

## Testing in the VM lab

Layers that change system state (the network extension, package manager routing,
agent hooks) are accepted in a dedicated macOS virtual machine with System
Integrity Protection enabled, not on a developer's own Mac.
[docs/vm-lab.md](docs/vm-lab.md) describes the lab and how to reach it.

## Repository layout

| Path | Contents |
| --- | --- |
| `server/` | The Python engine: registry firewall, install script containment, agent hooks, software inventory and remediation, smart triage. Frozen into the app as `boxcop-engine`. |
| `desktop/macos/` | The Swift app (`BoxCop`), shared core (`BoxCopCore`), network extension (`BoxCopNetworkFilter`), build scripts and resources. |
| `tools/` | Command-line tools: malware feed publisher, skill scanner, software inventory. |
| `tests/` | Python tests for the engine and the build pipeline. Swift tests live in `desktop/macos/Tests`. |
| `docs/` | One document per layer, plus build, release and lab guides. |
| `research/aikido/` | Notes on the closest competing product. |
| `website/` | The product site. |
| `brand/` | Icon and mark artwork. |
| `build.sh` | The signed, notarized distribution build. |
| `LICENSE`, `NOTICE` | The Apache-2.0 license text and the attribution notice. |
| `update_from_feed.sh` | Daily review of public security feeds; see [docs/security-feed-review.md](docs/security-feed-review.md). |

## Principles

1. **Prevent, don't just detect.**
2. **Assume unfamiliar code may be malicious**, whether or not it has a known signature.
3. **Use context.** New, unsigned, agent-written or just-downloaded code deserves
   tighter limits than software the user has run for years.
4. **Stay quiet.** Ordinary work should not be interrupted.
5. **Claim only what is tested.** Show "Protected" only when enforcement is active;
   otherwise say what is off, needs setup or is unavailable.
6. **Local first.** No account, and nothing uploaded by default.

## Relationship to Allay

BoxCop was ported from [allayhq/Allay](https://github.com/allayhq/Allay) at commit
`2e2552da`. It keeps the six machine-protection layers. Allay's monitoring features
(screen and clipboard collection, the paste guard, the browser extension), its
review reminders and its team features were not carried over.

Three things still carry the old names, on purpose:

- **Bundle identifiers.** The app is `local.sentinel.endpoint` and the network
  extension is `local.sentinel.endpoint.network-filter`. The Developer ID
  provisioning profiles we hold are bound to these identifiers. New identifiers
  need new profiles from Apple, so they stay until those exist.
- **The package malware feed.** BoxCop reads the existing signed feed at
  `https://getallay.ai/package-feed/v1/policy.json` (payload schema
  `allay.package-policy.v1`) until it hosts its own.
- **The lab directory.** Signing profiles and VM access live in `~/.sentinel-lab`
  on the development Mac.

## Competition

Aikido's Device Protection is the closest product. It gates packages, IDE and
browser extensions and agent skills, with central management, and is sold to
security teams. Our notes from installing and testing it are in
[research/aikido/README.md](research/aikido/README.md).

## License

BoxCop is licensed under the Apache License, Version 2.0. The text is in
[LICENSE](LICENSE) and attribution is in [NOTICE](NOTICE).

Bundled data and software keep their own licenses. In particular, the threat
domain list used by outbound control is the HaGeZi Threat Intelligence Feeds list,
licensed under GPL-3.0. It ships as a separate data file with its own license and
notice in `desktop/macos/Resources/ThreatDomains/`, and is not part of the
Apache-2.0 licensed code. The package malware intelligence, Sparkle, llama.cpp and
the local model each carry their own license, listed in [NOTICE](NOTICE).

The GitHub repository is still private. The license is in place; the remaining
steps before the repository is opened are on the [roadmap](docs/roadmap.md).
