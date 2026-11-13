# BoxCop

Local protection for Macs that run AI coding agents.

BoxCop checks package installs, contains npm install scripts, blocks connections
to known threat domains, and checks agent actions before they run. It runs on your
Mac without an account. Experimental local AI triage helps explain security events.

**Status: macOS beta.** Coverage is incomplete and depends on which protections
you enable. BoxCop shows the state of each layer; see the limits below before
relying on it.

## What it does

| Risk | Layer | Built today | Current limits |
| --- | --- | --- | --- |
| An agent installs something malicious: a compromised npm or PyPI release, a fake skill | **1. Install gate** | A local registry proxy refuses npm and PyPI releases listed in a signed feed built from Datadog, OpenSSF and GitHub intelligence. Both tiers are refused: confirmed malware, and releases reported as malware but not yet confirmed. A blocked version fails in the terminal with an error that names BoxCop, while ranges and tags resolve to the highest clean version. Routing for npm and pnpm is opt-in. Skill and instruction files are checked for hostile patterns. | The reported tier includes research and borderline packages, so a legitimate release can be refused; you can allow one exact release of that tier from its event. Confirmed malware cannot be allowed. No minimum release age. No pip or uv routing in the app. No MCP server or extension checks. Skill checks are narrow patterns. |
| Allowed code behaves badly when it runs: an install script sends credentials out | **2. Containment** | npm dependency install scripts run in a sandbox. Their only network path is a local proxy that allows only hosts on its allowlist. Writes to shell and npm configuration are denied. Blocks are reported with the package and the agent that started the install. The same mechanism can run a single command contained from the command line. | Automatic only for npm install scripts. Agent-written scripts, downloaded binaries, MCP servers, pnpm, Yarn and Python installers are not contained automatically. Built on `sandbox-exec`, which Apple has deprecated. |
| Data leaves through any app: a connection to a malware host | **3. Outbound control** | A network system extension records every app's new connections with process and signing identity, and blocks hostnames on a bundled threat list. | Reputation only. No per-app rules. No payload or secret inspection. The list updates only with app releases. Needs the signed build. |
| An agent is steered by hostile content: prompt injection in a page, document or tool result | **4. Agent action checks** | Pre-action hooks for Claude Code, Codex and Cursor deny recognizable credential access, exfiltration and dangerous commands. The app shows whether each hook is installed and has been called. | Allow or deny only: there is no way to let a denied action through once. Cooperative: an effect hidden inside a script evades the hooks. No coverage of desktop agent apps. No prompt-injection detection. |
| The machine is already weak: outdated runtimes and apps | **5. Machine health** | An inventory of apps, Homebrew, Python, npm and runtimes, matched against reviewed findings. Guided updates for a few Homebrew formulae and Pillow. | Findings are hand-reviewed, not general CVE coverage. No Electron or Chromium runtime checks. No scan for plaintext secrets. |
| Too many alerts, or protection applied blindly, so the user turns everything off | **6. Smart triage** | A bundled llama.cpp runtime with a local model reviews linked activity: network history together with the install gate, containment and agent check events. It returns concerns that cite the events they rest on, and the explanation appears on those events. One model runtime runs at a time. | Advisory only. It does not yet choose which protections apply. The model is a 2.7 GB download on first use, and is not downloaded unless the disk has room for it plus 4 GB. It uses about 3 GB of memory while running. Checked with a real model on the development Mac, not yet inside the VM lab; treat it as experimental. |

See [protection layers](docs/layers.md) for implementation details and the
[roadmap](docs/roadmap.md) for planned work.

## Build from source

Requires macOS 14 or later, Xcode Command Line Tools, CMake, and Python 3.12.

```sh
git clone https://github.com/LIT-Protocol/boxcop.git
cd boxcop
python3.12 -m venv .venv
.venv/bin/python -m pip install -r requirements.txt
.venv/bin/python desktop/macos/scripts/build_app.py --profile limited-development --output /tmp/boxcop-dev
```

The development build is ad-hoc signed and excludes outbound control. That layer
requires a Developer ID signed app and provisioned network extension.

The install gate requires an explicitly configured signed malware feed. No feed
is trusted by default; without one it shows "Unavailable". Follow the
[feed configuration and publisher guide](docs/package-registry-firewall.md).

For a signed, notarized distribution build, configure the certificates and
provisioning profiles in the [release guide](docs/releasing.md), then run:

```sh
./build.sh
```

Read [getting started](docs/getting-started.md) for first launch, protection tests,
status checks, and removal. Use a dedicated [macOS VM](docs/vm-lab.md) to test
changes to network extensions, package routing, or agent hooks.

## Contributing

Contributions are welcome: bug reports, documentation, reproducible protection
tests, and code improvements all help. See [CONTRIBUTING.md](CONTRIBUTING.md)
for setup, checks, and pull request guidance. For larger changes, open an issue
first to discuss scope and the protection boundary.

```sh
.venv/bin/python -m pytest -q tests
swift test --package-path desktop/macos
```

## Repository guide

| Directory | Contents |
| --- | --- |
| `server/` | Python protection engine and local triage |
| `desktop/macos/` | Swift app, network extension, build scripts, and Swift tests |
| `tools/` | Feed publisher, skill scanner, and inventory tools |
| `tests/` | Python tests and VM acceptance tools |
| `docs/` | Protection, setup, build, and release guides |
| `website/` | Product website |
| `brand/` | Icons and artwork |

## License

BoxCop code is licensed under [Apache-2.0](LICENSE). See [NOTICE](NOTICE)
for attribution and third-party components.

Bundled data and software keep their own licenses. In particular, the threat
domain list used by outbound control is the HaGeZi Threat Intelligence Feeds list,
licensed under GPL-3.0. It ships as a separate data file with its own license and
notice in `desktop/macos/Resources/ThreatDomains/`, and is not part of the
Apache-2.0 licensed code. The package malware intelligence, Sparkle, llama.cpp and
the local model each carry their own license, listed in [NOTICE](NOTICE).
