# The six layers

BoxCop is one app with six layers. Each section says what the layer does, where
it is implemented, what it does not do, and which existing tools we use as a
reference.

BoxCop does not bundle or depend on any reference tool. Each protection is our own
implementation. The reference tools show what people want, set the bar we compare
against, and are where new protections tend to appear first.

## Porting rule

BoxCop is licensed under Apache-2.0, so what it takes from other projects has to
be compatible with that.

- **Permissively licensed tools** (Apache-2.0 or MIT: sandbox-runtime, nono,
  Pipelock core, SkillSpector, agent-scan, OSV-Scanner, Gitleaks, Santa): rules and
  logic may be adapted, with attribution.
- **Copyleft or restricted tools** (Safe Chain is AGPL, LuLu is GPL-3.0, Achilles
  and Socket Firewall Free are PolyForm): reimplement the behaviour from their
  documentation and observed results. Translating their source into ours would
  carry their license with it.
- **Credit the source** of each ported protection in these docs. It is fair to the
  upstream authors and tells users where a rule came from.

Licenses and activity of the reference tools were checked on GitHub in November
2026. None of the tools were run as part of that check, except Aikido's product,
whose notes are in [research/aikido](../research/aikido/README.md).

## 1. Install gate

**What it does.** Blocks npm and PyPI releases that are listed as malicious, at the
moment a package manager asks for them. Denies agent reads and writes of skill and
instruction files that contain hostile patterns.

**How.** A read-only registry proxy on `127.0.0.1:8794` sits between the package
manager and the public registry. The list is a signed snapshot built from Datadog,
OpenSSF and GitHub malware intelligence, verified with a public key pinned in the
app, and refreshed every 15 minutes. It has two tiers, and the proxy refuses both:

- **Confirmed malware.** Refused with HTTP 403 and the code `BOXCOP_KNOWN_MALWARE`.
- **Reported as malware, not yet confirmed.** Refused with HTTP 403 and the code
  `BOXCOP_REPORTED_MALWARE`. You can allow one exact release of this tier from its
  event with **Allow this release**, and remove the exception under Protections.
  Confirmed malware cannot be allowed.

A blocked version stays in the version list, marked deprecated (npm, pnpm) or
yanked (PyPI) with a BoxCop message, and its download answers 403. A range or a
tag therefore resolves to the highest clean version, and an exact request for the
blocked version fails with an error that names BoxCop. The package named `boxcop-test-malware` is always
blocked so the gate can be tested without real malware. Routing npm and pnpm
through the proxy is opt-in and reversible.

| | |
| --- | --- |
| Registry proxy | `server/package_proxy.py`, `server/package_runtime.py` |
| Feed format, signatures, version matching | `server/package_intelligence.py`, `server/package_channel.py` |
| npm and pnpm routing | `server/package_routing.py`, `tools/package_service.py` |
| Feed publisher | `tools/package_feed.py`, `tools/package_publisher.py` |
| Skill and instruction checks | `server/skill_security.py`, `tools/skill_scan.py` |
| Docs | [package-registry-firewall.md](package-registry-firewall.md), [skill-security.md](skill-security.md) |

**Limits.** The reported tier includes research and borderline packages, so a
legitimate release can be refused until you allow it. No minimum release age, so a
malicious release is allowed until a source lists it. The app routes npm and pnpm only; pip and uv work when pointed at
the proxy by hand. Private registries, direct URLs, git dependencies and existing
caches bypass the proxy. No MCP server or editor extension checks. Skill checks are
narrow text patterns.

**Reference tools.**
[Aikido Safe Chain](https://github.com/AikidoSec/safe-chain) (AGPL) and
[Socket Firewall Free](https://github.com/SocketDev/sfw-free) (PolyForm) for
package blocking: reimplement from documented behaviour. Next to bring over:
minimum release age (Safe Chain hides releases under 48 hours old) and pip, uv,
yarn, bun and cargo coverage.
[NVIDIA SkillSpector](https://github.com/NVIDIA/SkillSpector) and
[Snyk agent-scan](https://github.com/snyk/agent-scan) (permissive) for skill and
MCP checks. Our skill policies are original checks informed by SkillSpector's
threat categories. Next: wider pattern categories and local discovery of MCP
servers and skills across every installed agent, with no token or upload.

## 2. Containment

**What it does.** Runs code with limits instead of trusting it. Today that means
npm dependency install scripts: a contained script, and everything it starts, can
connect only to allowed destinations.

**How.** npm's `script-shell` setting points at a BoxCop wrapper. The wrapper
re-executes dependency install scripts under `sandbox-exec` with a profile that
denies all network access except BoxCop's loopback listeners, and denies writes to
shell startup files, `~/.npmrc` and LaunchAgents. A local proxy on
`127.0.0.1:8795` allows a destination only if it is on the built-in list or
allowed by the user for that package. Refused connections are recorded with the
package name and the agent that started the install. The engine's `--contain`
mode applies the same sandbox and proxy to one command given on the command line.

| | |
| --- | --- |
| Wrapper, sandbox profile, allowlist proxy | `server/package_scripts.py` |
| Contained single command | `server/containment.py` |
| Docs | [install-script-protection.md](install-script-protection.md) |

**Limits.** Automatic containment covers npm install scripts only. It limits
outbound connections and a few write paths; a contained script can still read
files and can misuse a host that is allowed. It applies at install time, so code
a package leaves behind runs normally later. `sandbox-exec` is deprecated by
Apple. Not yet exercised in a signed, installed build at scale.

**Reference tools.**
[Anthropic sandbox-runtime](https://github.com/anthropics/sandbox-runtime) and
[nono](https://github.com/nolabs-ai/nono) (permissive) for running a command or
MCP server with restricted network and files. Next: wrapping any command or MCP
server automatically, read restrictions on credential folders for install scripts,
and keeping API keys outside the sandbox.
[Pipelock](https://github.com/pipelab-org/pipelock) (core is permissive) for
scanning agent traffic. Our allowlist proxy decides by hostname only. Next: secret
detection in outbound requests from contained processes, and MCP traffic checks.

## 3. Outbound control

**What it does.** Records every app's new outgoing connections and blocks
connections to hostnames on a threat list, before any payload is sent.

**How.** A NetworkExtension content filter, packaged as a system extension, sees
new flows from every process. It matches the hostname against a bundled snapshot
of the HaGeZi Threat Intelligence Feeds list, records the flow with process path,
signing identity and ancestry, and blocks on a match. History is encrypted and
bounded.

| | |
| --- | --- |
| Filter provider and threat matching | `desktop/macos/Sources/BoxCopNetworkFilter/` |
| Shared models, journal, summaries | `desktop/macos/Sources/BoxCopCore/Network*.swift` |
| Bundled list and its manifest | `desktop/macos/Resources/ThreatDomains/` |
| List refresh | `desktop/macos/scripts/refresh_threat_domains.py` |
| Extension packaging | `desktop/macos/scripts/protected_bundle.py` |
| Docs | [outgoing-connections.md](outgoing-connections.md) |

**Limits.** Destination reputation only: exact hostnames on one list. No per-app
rules, no payload or secret inspection, no TLS inspection. Direct-IP connections,
unlisted subdomains, VPN tunnels and encrypted DNS can evade it. The list changes
only when the app is updated. Requires the Developer ID signed build and the
user's approval in System Settings.

**Reference tools.** [LuLu](https://github.com/objective-see/LuLu) (GPL-3.0) and
Little Snitch for per-app outbound firewalls: reimplement from documented
behaviour. The fields we record follow the process and destination metadata LuLu
documents. Next: per-app rules keyed to signing identity.

## 4. Agent action checks

**What it does.** Checks what a coding agent is about to do, before it does it.
Denies recognizable credential access, exfiltration and dangerous commands.

**How.** BoxCop registers pre-action hooks in the user configuration of Claude
Code, Codex and Cursor. Each hook calls `BoxCop --host-agent-hook <agent>`, which
evaluates the action against deterministic rules and answers allow or deny within
the agent's hook deadline. A denial is final for that action; there is no later
decision to wait for.

| | |
| --- | --- |
| Hook installation, callbacks, health | `server/host_agents.py`, `server/host_agent_verification.py` |
| Command and path rules | `server/commands.py`, `server/classify.py`, `server/engine.py` |
| Native hook launcher | `desktop/macos/Sources/BoxCopCore/HostHookSupervisor.swift` |
| Docs | [host-agent-protection.md](host-agent-protection.md) |

**Limits.** Cooperative: the agent must call the hook, and the rules read command
text, so an effect hidden inside a script or behind an alias evades them. Codex is
covered for shell commands only. Desktop agent apps (Claude Cowork, the ChatGPT
and Codex apps) are not covered. There is no prompt-injection detection.

**Reference tools.**
[Meta PromptGuard 2](https://github.com/meta-llama/PurpleLlama) for detecting
prompt injection with a small local model. Not built here. Next: a local injection
classifier on content agents read.
[Santa](https://github.com/northpolesec/santa) (permissive) for allowing or
blocking binaries. Not built here. Apple has approved the Endpoint Security entitlement;
credential protection is now integrated as an opt-in beta, pending signed VM acceptance.
See [credential protection](credential-protection.md) for supported agents and limits. See the
[Endpoint Security plan](../plans/endpoint-security.md) for progress and release prerequisites.

## 5. Machine health

**What it does.** Finds installed software with a reviewed security finding and
helps fix some of it.

**How.** A read-only scan of applications, Homebrew, Python, npm and language
runtimes reads metadata (never running anything it inspects) and matches versions
against a reviewed set of advisories. For a few Homebrew formulae and for Pillow,
BoxCop prepares an update, shows the plan, applies it after approval and rescans.

| | |
| --- | --- |
| Inventory | `server/software_inventory.py`, `server/inventory_metadata.py`, `server/deployment_metadata.py`, `tools/supply_inventory.py` |
| Reviewed advisories | `server/exposure_advisories.py`, `server/feed_advisories.py`, `server/november_advisories.py`, `server/remaining_advisories.py` |
| Guided updates | `server/software_remediation.py`, `server/remediation_console.py` |
| Feed review workflow | `scripts/security_feed_review.py`, `update_from_feed.sh` |
| Docs | [software-exposure.md](software-exposure.md), [software-remediation.md](software-remediation.md), [security-feed-review.md](security-feed-review.md) |

**Limits.** Findings are hand-reviewed, so coverage is a short list and not
general CVE matching. A version match is not proof of exploitability, and "no
match" does not mean safe. No Electron or Chromium runtime detection inside apps.
No scan for plaintext secrets on disk.

**Reference tools.** [Achilles](https://github.com/crabnebula-dev/achilles)
(PolyForm: reimplement) and [OSV-Scanner](https://github.com/google/osv-scanner)
(permissive) for finding vulnerable installed software. Next: Electron, Chromium
and Tauri runtime detection, hardening checks, and matching against OSV, EUVD and
NVD. [Gitleaks](https://github.com/gitleaks/gitleaks) (permissive) for finding
secrets in files. Not built here. Next: a "plaintext secrets on this Mac" check
whose patterns are shared with outbound secret detection.

## 6. Smart triage

**What it does.** Uses a local model to review linked activity and explain events
in plain language, so a person who cannot read a script still gets a useful
answer.

**How.** The app ships a statically linked llama.cpp server. On first use it
downloads a pinned, checksum-verified Qwen 4B model (2.7 GB), but only when the
disk has room for the model plus 4 GB. Exactly one model runtime runs, on loopback
with an authentication token, and it uses about 3 GB of memory while running. The
model is given the engine's events (install gate, containment, agent checks)
alongside network history, as bounded, untrusted data. Only schema-valid output
whose citations point at supplied events is accepted, so an explanation attaches
to the event it cites in the Events list. The triage card under Protections can
remove the downloaded model.

| | |
| --- | --- |
| Model runtime management | `server/local_inference.py` |
| Linked-activity review | `server/workflow_judgment.py`, `server/workflow_context.py` |
| Runtime build | `desktop/macos/scripts/bundle_inference.py` |
| Docs | [workflow-judgment.md](workflow-judgment.md), [workflow-context.md](workflow-context.md) |

**The rule.** The model may tighten protection, never loosen it. Its output is
advisory text. It cannot allow an action, lift a block or change a policy; only
the user can. The model reads attacker-controlled text, so nothing it says is
allowed to grant access.

**Limits.** It does not yet decide which protections apply to what. A small local
model can miss risk or overstate it. It needs about 3 GB of free memory and has
not yet been accepted in the VM lab. Without the model, nothing else changes: the
deterministic layers decide on their own.

## Keeping up

Review the reference set on a regular schedule, the way `update_from_feed.sh`
reviews security feeds, and open an issue for each new protection worth bringing
over.
