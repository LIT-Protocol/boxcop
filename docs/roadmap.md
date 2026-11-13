# Roadmap

This is the plan from [allayhq/Allay#149](https://github.com/allayhq/Allay/issues/149),
adjusted for what BoxCop has today. [layers.md](layers.md) describes the current
state of each layer.

**Priority order:** distinctive prevention, then experience, then supporting
features, then breadth for organizations.

## Steps

1. **Generalize containment.** The engine can already run one command contained
   (`boxcop-engine --contain`), using the same sandbox and allowlist proxy as npm
   install scripts. Next is applying it automatically to agent-written scripts,
   downloaded executables and MCP servers. Use sandbox-runtime and nono as the
   reference for scope.
2. **Finish the install gate.** Minimum release age, pip and uv routing in the
   app, wider skill checks, and local discovery of MCP servers.
3. **Wire triage to enforcement.** First-seen signals, contain-by-default for new
   code, model explanations and proposed exceptions. The model may only tighten.
4. **Strengthen outbound control.** Per-app rules, threat-list updates between
   releases, and secret detection for contained processes (the Pipelock approach).
5. **Broaden machine health.** OSV matching, Electron and Chromium runtime checks,
   a plaintext-secret scan.
6. **Cover desktop agents.** Claude Cowork and the ChatGPT and Codex apps, where
   hooks or process identity allow.
7. **Open the project.** The license is done: BoxCop is Apache-2.0 licensed. The
   repository is still private. What remains before it opens: a threat model,
   known limits, reproducible demos and a disclosure process.
8. **A control plane for organizations**, when organizations ask for it: central
   policy and exceptions, fleet status, audit export. BoxCop has none of this today.

## Owed on what exists

- Run install script protection in a signed build at scale, verify its
  per-package host list, and test more escape routes.
- Give BoxCop its own bundle identifiers and provisioning profiles. It currently
  keeps `local.sentinel.endpoint` because the profiles we hold are bound to it.
- Host BoxCop's own package malware feed. It currently reads the existing Allay
  feed.
- Accept smart triage in the VM lab. It has not passed an acceptance run; see
  [vm-lab.md](vm-lab.md).
- Set up an update feed. Builds have no in-app updates until one is configured;
  see [releasing.md](releasing.md).

## What we need to validate

1. People will install another security app for this, including people who are
   not developers.
2. One assembled app beats installing the individual tools, and beats Aikido for
   individuals.
3. Contain-by-default for new code does not break ordinary work.
4. A small local model is accurate enough to triage. If it is not, whether users
   accept a connected one.
5. Seatbelt (`sandbox-exec`), which Apple has deprecated, remains a workable base
   for containment.
6. Organizations will pay for central management.

## Risks

- **Scope.** Six layers is a lot. Integration quality matters more than layer count.
- **Maintenance load.** We own every layer, and the reference tools keep moving.
- **Porting carelessly.** BoxCop is Apache-2.0 licensed. Copying source from a
  copyleft or restricted tool would put that tool's license on our code. See the porting rule in [layers.md](layers.md).
- **The macOS boundary.** Without the Endpoint Security entitlement, containment
  covers only what we launch or route, not everything on the machine.
- **Model mistakes.** A wrong model verdict must never be able to open a hole.
- **Trust.** A security app that touches networking and package managers can
  break workflows or add vulnerabilities of its own.

## Decision rule

Before building a feature, ask whether it prevents a meaningful risk, helps
someone understand or fix one, or makes existing protection much easier to use.
Before designing a protection from scratch, check how the reference tools already
solve it. Do not advertise what does not work yet.
