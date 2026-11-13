# Endpoint Security protection roadmap

Apple has approved the Endpoint Security entitlement (reported by Chris).
Approval enables implementation; it does not activate protection in existing builds.
Target: macOS 14+, retaining existing network filtering, registry intelligence,
agent hooks and containment where they provide complementary coverage.

## 1. Credential protection — implemented beta, signed VM verified

- [x] Local deterministic read policy for conventional SSH private keys, AWS
  credentials/SSO cache, Google ADC, and home-level npm/PyPI/netrc credentials.
- [x] Combined network/ES extension with uncached AUTH_OPEN decisions, validated
  signing identities, full audit-token ancestry, fork/exec/exit tracking, bounded
  state and event-loss reporting.
- [x] Account-home discovery and metadata-only file identity index outside the
  authorization callback; existing hard links, symlinks and case aliases covered.
- [x] Bounded denial history, health/degraded reporting, authenticated controls,
  opt-in preference, FDA guidance, pause/resume and exact process/file exceptions
  with five-minute monotonic expiry.
- [x] Refreshed Developer ID profiles validated and saved persistently under
  `~/.sentinel-lab/profiles/`; signed/notarized combined extension installed in VM.
- [x] Signed SIP-enabled VM tests: direct/shell/Python/grandchild reads, aliases,
  public/ordinary files, unrelated processes, churn, unauthorized controls,
  exception scope and actual expiry, upgrade, app quit, pause/resume, reboot,
  missing/revoked FDA and permission recovery. Existing network blocking passes.
- [x] 143 Swift tests; packaging tests: 89 passed, one skipped.
- [x] Repeated-read latency sampled with no response failures or unresolved paths
  in the final acceptance runs. This is a smoke measurement, not a load benchmark.

Evidence and reproduction: [credential protection](../docs/credential-protection.md)
and [VM results](../docs/evidence/credential-protection-2026-11-13.json).
No permissions or extensions were changed on the development Mac.

Remaining coverage work (not claimed by this beta):
- [ ] Validate live workflows for every recognized agent; signed Cursor in Node
  mode and its descendants were used for deterministic VM enforcement tests.
- [ ] Reconcile pre-existing detached helpers and untracked broker launches.
- [ ] Close new/replaced-file alias index refresh windows; stress replacement races.
- [ ] Extend coverage to custom paths and other credential APIs where appropriate.
  Inherited descriptors, memory, Keychain and SSH-agent APIs are outside AUTH_OPEN.
- [ ] Broader deadline/load and uninstall acceptance. Refresh the repository's
  release profile secret before a distribution workflow uses this capability.

## 2. Automatic coverage across tools

- [ ] Apply baseline file policies across recognized CLI and desktop agents,
  package installers, MCP servers and descendants without per-tool hooks.
- [ ] Validate each supported tool; publish coverage and attribution limitations.
- [ ] Retain hooks for intent/tool context and registry routing for package/version
  decisions. ES does not replace registry resolution or a complete sandbox.

## 3. Execution control

- [ ] Add AUTH_EXEC rules using executable identity, signing information and
  reputation, with bounded local decisions and invalidation on updates.
- [ ] Treat interpreter scripts separately; trusting Python or Node does not
  establish that their scripts are safe.

## 4. Persistence and destructive-change protection

- [ ] Protect shell startup files, LaunchAgents and selected user data against
  scoped processes. Cover create, replacement, rename, unlink and relevant
  metadata/link operations rather than relying only on writable opens.
- [ ] Add recovery and carefully scoped exceptions; validate ordinary installers.

## 5. Simpler setup and richer explanations

- [ ] Aim for one system-protection setup flow, with accurate independent FDA,
  system-extension and network-filter approval states.
- [ ] Correlate process/file events with network history and package/agent events.
- [ ] Use local AI after the decision for explanations, never on the synchronous
  authorization path. Bound and redact event data.
- [ ] Retain network filtering: ES does not inspect HTTPS payloads or replace
  outbound filtering. Retain existing containment until replacements are proven.

## References

- https://developer.apple.com/documentation/EndpointSecurity
- https://developer.apple.com/documentation/endpointsecurity/monitoring-system-events-with-endpoint-security
- https://developer.apple.com/videos/play/wwdc2020/10159/
- https://developer.apple.com/documentation/endpointsecurity/es_respond_flags_result(_:_:_:_:)
