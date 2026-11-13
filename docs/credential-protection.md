# Credential protection (beta implementation)

BoxCop's combined network/Endpoint Security extension can deny read opens of
selected credentials by recognized signed agents and tracked descendants. This
beta passed signed, notarized VM enforcement tests on macOS 14.6.1 with SIP enabled.
Existing installed builds do not gain it automatically. See the recorded scope below.

## Setup

Use a signed distribution build whose network-extension provisioning profile has
`com.apple.developer.endpoint-security.client = true`. Old network-only profiles
are rejected at build time. Keep the existing bundle ID
`local.sentinel.endpoint.network-filter`; regenerate its Developer ID profile
with Apple's approved capability. The containing app keeps its existing profile.

In Protections, enable **Credential protection · Beta**. If necessary, BoxCop
first activates its combined system extension and network filter. macOS approval
and Full Disk Access are separate steps. The card links to Full Disk Access when
ES reports it is missing; enable **BoxCop Network Filter** there. Status refreshes
with the app's normal polling. Restart agents after protection starts.

The toggle is off initially and its preference is saved in the extension's
root-owned directory. Pause Protection disables it and Resume restores it.
Removing BoxCop's system extension removes both network and credential services.
A missing/unreachable service is never reported as active credential protection.
On the tested macOS 14.6.1 VM, revoking FDA left an existing ES client enforcing
until restart. After reboot, BoxCop reported missing permission and did not claim
protection; granting FDA again restored enforcement through normal status polling.

## Scope and decisions

Recognized identities (both team and signing identifier must match, with valid,
non-ad-hoc code signing metadata supplied by ES):

- Claude desktop: `Q6L2SF6YDW / com.anthropic.claudefordesktop`
- Claude Code native CLI: `Q6L2SF6YDW / com.anthropic.claude-code`
- Codex native CLI: `2DC432GLL2 / codex`
- Cursor: `VDXQ22DGB9 / com.todesktop.230313mzl4w4u92`

These were verified against installed binaries on the development Mac. Unsigned
scripts, other distributions and Codex desktop are not independently recognized.
Installers/MCP servers are covered when they descend from a tracked agent;
standalone npm/pip processes are not automatically classified. Shell aliases and
executable names cannot establish trust or scope.

ES fork/exec events propagate scope using full audit tokens; exits remove it.
Parent and responsible-process audit tokens can recover tracked ancestry.
Existing detached children cannot always be reconstructed, hence the restart
instruction. Reparenting does not erase a process already in the tracker.
Event sequence gaps and tracker capacity exhaustion make status degraded.

Protected defaults across discovered account homes:

- Conventional SSH private key names (`id_rsa`, `id_dsa`, `id_ecdsa`, `id_ed25519`,
  `id_ecdsa_sk`, `id_ed25519_sk`); public keys and known_hosts are unaffected.
- `.aws/credentials`, `.aws/sso/cache/*.json`.
- `.config/gcloud/application_default_credentials.json`.
- Home-level `.npmrc`, `.pypirc`, `.netrc`.

AUTH_OPEN decisions use path rules and a metadata-only file-identity index.
Existing hard links and symlink aliases to indexed credentials match by device
and inode. The index refreshes during status polling, outside the ES callback.
No secret contents, file I/O, model inference or IPC enter the authorization path.
Responses are not cached. Unknown scope and unresolved paths fail open; unresolved
paths for scoped reads, ES response failures and sequence gaps are surfaced.

Recent successful denials appear on the card (50 retained in memory; five shown).
**Allow for 5 minutes** grants only the blocked process incarnation access to that
file identity. It does not authorize children, future processes or an interpreter
in general. Exceptions use monotonic expiry and disappear on service restart or
disable. Control requests require the signed BoxCop app from the same signing
team, in addition to the existing configuring-user/root socket access check.

## Limits

This is not a complete credential sandbox. Already-open/inherited descriptors,
credentials in memory or environment variables, Keychain and SSH-agent APIs,
custom paths, unrecognized independent tools, and helpers launched through an
untracked broker remain outside this boundary. File identity indexing has a
refresh window for newly created/replaced credentials accessed only by aliases.
Hard-link copies remaining after removal of the canonical credential path lose
index coverage after refresh. New accounts require restarting protection.

Write-only opens are not denied by this read-protection policy. Persistence and
write protection remain separate roadmap work. Network filtering, agent hooks,
registry routing and install-script containment remain useful and unchanged.

## Recorded VM acceptance (2026-11-13)

[Machine-readable evidence](evidence/credential-protection-2026-11-13.json) records
build 1794610185, its notarization and extension hash. The final recovery run passed
22 checks, including 200 repeated denied reads and 50 short-lived descendants,
with zero response failures or unresolved paths. Eight existing outbound-control
checks also passed. Full Swift suite: 143 passed; packaging: 89 passed, one skipped.

The probe launches the actual Developer ID signed Cursor executable with
`ELECTRON_RUN_AS_NODE=1`; shell/Python/grandchild probes inherit its kernel-verified
identity scope. This proves enforcement without relying on a model to perform the
read. It does not certify every supported agent's interactive workflow. Only
synthetic, newly created credential fixtures are used. Existing fixture paths are
skipped instead of overwritten.

Run `tests/vm/credential_acceptance.py --expected deny` inside the configured VM
with protection active (`--expected allow` when disabled). Use `--state
needsPermission` with `--expected allow` for a missing-FDA run. The script requires
SIP and a VirtualMac and verifies Cursor's signature. Run
`tests/vm/credential_exception_probe.cjs` using that signed executable, then select
its denial's **Allow for 5 minutes** in BoxCop. The probe checks child/other-file
denial and waits for real expiry. Native UI controls drive pause/resume and FDA.

These tests cover the new credential boundary and network regression, not all six
existing product layers. The VM's install gate reported `needs_setup` (its local
listener was not answering); no passing install-gate claim is made. Replacement
races, every agent UI, uninstallation and sustained event/deadline stress remain
additional acceptance work.

## Broader signed VM acceptance checklist

Use the synthetic account in the SIP-enabled VM described in [vm-lab.md](vm-lab.md).
Never test against real credentials. Before release, record results for:

1. Install/upgrade the combined signed extension; approve extension/network setup;
   enable credential protection before FDA and verify the missing-permission state.
2. Grant FDA; verify active status. Restart each supported agent. Ask it to run
   a shell and Python read of synthetic protected files: the read must fail before
   bytes are returned and the event must name the category/process.
3. Verify `.pub`, known_hosts, ordinary project files and unrelated terminal
   processes still work. Verify same-named/ad-hoc executables do not gain scope.
4. Test child/grandchild execution, reparenting, process churn, pre-existing
   children, symlinks, hard links, case aliases, and atomic credential replacement.
5. Grant an exception; verify only the exact process/file can read, a sibling
   cannot, it expires after five minutes, and disable/re-enable clears it.
6. Verify raw same-user socket clients cannot change settings or grant exceptions.
7. Test pause/resume, app quit, extension restart, upgrade, FDA revocation and
   removal. Never report healthy when the service cannot enforce.
8. Stress process/file events and measure latency/deadline failures, memory bounds
   and degradation/recovery. Check that concurrent network filtering still works.

Local checks: `swift test --package-path desktop/macos` and
`python -m pytest -q tests/test_protected_bundle.py tests/test_macos_packaging.py`.
