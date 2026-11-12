# Selected software updates

Home and Software review show one selectable action per supported installation,
with supported actions checked initially, Select all / Select none, and a batch
preview before Apply. Selecting or deselecting an item invalidates the preview.
The table groups installations by their shared fix, with affected software in the
left column and the action or next step in the right column. Group checkboxes
select all supported installations in that row; expanding a row reveals individual
checkboxes and paths. Partial selections display their count. Directory hints and
Homebrew receipts for the same formula share one action; separate package managers
and Python environments retain individual selections within their groups.

The first adapters support official Homebrew core formulae `brotli`, `cloudflared`,
`node`, and `ruby`, and Pillow in standard numeric pyenv environments. Eligibility
is offline; it does not promise a compatible fixed release is available. Preparing
a selected action queries the manager and resolves its available release. The
installed advisory rules, rather than parsing remediation prose, verify that the
candidate clears all known version advisories.

Homebrew preview includes its dry-run dependency changes. Pinned formulae,
unknown fixed releases, custom taps, and Node/Ruby major upgrades require review.
BoxCop uses the local Homebrew catalog without refreshing it implicitly: when no
fixed release is offered, refresh Homebrew and preview again. Upgrade runs with
auto-update and automatic cleanup disabled. It does not restart services. Unlinked installed formulae can be upgraded; the
preview discloses possible linking and shell-resolution changes. The initial upgrade
plan also includes formula-scoped cleanup of affected old versions. After upgrading,
BoxCop rescans, verifies a fixed active replacement through Homebrew, runs cleanup
without another approval, and rescans again. Cleanup failures remain actionable
and do not erase the successful upgrade. When a
fixed version and older affected copies coexist, the scanner offers a separate
**Remove old versions** action instead of another update. Its formula-scoped
Homebrew cleanup preview lists removals (including any stale downloads), requires
approval, verifies a fixed active version, and rescans after cleanup.

Pillow preview uses the exact environment's interpreter in isolated mode, pip's
binary-only resolver against PyPI, and a baseline check of existing environment dependencies.
It checks installed reverse-dependency constraints against the resolved Pillow
version. Application compatibility still needs testing, especially across major
versions. Apply installs the exact official wheel with its SHA-256 URL fragment
and no additional dependencies, then compares pip check results against that baseline. Unrelated pre-existing issues
are shown in the preview and do not block the update; new issues fail verification. If the fixed release cannot
run on that Python version, the environment needs migration; BoxCop does not
silently upgrade Python or edit a project's requirements/lockfiles.

Both adapters regenerate the plan immediately before applying and require an
identical fingerprint of the installation evidence, target, and preview. Group-writable manager directories are supported; executable existence and expected
installation-path checks still apply. Commands
come exclusively from reviewed adapters; client requests contain selection IDs
and approval fingerprints, never argv or executable paths. A private process lock
serializes prepare/apply operations. Processes use argument arrays, a minimal
environment and bounded retained output. Preparation has process-group deadlines;
installation and approved cleanup have no wall-clock timeout. Verbose builds are
drained continuously into bounded output tails instead of being killed for output
volume. Keep BoxCop open during
updates. Package managers do not offer transactional rollback: a failure or timeout
can leave partial changes and must be followed by a recheck.

Each successful command is followed by a fresh inventory. Missing records,
incomplete scans, remaining affected copies, and unverifiable versions never count
as a verified fix. A positively verified installed version is reported as
**Restart needed** because the scan cannot verify running processes or embedded
copies. Results survive app restarts in a private, atomic `software-remediation-results.json`
store (latest attempt per installation, up to 128). Pending attempts are recorded
before execution, so a missing completion is visible after a crash. Outcomes also
remain in the workflow journal. Failed updates remain retryable; migration/manual
review outcomes move out of the automatic-update group while their installation
evidence is unchanged. New scan evidence supersedes those classifications. Failed commands expose an expandable Command details section and
write a private, 256 KiB-bounded `software-remediation.jsonl` in BoxCop’s BoxCop
application-support directory. URL credentials and common secret query parameters
are redacted. stderr is kept separate from machine-readable stdout. No service restart, project-pin change, or privileged install is automatic. Old
Homebrew versions are removed through cleanup included in the approved upgrade plan
or through a standalone cleanup plan for copies already left behind.

App updaters (including LM Studio), nvm runtime migration/removal, and unresolved
embedded-browser advisories remain in **Needs review or migration**, with a reason
and access to advisory details. This release does not claim to repair persistence
or clear advisories without a known fixed-version rule.

Validation uses mocked managers and fixture inventories; tests do not upgrade the
developer's installed software. Run:

```sh
python -m pytest tests/test_software_remediation.py tests/test_software_inventory.py
swift build --package-path desktop/macos --product BoxCop
swift test --package-path desktop/macos
```

## Agent handoff

Each manual-review group offers **Copy agent instructions**. The locally generated
prompt includes every installation in that group, its paths and observed versions,
linked advisory states/ranges/sources, scan time, completeness and coverage. Nothing
is sent to an agent automatically; the user chooses where to paste it. Copying
replaces the clipboard but does not authorize or execute a repair.

The Node prompt asks for read-only consumer discovery and a user-selected plan:
migrate active projects, remove unused runtimes while preserving source, or
explicitly retire unwanted projects. It addresses pins, aliases, global packages,
running processes, automatic reinstallation and verification. It does not label a
moved directory as execution-proof quarantine. Browser and LM Studio handoffs
preserve their distinct verification and persistence limitations. Scan metadata is
encoded as JSON and explicitly treated as untrusted evidence, never shell input.

## Live update console

Running actions expose **View live console**; recorded execution results expose
**View console**. The viewer polls a local snapshot once per second, supports
selectable monospaced text, Follow output and Copy output, and continues displaying
the completed result. Closing the viewer does not stop the update. A new attempt
replaces that installation's old console, and its current result replaces the old
failure row immediately.

The engine captures both stdout and stderr during plan revalidation, installation
and verification. A private `software-console/<installation-id>.json` snapshot is
published atomically at most twice per second, plus command/completion boundaries.
It keeps roughly 128 KiB of text and at most 128 installation logs. The UI labels
truncated output and unfinished attempts explicitly. Reads do not take the update
lock. Failed console writes do not terminate the updater. Credential redaction
matches the existing diagnostics, but copied output can contain local paths and
other details; it is never sent automatically. Older builds did not record console
output, so their past/running attempts cannot be reconstructed by this feature.
