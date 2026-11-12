# Machine health: software inventory

This is BoxCop's machine health layer. The app scans selected software locations
once protection is on and repeats the scan while it is open. Health shows the
findings, how to fix each one, links to primary sources, the scan time, and
whether coverage was incomplete or the result is stale. Recheck runs a fresh scan.
The scan is a separate background process, so nothing else waits for it. Closing
the app stops scheduled scans.

The same implementation powers `tools/supply_inventory.py ROOT` and the engine's
`--software-inventory [--cache] [--root ABSOLUTE_PATH]` mode. It reads metadata;
it never starts an inspected interpreter, imports a package, runs an installer,
executes a launch daemon or follows instructions in a feed.

## Coverage and interpretation

Default roots: system/user Applications, both Homebrew Cellars and Caskrooms, pyenv/uv/asdf/mise/
nvm/rbenv runtime locations, user Library/Python, .wasmtime, PrivilegedHelperTools
and LaunchDaemons. Project-local virtual environments outside those roots need an
explicit CLI scan. App bundles are identified through Info.plist bundle IDs, Python
packages through METADATA, npm packages through package.json, Homebrew through
receipts, and selected runtime managers through version-directory hints. Hints and
metadata may be false, stale or replaced. Unversioned Wasmtime remains unresolved.

| Software | Reviewed finding |
|---|---|
| PHP | Per-branch October fixes plus a separate session-upload configuration review |
| Node / Brotli | Node branch fixes; standalone Brotli update finding; embedded copies require rebuild verification |
| Pillow | FPX advisory range; optional olefile / untrusted-image prerequisites |
| Ruby | Three separate compiler-fix thresholds; untrusted regexp prerequisite |
| Wasmtime | Separate SSA and ARM64 branch bugs; architecture unknown unless independently verified |
| Chrome / Firefox | Vendor update baselines; Firefox release/ESR ambiguity remains unresolved |
| Electrum | Wallet update finding; no transaction-signature or fee-bump mediation |
| TeamViewer / Tailscale / headscale | Reviewed macOS client and separate node/controller update baselines; add-ons, SSH/Serve settings and remote nodes remain unverified |
| Better Auth / Expo | Separate npm package findings for reviewed stable/beta ranges; plugin registration, package pairing and secret rotation remain unknown |
| FreeRDP | Homebrew core 3.x security-release baseline; embedded clients and active RDP features remain unverified |
| Node-RED | npm presence triggers configuration review at every version; no package version proves adminAuth or network isolation |
| Next.js / Langflow / LMDeploy / SGLang | Reviewed local package findings; runtime/server settings remain unverified; LMDeploy has no verified fix |
| pgAdmin 4 / Atlantis / BIND / FreeSWITCH / Bitcoin Core / Jenkins | Selected package/formula advisories; explicit branch/channel and running-service limits |
| Laravel / Drupal core | Composer installed-package findings; enabled features, database configuration and remote sites remain unknown |
| Drupal Commerce / Adobe Commerce and Magento | Installed Composer product/module metadata; isolated Magento patch status can remain unresolved |
| EPICS Base / ClickHouse / LM Studio | Formula/cask receipts or app bundle ID; running state and ambiguous LM Studio builds remain unknown |
| Keycloak / Jackson databind | Bounded Maven JAR properties; no class loading, shaded/nested archive or live JVM inspection |
| WordPress / Avada / Nextcloud built-in CODE / GitLab | Local source/deployment metadata; separate WordPress incidents, exact product identities and explicit remote/runtime limits |
| Time4Popcorn | Helper/daemon presence and ambiguous Popcorn app identity review; no blanket identification by display name |

A later feed review added Cloudflare client update advice, unresolved embedded-browser app reviews, and
explicit-root checks for Echo `go.mod`, GoAhead vendor source metadata and selected
Compose/Kubernetes image declarations. Deployment/source findings cannot prove that
installed or running code is fixed: their state remains unresolved even when
`declared_version_state` records a fixed baseline. Standard Compose filenames and
`*.k8s.json` / `*.k8s.yaml` / `*.k8s.yml` are supported; images are matched by exact
repository identity. No cluster, Docker socket, registry or Go tool is contacted.
YAML aliases, duplicate keys, unsafe constructors and resource-limit violations are
rejected.

Inventory does not intercept installs or install scripts; the
[install gate](package-registry-firewall.md) and
[containment](install-script-protection.md) do that. A periodic scan cannot
guarantee detection before something runs.

Project-local Python, npm and Composer installs outside the default roots need an
explicit scan, for example:

```sh
.venv/bin/python tools/supply_inventory.py --root /absolute/path/to/project
```

The new package names are ecosystem-specific. Composer reads only bounded
`vendor/composer/installed.json` metadata (versions 1/2), never PHP/autoloaders or
lockfile declarations. Custom vendor paths and manifests exceeding 256 KiB remain
incomplete/unsupported. Homebrew HEAD/custom-tap metadata remains unresolved. JAR and CMS/deployment
metadata can describe cached or inactive code, not a running service.

The November feed review added a separate Chrome 157 baseline while preserving
the October finding. All new package names have fixture-tested automatic installation layouts and
explicit-root discovery. Project installs still require an explicit root. Node-RED
settings are not executed or interpreted, and Siemens Industrial OS versions are
not used as npm fix versions. Better Auth remediation includes updating both
packages and rotating exposed application secrets; a fixed metadata finding cannot
verify those actions.

The reviewed snapshot and primary URLs are in
[`server/exposure_advisories.py`](../server/exposure_advisories.py), initially dated 2026-10-27,
with per-advisory review dates (Chrome November baseline reviewed 2026-11-04),
[`server/feed_advisories.py`](../server/feed_advisories.py), reviewed 2026-11-03, and
[`server/november_advisories.py`](../server/november_advisories.py), reviewed 2026-11-04.
The pwn.watch feed is a discovery source, not live policy input.
The [local daily review](security-feed-review.md) checks it and Cloudflare Zero Wire
and proposes tested additions through draft PRs. Feed text never changes policy
by itself. Exact LiteLLM/SubQuery distribution checks remain supported.

`affected_version` is a metadata version match, not an observed exploit.
`fixed_for_advisory` describes only the reviewed range, not universal safety or the
running process. `update_available` means the installed version hint precedes a
vendor update baseline; not every older version is asserted affected by every CVE.
Backports, vendor suffixes, prereleases, unknown channels/architectures and unsupported
branches remain unresolved. Settings and loaded embedded libraries remain unknown.
“No snapshot match” must never be displayed as “safe.”

Limits: 32 roots, 300,000 entries (with capacity reserved for later roots), depth 64
for automatic installation-layout traversal / 10 for explicit recursive scans,
128 observations, 16 MiB metadata per scan,
256 KiB per ordinary metadata file, five-second scan deadline, 15-second native child deadline
and 2 MiB output cap. Selected JAR readers permit at most 8 MiB per archive,
4,096 entries and 16 KiB per selected properties file within the same total read
and time budgets. Descriptor-relative traversal rejects symlink roots/ancestors
and children. Read failures, changes during reads and limits make results incomplete, with bounded
path-specific diagnostics. Automatic scans follow Homebrew receipts, runtime layouts,
Python dist-info and npm installation trees rather than crawling headers, documentation
and package source. Symlinks and app bundles without standard metadata are declared
coverage exclusions; explicit recursive scans still mark skipped symlinks incomplete.
Symlink-based installations may need a canonical explicit-root scan. Known packages
without a version remain unresolved observations; npm configuration-only manifests
do not make a scan incomplete. The app shows coverage gaps separately from software
findings, with root states, the paths of metadata failures and guidance. Retrying
does not repair installed metadata.
Plists are parsed unchanged first. If XML parsing fails, UTF-8 XML gets one
in-memory retry with XML-invalid ASCII control characters removed (legal tabs,
newlines and carriage returns remain). This accommodates stray copyright control
characters and trailing null bytes accepted by macOS. Other XML errors remain
visible; binary plists are not sanitized. Installed files and metadata digests
always retain the original bytes.
Absent roots are listed separately from unavailable roots. The UI displays partial
coverage and flags the last successful result stale after ten minutes.

## Durable format

`~/Library/Application Support/BoxCop/software-inventory.json` is an atomic mode
0600 cache in the existing owned mode 0700 app directory. It is replaced each scan;
no raw metadata file is retained. Failures are visible. The activity journal also
records a `software_inventory` summary with scan/review timestamps, observation and
review counts, and `finding_only` enforcement. These records are local and may reveal
software names and filesystem paths. Nothing is sent to pwn.watch or anywhere else.

Schema `boxcop.software-inventory.v2` includes:

- `generated_at`, `reviewed_at`, `freshness_seconds`, `elapsed_ms`, `cache_status`;
- `roots` with scanned/partial/absent/unavailable/not_scanned states, `incomplete`, `issues`,
  bounded counts and explicit coverage text;
- optional `limitations` and `issue_details` (reason/path, at most 64), readable by
  older v2 consumers that ignore additional fields;
- `records`: stable path-derived ID, name/version, metadata path/kind/digest,
  observed metadata device/inode/size/mtime/owner, advisory assessments;
- each advisory's source/review date, verification state, affected/fixed ranges,
  platform, prerequisites, backport caveat, remediation and `finding_only` boundary;
- unknown running state, configuration and embedded dependencies rather than
  invented confirmation of the installed/running executable.

The v1 CLI's positional root and Python `inventory(root)` adapter remain available,
but CLI JSON now uses v2 and only the reviewed software set is retained. Consumers
must check the schema and timestamps. Metadata identity is **not executable identity**.

## What a finding means

Inventory reports findings. It does not block, quarantine or uninstall anything,
and it never runs a command taken from a feed or a plist. Code that is already
running, loaded libraries and credentials already in memory are unaffected by an
update, so restart guidance stays visible after the installed version changes.
Recheck refreshes the evidence.

For some findings BoxCop can prepare and apply the update for you; see
[software-remediation.md](software-remediation.md).

### Time4Popcorn privileged helper

The researcher identifies `/Library/PrivilegedHelperTools/PT.updd` and
`/Library/LaunchDaemons/PT.updd.plist` in the abandoned fork. The unrelated modern
Popcorn Time product is not identified as affected. BoxCop reports file presence,
owner and metadata identity as a **candidate**, not proof of provenance or
execution, and links to the researcher's removal guidance. Verify the helper and
launch-daemon identity before an administrator follows that guidance. BoxCop does
not disable root helpers.

## Validation

```sh
python -m pytest -q tests/test_software_inventory.py tests/test_feed_advisories.py \
  tests/test_feed_advisories_extended.py tests/test_feed_advisories_november.py \
  tests/test_feed_advisories_remaining.py tests/test_supply_chain.py
```

The tests build fixture installation layouts in temporary directories. They cover
affected, fixed, unknown and benign versions, traversal limits, symlink rejection
and incomplete scans. They do not scan the developer's Mac.
