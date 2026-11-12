# Package intelligence and registry firewall

BoxCop can block listed malicious npm and PyPI releases without a minimum release
age. This implementation is **opt-in**: it does not change global package-manager
settings on first launch. Previously enabled routing resumes with BoxCop protection. Builds
with a provisioned feed expose explicit npm/pnpm activation and removal in the
protection setup screen. See the [production deployment guide](../deploy/boxcop/README.md).

The registry proxy runs inside BoxCop's existing policy engine. Quitting or pausing
BoxCop stops it. Protected npm routing remains in place, so routed installs fail
until BoxCop resumes or routing is explicitly disabled. No separate launchd job is
installed. Existing command checks use the same provisioned policy directory.
There is no new macOS Network Extension or TLS interception requirement.

The registry firewall decides which releases may be downloaded. What an allowed
package's install scripts may connect to is covered separately by
[install script protection](install-script-protection.md).

## What is implemented

- Publisher ingestion of Datadog npm/PyPI manifests, OpenSSF MAL records through
  OSV bulk exports (or a local OSV directory), and GitHub's malware API.
- GitHub pagination, inclusive update cursors, withdrawals, and optional full
  reconciliation. A failed source fetch aborts publication and cursor advancement.
- npm SemVer and Python PEP 440 matching, ecosystem-specific package names,
  exact-version compromises, explicit package-wide malicious-intent rules,
  provenance, source licensing, and retained report identifiers.
- Ed25519-signed full replacement snapshots with an independently provisioned
  public key, atomic installation, sequence rollback checks, and last-good state.
- Read-only public npm and PyPI proxy: remove blocked releases from metadata and
  check authenticated artifact links again before downloading and streaming.
- Local `/status` reports policy availability, source fetch metadata, stale state,
  failed refreshes, and blocked-request count. Access logs do not retain package
  names or credentials. Only blocked responses contain the applicable report IDs.

Unknown packages and new versions are allowed. Ordinary CVEs are not ingested as
malware. OpenSSF includes research and borderline reports, so its records default
to review-only; a publisher can explicitly approve MAL IDs after review. GitHub
records with OpenSSF aliases/references retain that conservative disposition.
Mirroring does not count as independent corroboration. Datadog and other GitHub
malware records can block based on their own selectors. Unsupported selectors
become review-only, never an inferred package-wide ban.

Datadog `null` entries explicitly designate malicious-intent package names and
block all versions while that source assertion remains active. Version lists block
only listed versions. Full replacement updates remove deleted Datadog/OpenSSF
assertions, process withdrawals, and preserve any still-active independent report.

## Publisher setup

Use Python 3.12 and the repository dependencies. Run this on the publisher, not on
every endpoint. Full initial GitHub ingestion can exceed unauthenticated rate
limits; supply a GitHub API token through `GITHUB_TOKEN`, never a command argument.
Only GitHub API requests receive it; dependency names from installs are never sent
to an intelligence provider.

```sh
python -m tools.package_feed keygen \
  --private-key .context/package-publisher/private.key \
  --public-key .context/package-publisher/public.key

python -m tools.package_feed build \
  --private-key .context/package-publisher/private.key \
  --state-dir .context/package-publisher/state \
  --output .context/package-publisher/policy.json \
  --sequence 1
```

The keygen command creates raw Ed25519 key files with mode 0600 and refuses to
overwrite them. Keep the private key in protected publisher storage; do not commit
or ship it. The example is suitable for development. Production needs a managed
signing key, durable publisher state, and a pinned public key distributed through a
trusted release/provisioning path. Never accept a public key from the feed URL.

Each successful build must increase `--sequence`. Preserve the previous output
file and state directory across runs; serialize publisher jobs. The output carries
the full policy, license texts, attribution, and source metadata. Host that signed
file on an HTTPS endpoint when deploying. No hosting account or endpoint is
assumed or configured by this change.

Optional flags:

- `--openssf-dir PATH`: read a local directory of `MAL-*.json` OSV metadata instead
  of OSV bulk exports. No repository scripts or package samples are executed.
- `--reviewed-ids FILE`: JSON list of explicitly reviewed MAL IDs eligible to block.
- `--full-github-refresh`: reconcile the API from scratch, including records
  deleted upstream. Run periodically (for example weekly); ordinary updates use
  the cursor and process withdrawals. A mirror can still lag the original source.

Schedule ingestion according to upstream quotas and incident-response needs. The
client defaults to polling the published snapshot every 15 minutes. That interval
is not a malware-detection latency guarantee.

## Try the proxy without changing system configuration

With a signed snapshot and its public key:

```sh
python -m server.package_proxy \
  --snapshot .context/package-publisher/policy.json \
  --public-key .context/package-publisher/public.key \
  --state-dir .context/package-client
```

Alternatively, use the built application's engine with the same arguments:

```sh
/Applications/BoxCop.app/Contents/Resources/engine/boxcop-engine \
  --package-protection \
  --snapshot /absolute/path/policy.json \
  --public-key /absolute/path/public.key \
  --state-dir /absolute/path/package-client
```

Check `http://127.0.0.1:8794/status`. The listener binds only to `127.0.0.1` and
requires that literal Host header. Browser-origin requests, credentials, cookies,
write requests, arbitrary proxy destinations, and redirects are rejected.

Route individual installs using these command-scoped options:

```sh
npm install --registry=http://127.0.0.1:8794/npm/ --no-audit PACKAGE
pnpm add --registry=http://127.0.0.1:8794/pnpm/ PACKAGE
python -m pip install --index-url http://127.0.0.1:8794/pypi/simple/ PACKAGE
uv pip install --index-url http://127.0.0.1:8794/pypi/simple/ PACKAGE
```

npm, pnpm, pip and uv pip are covered by real-client automated tests. npm and pnpm
also have cold frozen-install and lockfile-portability tests. The shared `/npm/`
route recognizes pnpm's user agent; `/pnpm/` explicitly selects pnpm metadata.
Yarn/Bun integration, Rust, Go, Maven, NuGet and other ecosystems are not claimed
by this first implementation. Keep private scoped registries configured directly;
the proxy does not support private registry auth or publishing. npm audit is a
separate service; this read-only proxy does not implement its POST endpoints.

## App-owned package protection

Use **Enable npm and pnpm protection** in BoxCop's protection setup screen. Setup
runs asynchronously through the existing engine pipe, reports progress, and keeps
failed activation retryable. A verified cached policy is served before any network
refresh. Initial setup downloads and verifies a release-pinned snapshot. Only after
the local listener starts does BoxCop add its reversible user npmrc block.

On upgrade, BoxCop stops and removes its old
`~/Library/LaunchAgents/com.boxcop.package-protection.plist`. Previously enabled
routing is restored when BoxCop protection starts. A failed old activation with no
routing does not silently opt in. Disabling restores npmrc before stopping the
proxy. Quitting/pausing leaves routing enabled deliberately; package downloads
through that route fail while BoxCop is stopped.

Policy and artifact-link keys remain under
`~/Library/Application Support/BoxCop/package-protection/`. Retain this directory
for signature rollback protection and stable local artifact links. Public-key
rotation remains explicit. Standalone launchd enrollment is no longer supported.

## Outages and coverage limits

The first start requires a valid signed snapshot. Refresh failures retain the
last verified snapshot and expose an error in `/status`; known matches still block
and unknown packages remain allowed. Snapshots older than 24 hours show `stale`.
Staleness is a feed-health indicator, not a release-age restriction. Invalid local
snapshots prevent startup. A stopped proxy causes routed installs to fail until
the service recovers or routing is removed; it never silently redirects around
protection. Already-streaming downloads cannot be revoked by a later feed update.

Only traffic actually routed through the proxy is protected. Existing package
caches, installed code, direct URLs/Git dependencies, private registries, lockfiles
pointing to upstream URLs, and project/environment overrides can bypass it.
The firewall does not scan bytes for previously unknown malware or authorize OS
execution policy. Metadata identity is supplied by the upstream HTTPS registry.

**npm/pnpm lockfiles remain portable under the tested configurations.** npm keeps
canonical public tarball URLs and reroutes downloads through its native configured
registry behavior. pnpm receives standard registry artifact paths and omits those
paths from its lockfile. The helper binds each requested tarball to live registry
metadata before applying version policy; filenames alone are not trusted.

**Python artifact URLs still depend on the local proxy.** Do not use this route to
generate shared `uv.lock` or other artifact-URL lockfiles yet. Plain pip/uv pip
installs are tested, but Python lock-writing workflows remain evaluation-only.
Existing caches and explicit non-registry URLs remain outside download enforcement.

Malformed or unsupported registry metadata returns a validation error, not a
claim that the package is malicious. Python distribution formats other than
recognized wheel/sdist filenames are not supported. PEP 658 metadata sidecars
are not advertised; clients obtain metadata from the authenticated artifact.

## Validation

```sh
python -m pytest -q tests/test_package_intelligence.py \
  tests/test_package_proxy.py tests/test_package_installs.py tests/test_supply_chain.py
```

The real npm/pip tests use only locally generated inert archives and a simulated
upstream transport. They exercise allowed fresh releases, blocked direct and
transitive installs, and an npm install-script marker that must never execute.
Other tests cover signatures, wrong keys, rollback across restart, source
withdrawals, range boundaries, ecosystem isolation, failed updates, forged artifact
links, source pagination, and enrollment. No malware samples are downloaded.
