# Install gate: the registry firewall

BoxCop blocks npm and PyPI releases that are listed as malicious, at the moment a
package manager asks for them. It does this with a local registry proxy and a
signed list of malicious releases.

Routing is **opt-in**. BoxCop does not change package manager settings until you
turn the install gate on in the app, and turning it off restores them.

The proxy runs inside BoxCop's engine, so it is up while the app is running.
Quitting BoxCop stops the proxy but leaves the routing in place, so routed
installs fail until BoxCop is running again or routing is turned off. That is
deliberate: the gate does not silently step aside. No launchd job is installed,
and no TLS interception is involved.

The registry firewall decides which releases may be downloaded. What an allowed
package's install scripts may connect to is covered by
[install script protection](install-script-protection.md).

## Test it

With the install gate on, run:

```sh
npm install boxcop-test-malware
```

The install fails with the same response as a real listed package, and the block
appears in the app's Events list. The package named `boxcop-test-malware` is
always blocked, in npm and PyPI and at any version. It needs no feed entry and
the request never reaches the public registry.

## Where the list comes from

BoxCop does not have a malware feed of its own yet. Builds made with `build.sh`
read the existing signed Allay feed:

```sh
export BOXCOP_PACKAGE_FEED_URL=https://getallay.ai/package-feed/v1/policy.json
export BOXCOP_PACKAGE_FEED_PUBLIC_KEY_BASE64=4vFHQbvIWeK3TVnv7vCjb8M0yTisaM1hpvnUA3F6ZYw=
export BOXCOP_PACKAGE_FEED_MINIMUM_SEQUENCE=1
```

`build.sh` sets these by default. Set them yourself before a limited-development
build made with `build_app.py`. The build writes them into `channel.json` inside
the engine. A build without them has no feed, and the app shows the install gate
as "Unavailable".

The key is public. The app accepts a snapshot only if it is signed with the
matching private key and its sequence number is not lower than the last one it
saw, so the feed host cannot serve an altered or older list. The payload schema
is still named `allay.package-policy.v1`. When BoxCop publishes its own feed, the
three values change and nothing else does.

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

## Publishing a feed

This section is for whoever publishes a feed. Using BoxCop does not require it.

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
file on an HTTPS endpoint when deploying. This repository does not configure a
hosting account or endpoint.

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

## The local proxy

While the install gate is on, the proxy listens on `127.0.0.1:8794` and
`http://127.0.0.1:8794/status` reports its health. The listener binds only to
`127.0.0.1` and requires that literal Host header. Browser-origin requests,
credentials, cookies, write requests, arbitrary proxy destinations and redirects
are rejected.

The app routes npm and pnpm for you. You can also route a single install by hand:

```sh
npm install --registry=http://127.0.0.1:8794/npm/ --no-audit PACKAGE
pnpm add --registry=http://127.0.0.1:8794/pnpm/ PACKAGE
python -m pip install --index-url http://127.0.0.1:8794/pypi/simple/ PACKAGE
uv pip install --index-url http://127.0.0.1:8794/pypi/simple/ PACKAGE
```

npm, pnpm, pip and uv pip are covered by automated tests that run the real
clients. npm and pnpm also have cold frozen-install and lockfile-portability
tests. The shared `/npm/` route recognizes pnpm's user agent; `/pnpm/` explicitly
selects pnpm metadata. Yarn, Bun, Rust, Go, Maven, NuGet and other ecosystems are
not covered. Keep private scoped registries configured directly; the proxy does
not support private registry authentication or publishing. npm audit is a
separate service, and this read-only proxy does not implement its POST endpoints.

## Turning it on in the app

Turn on the install gate under Protections. Setup runs in the background through
the engine, reports progress, and can be retried after a failure. A verified
cached list is served before any network refresh. First setup downloads and
verifies a snapshot from the feed pinned in the build. Only after the local
listener has started does BoxCop add its marked, reversible block to the user
`~/.npmrc`.

Routing that was on when BoxCop quit is restored when it starts again. Turning the
gate off restores `~/.npmrc` before the proxy stops.
`BoxCop --status` reports whether the gate is configured, routed and listening.

The list and the keys for local artifact links are kept under
`~/Library/Application Support/BoxCop/package-protection/`. Keep this directory:
it holds the last accepted sequence number, which is what stops an older list
from being accepted. Blocked requests are logged there in `blocks.json` with the
package name, version and reporting sources.

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
  tests/test_package_proxy.py tests/test_package_installs.py tests/test_package_routing.py \
  tests/test_package_runtime.py tests/test_supply_chain.py
```

The real npm/pip tests use only locally generated inert archives and a simulated
upstream transport. They exercise allowed fresh releases, blocked direct and
transitive installs, and an npm install-script marker that must never execute.
Other tests cover signatures, wrong keys, rollback across restart, source
withdrawals, range boundaries, ecosystem isolation, failed updates, forged artifact
links, source pagination, and enrollment. No malware samples are downloaded.
