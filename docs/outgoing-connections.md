# Network activity and threat-domain blocking

Activity journals now use [application-level encryption and explicit plaintext export](journal-encryption.md). Historical JSONL filenames contain encrypted records; export before using offline replay tools.

Both beta and stable distribution builds observe new outgoing network flows across this Mac. There
is no enrollment list: apps installed after setup, command-line tools, helpers and
system processes are included when macOS delivers their flows to the extension.
**New flows to listed threat hostnames are blocked before payload transfer. Other
flows are logged and allowed.** This is destination reputation, not payload
inspection or a guarantee that allowed downloads are safe. Endpoint Security
approval and agent sandboxes are not required.

## Setup

1. Install the signed, notarized BoxCop build in `/Applications`.
2. In setup, install (or update) the network extension and approve it in macOS.
3. Enable network protection and accept macOS's network-filter permission.
4. Connections shows the live threat-blocking switch, list date and activity.

No app picker or per-app administrator prompts are needed. The wizard checks the
installed extension version, filter settings and observation service. Previously
completed installations return to setup if those are missing. Network observation
can be enabled without consenting to clipboard or screen monitoring. Connections
shows current state and the latest activity after setup.

Upgrading from the selected-app prototype replaces its blocking provider. The new
provider never consults old enrollment or temporary rules. A hostname match is
evaluated synchronously from an immutable in-memory list, independently of process
inspection and log writes. Unknown process identity, a full logging queue or an
unwritable journal cannot bypass a domain block or cause an unrelated flow to be
blocked. The legacy ES-backed development route is separate.

## Threat list and limits

The signed extension bundles [HaGeZi Threat Intelligence Feeds Mini](https://github.com/hagezi/dns-blocklists#tifmini),
a list of malware, phishing and other threat destinations. The unmodified data,
GPL-3.0 license, attribution and pinned source/hash manifest are in
`desktop/macos/Resources/ThreatDomains`, copied into the signed extension's
`Contents/Resources/ThreatDomains`. Runtime verifies the SHA-256 and entry count.
No reputation queries or automatic feed requests leave this Mac.

This first version ships snapshot updates with app releases. The UI shows the
upstream publication date and warns after seven days; old snapshots keep working
but do not know about newer threats. The release workflow runs
`desktop/macos/scripts/refresh_threat_domains.py`, which pins the newest upstream
commit, validates the list with the runtime's host rules and rewrites the snapshot
and manifest before building; a list older than two days, malformed, or less than
half the previous size fails the release. Each release attaches the shipped
`threat-domains-manifest.json`. Run the same script locally to commit a refreshed
snapshot. Retrieval time must not be substituted for publication time. This is not a continuously updated threat service.

Matching checks both URL host and remote hostname supplied by macOS, lowercases
ASCII names, and removes one DNS trailing dot. Only exact hostnames match: no
substring, suffix, shared-IP or "strange-looking name" rules. Punycode labels work;
raw Unicode, malformed names and IP literals are not domain matches. No reverse
DNS is used. Unlisted subdomains, direct-IP flows, missing/spoofed hostname
metadata, proxies/VPN tunnels, encrypted DNS, established connections and traffic
outside this extension's visibility can evade this layer. It does not inspect
TLS, scan downloads or distinguish individual safe/unsafe paths on a listed host.

Threat blocking defaults on when this extension runs. The authenticated local
control socket lets root or the configuring user switch to logging-only mode;
that preference persists in the private `threat-blocking.txt` file. This is a user
control, not tamper resistance against malicious code running as that user or root.
A corrupt/missing bundled list is reported and falls back to logging-only; a
corrupt preference is reported with blocking off until reset. The UI exposes a
false-positive escape hatch by disabling threat blocking without disabling logs.
No per-domain exceptions are implemented yet.

The reserved hostname `malware-test.boxcop.test` is an explicit harmless test rule,
labeled separately from threat intelligence. It does not resolve publicly. Native
tests temporarily map it and an actual listed hostname to a controlled receiver,
using a scoped synthetic DNS server, then verify zero delivered requests with
blocking on and successful requests with blocking off. `/etc/hosts` mappings
were observed to lack hostname metadata and bypass domain matching in the VM.
Test mappings are removed afterward; no live malicious host or payload is contacted.

## Recorded data

Each event has a UUID, timestamp, outgoing direction and `observed_allowed` or
`blocked_threat_domain` decision. Blocked records include the matched hostname,
list source/revision and reason; old observation-only records remain readable.
Exported timestamps currently use Foundation seconds since 2001-01-01 UTC.
It describes a newly attempted flow, not a confirmed connection or transfer.

| Data | Source and limits |
| --- | --- |
| PID, effective UID, process incarnation | Kernel flow audit token; unknown tokens still produce an event |
| Executable path and name | Code identity and a live process snapshot, when available |
| Signing status, identifier, team, code hash, flags and certificate subjects | Security framework, best effort; a valid signature is not a safety judgment |
| Arguments and ancestor PID/path chain | Live snapshot checked against the audit token before/after; unavailable for exited or inaccessible processes |
| Responsible app identity | macOS source-app audit token, separate from the process that opened the socket |
| Remote and local address/port | Socket endpoints; includes TCP/UDP, IPv4/IPv6 and loopback flows delivered by macOS |
| Hostname and its source | Prefer flow URL host, then macOS remote hostname; absent when neither is supplied |
| URL, transport, socket family/type/protocol | Flow metadata, when available |

This follows the process/destination metadata used by
[LuLu's flow provider](https://github.com/objective-see/LuLu/blob/master/LuLu/Extension/FilterDataProvider.m)
and [process inspection](https://github.com/objective-see/LuLu/blob/master/LuLu/Extension/Process.m).
We retain both the observed endpoint and any hostname, including hostname
provenance. We do not infer a verified domain from reverse DNS. An IP-only flow
stays IP-only. Ancestry is an observation-time snapshot, not ES-backed lineage.

Fields are bounded: URLs 2,048 characters, arguments 4,096 bytes/64 entries,
ancestry 16 generations, process path 4,096 characters. Environment variables and
payloads are not collected. Arguments and URLs can contain sensitive information;
setup and the history view disclose this. No network telemetry leaves the Mac.

## History, export and health

The extension stores owner-only encrypted record files under
`/Library/Application Support/BoxCopNetwork.noindex/`: `connections.jsonl` and
`connections.previous.jsonl`, each at most 4 MiB. Rotation discards the oldest
file. History survives app closure and extension restart. This is a bounded
local history, not a tamper-proof audit trail or a guarantee of crash durability.

The default UI summarizes apps and destinations for Today or the Last 7 Days
(today and the preceding six local calendar days). Expand an app to see its
hostnames and IP-only destinations, attempt/blocked counts, processes and first/last
seen times. Domains reverses that grouping; Blocked shows rows with blocked attempts
and their reason. Unknown attribution and missing hostnames remain explicit.
Counts describe attempted flows, not established connections or transferred bytes.

Daily app/process/destination summaries are stored separately in the private
`network-summary.json` encrypted checkpoint, so raw-log rotation does not erase statistics.
Collection begins when the updated extension starts; older raw events are not
backfilled. Summaries survive restart and retain seven calendar days, capped at
4,000 rows and a conservative 12 MiB encoded-size budget. Capacity omissions are
reported cumulatively since summary collection began. Checkpoints are atomic,
owner-only, and saved in batches every five seconds; an abrupt restart may lose
the latest counters. Failed checkpoints and incomplete observation are reported
in the UI. No payloads or byte totals are collected.

The optional Recent Activity view searches the latest 100 retained events, displays
up to 30 matches, opens connection details, and exports all retained raw records as JSON. The export is a
user-controlled file. Root and the user who initially enabled observation can
read history through the authenticated local socket; other local users cannot.
The provider observes all UIDs, including system processes, rather than filtering
collection to that owner.

A bounded queue decouples observation from process inspection and disk writes.
The view reports flows observed, queue drops and write failures for the current
provider session. Unknown attribution remains visible. Overflow drops log entries,
never changes the threat verdict. Disabling the filter stops collection and
blocking; removing the
extension retains history. Existing sockets, cloud agents, unsupported flow types
and traffic macOS does not deliver are coverage limits.

## Signing and provisioning

The canonical local credential/configuration directory is `~/.sentinel-lab/`.
Private signing keys and notarization secrets remain in macOS Keychain. Never
commit credentials. Developer ID profiles are:

- `~/.sentinel-lab/profiles/Allay_Developer_ID.provisionprofile`
- `~/.sentinel-lab/profiles/Allay_Network_Developer_ID.provisionprofile`

The app identifier is `local.sentinel.endpoint`; the extension identifier is
`local.sentinel.endpoint.network-filter`. Both need
`content-filter-provider-systemextension`; the app also needs
`com.apple.developer.system-extension.install`. No ES entitlement is included.
`BOXCOP_APP_PROFILE` and `BOXCOP_NETWORK_PROFILE` override profile paths.

```sh
./build.sh
```

The wrapper always builds `distribution`, with channel `beta` by default, matching main-branch CI, and automatically uses
the current Unix timestamp as the extension build number. `BOXCOP_EXTENSION_VERSION`
can override it with an increasing positive integer. `BOXCOP_CHANNEL=stable` selects the stable channel with the same protections.
Only the explicit lower-level `--profile limited-development` omits the network
extension for development validation. Legacy `BOXCOP_PROFILE` overrides are rejected.

The builder validates Apple profiles, signs, notarizes and staples the app and DMG.
It never falls back to ad-hoc signing. App and extension both carry
`NSSystemExtensionUsageDescription`. CI signing triggers are unchanged.

## Validation

The [native threat-blocking report](../artifacts/threat-domain-blocking-live-v1.json)
records signed/notarized build 112 on the SIP-enabled VM. An actual listed hostname
and the reserved test hostname were routed only to our harmless receiver. With
blocking on, both fresh DNS attempts and cached-DNS TCP attempts were denied with
zero downloaded bytes. The unlisted name on that same receiver stayed reachable.
The UI's logging-only switch restored both downloads and persisted across a forced
provider restart. Making the journal unwritable did not bypass blocking or deny
the unlisted flow. The native details view and exported history retain the reason
and source revision. The `/etc/hosts` hostname-visibility miss is recorded too.

Core tests exercise metadata provenance, unknown identities, journal persistence,
rotation, size bounds and file permissions/symlink rejection. The [native observation report](../artifacts/network-observation-live-v1.json)
records a signed/notarized build 111 on a SIP-enabled macOS 14.6.1 VM: automatic
coverage of a newly added tool, TCP/UDP receiver delivery, `curl → example.com`
metadata, network-only setup, local access controls and native JSON export.
History survived a forced provider restart in candidate 110, although termination
reset the VM SSH connection. A deliberate journal write failure in build 111
reported four errors while all four test connections reached the receiver; writes
resumed after recovery. This evidence is separate from the historical blocking
prototype's [setup and TCP test](../artifacts/network-setup-live-v1.json).

Remaining qualification includes high-volume performance, sleep/wake, VPNs and
other filters, all supported macOS versions, hostname availability across apps,
multiple login sessions, abrupt termination and uninstall/reinstall. These are
not established by a successful build or a single VM run.
