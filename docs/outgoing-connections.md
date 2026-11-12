# Network activity and threat-domain blocking

This is BoxCop's outbound control layer. It needs the Developer ID signed build;
the limited-development build has no network extension. History is stored with
[application-level encryption](journal-encryption.md).

The signed build observes new outgoing network flows across this Mac. There
is no enrollment list: apps installed after setup, command-line tools, helpers and
system processes are included when macOS delivers their flows to the extension.
**New flows to listed threat hostnames are blocked before payload transfer. Other
flows are logged and allowed.** This is destination reputation, not payload
inspection or a guarantee that allowed downloads are safe.

## Setup

1. Install the signed, notarized BoxCop build in `/Applications`.
2. In the app, turn on outbound control. macOS asks you to allow the system
   extension in System Settings, and then to allow the network filter.
3. The app shows whether the filter is active, the date of the threat list and
   recent activity. `BoxCop --status` reports the same state.

No app picker or per-app prompts are needed. The app checks the installed
extension version, the filter settings and the observation service, and reports
the layer as "Needs setup", with the missing step, when any of them is missing.
In a limited-development build the layer is "Unavailable".

A hostname match is evaluated synchronously from an immutable in-memory list,
independently of process inspection and log writes. Unknown process identity, a
full logging queue or an unwritable journal cannot bypass a domain block or cause
an unrelated flow to be blocked.

## Threat list and limits

The signed extension bundles [HaGeZi Threat Intelligence Feeds Mini](https://github.com/hagezi/dns-blocklists#tifmini),
a list of malware, phishing and other threat destinations. The unmodified data,
GPL-3.0 license, attribution and pinned source/hash manifest are in
`desktop/macos/Resources/ThreatDomains`, copied into the signed extension's
`Contents/Resources/ThreatDomains`. Runtime verifies the SHA-256 and entry count.
No reputation queries or automatic feed requests leave this Mac.

The list is a snapshot that ships with each app release. The app shows the
number of hosts and the upstream publication date. Old snapshots keep working
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
corrupt preference is reported with blocking off until reset. For a false
positive, the "Block known malware hosts" switch under Protections turns blocking
off while connections are still recorded. There are no per-domain exceptions yet.

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
list source/revision and reason.
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
stays IP-only. Ancestry is a snapshot taken when the flow was observed.

Fields are bounded: URLs 2,048 characters, arguments 4,096 bytes/64 entries,
ancestry 16 generations, process path 4,096 characters. Environment variables and
payloads are not collected. Arguments and URLs can contain sensitive information.
No network telemetry leaves the Mac.

## History, export and health

The extension stores owner-only encrypted record files under
`/Library/Application Support/BoxCopNetwork.noindex/`: `connections.jsonl` and
`connections.previous.jsonl`, each at most 4 MiB. Rotation discards the oldest
file. History survives app closure and extension restart. This is a bounded
local history, not a tamper-proof audit trail or a guarantee of crash durability.

Under Protections, outbound control lists today's connections by app, with the
number of hosts and attempts for each. Blocked attempts appear in Events with the
app, the process, its signing identity and the reason. Unknown attribution and
missing hostnames stay explicit. Counts describe attempted flows, not established
connections or transferred bytes.

Daily app/process/destination summaries are stored separately in the private
`network-summary.json` encrypted checkpoint, so raw-log rotation does not erase statistics.
Collection begins when the updated extension starts; older raw events are not
backfilled. Summaries survive restart and retain seven calendar days, capped at
4,000 rows and a conservative 12 MiB encoded-size budget. Capacity omissions are
reported cumulatively since summary collection began. Checkpoints are atomic,
owner-only, and saved in batches every five seconds; an abrupt restart may lose
the latest counters. Failed checkpoints and incomplete observation are reported
in the app. No payloads or byte totals are collected.

**Export history** writes all retained raw records to a JSON file you choose.
Root and the user who initially enabled observation can
read history through the authenticated local socket; other local users cannot.
The provider observes all UIDs, including system processes, rather than filtering
collection to that owner.

A bounded queue decouples observation from process inspection and disk writes.
The app reports dropped records and write failures for the current provider
session. Unknown attribution remains visible. Overflow drops log entries,
never changes the threat verdict. Disabling the filter stops collection and
blocking; removing the
extension retains history. Existing sockets, cloud agents, unsupported flow types
and traffic macOS does not deliver are coverage limits.

## Signing and provisioning

The app identifier is `local.sentinel.endpoint` and the extension identifier is
`local.sentinel.endpoint.network-filter`. These are unchanged from the app BoxCop
was ported from, because the Developer ID provisioning profiles are bound to
them. Both need the `content-filter-provider-systemextension` capability; the app
also needs `com.apple.developer.system-extension.install`. No Endpoint Security
entitlement is requested.

`./build.sh` validates both profiles, embeds the extension with the bundled threat
list, signs, notarizes and staples. See [releasing.md](releasing.md). The app and
the extension both carry an `NSSystemExtensionUsageDescription`.

## Validation

`swift test --package-path desktop/macos` covers hostname matching, metadata
provenance, unknown identities, journal persistence, rotation, size bounds, file
permissions and symlink rejection. `tests/test_threat_domain_refresh.py` covers
the list refresh, and `tests/test_protected_bundle.py` covers extension packaging
and profile validation.

Whether the extension loads, blocks a listed hostname and leaves other traffic
alone can only be checked with a signed build on a Mac. That check is run in the
[lab VM](vm-lab.md) using the reserved test hostname and a local receiver, so no
real malicious host is contacted.

Not yet established: high-volume performance, sleep and wake, coexistence with
VPNs and other filters, every supported macOS version, multiple login sessions,
abrupt termination, and uninstall followed by reinstall.
