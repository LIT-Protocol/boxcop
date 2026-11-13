# Activity context for smart triage

The app joins what the layers observe into one bounded packet of linked events.
The packet is the evidence the [local model](workflow-judgment.md) reviews. It is
context only: nothing in it authorizes or blocks anything.

## Inputs

| Input | Evidence | Limits |
| --- | --- | --- |
| Network extension | Event ID and time, destination, hostname when macOS supplies one, sanitized URL, process, ancestry and signing identity, the decision and, for a block, the threat-list reason | New flows only. No payloads or byte counts, and no proof that data was transferred. Needs the network extension to be enabled. |
| Agent hooks | The agent, the kind of action, reported run and call identifiers and the decision | Only connected agents. A pre-action hook does not see whether the action completed. What an agent reports about itself is not verified. |
| Engine security events | The rows of the engine's `security_events` list: install gate blocks, refused connections from contained scripts, and agent hook denials, each with its layer, title, reason and subject. Each enters the packet as an event of kind `security_event` from the collector `engine`, with the ID `engine:` followed by the security event's ID. | Only what the engine blocked. Names, versions and hostnames, never payloads or file content. |
| Software inventory | Up to 128 observations with name, version, path and advisory state | A snapshot of installed software, not evidence of execution. |

Missing permissions, layers that are off, hooks that have not been called,
dropped history and truncated fields are represented in the packet explicitly, so
a reviewer can tell "nothing happened" from "nothing was observed".

## The packet

`WorkflowContext.build` in `desktop/macos/Sources/BoxCopCore/WorkflowContext.swift`
produces schema `boxcop.workflow-context.v1`:

- Session, revision and generation time. For each event: its ID, when it was
  observed and received, its kind, the collector it came from, and per-field
  provenance, availability and truncation.
- Typed links between events with one of three strengths. `recorded_reference`
  is an explicit reference in the data. `shared_identifier` joins events that
  carry the same identifier, such as a kernel process identity. `candidate` is a
  weaker match, such as a bare PID, and is never proof of a relationship.
- The state of each source, the number of omitted events, dropped history and
  quality issues.
- A fixed marker, `context_only_not_authorization`.

The packet covers the latest ten minutes and holds at most 64 events, 256 links
and 96 KiB. Selection keeps a mix of sources during a burst of network events and
then trims to the byte budget. It is bounded evidence, not a complete recording.

The engine validates every packet against these bounds (`validate_context` in
`server/workflow_context.py`) and rejects anything else. The app sends a packet
through the `workflow_context` pipe operation at most once every three seconds.
The engine keeps only the latest packet, in memory, and treats it as expired
after 15 seconds without a refresh. `workflow_clear` drops it and any review in
progress.

A finding from the model must cite events in the packet. When it cites an
`engine:` event, the app attaches the explanation to the matching row in the
Events list.

The engine's reply holds counts and signal identifiers, never event text. Two
signals are computed without the model: `observed_domain_block`, for a network
event the extension blocked, and `sensitive_content_label`, for an event whose
text matches the engine's secret and sensitive-data patterns. At most eight text
fields per packet are checked this way.

## Journals

The app keeps the events it has joined in a private, rotating, encrypted journal;
see [journal-encryption.md](journal-encryption.md). Network history has its own
retention, described in [outgoing-connections.md](outgoing-connections.md).
Clearing the live context does not erase saved journals.
