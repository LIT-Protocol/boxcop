# Live unified workflow context

The app feeds its enabled collectors into `WorkflowTimeline`. NetworkExtension
activity now enters the same timeline and private rotating workflow journal as
native, browser and agent observations. Activity offers **Export linked context**
for inspecting the exact bounded evidence packet used by the local reviewer.

## Inputs and coverage

| Input | Included evidence | Limits |
| --- | --- | --- |
| Network extension | Original network event ID/time, destination, available hostname, sanitized URL, process/ancestry/signing identity, decision and threat-list reason | New flows only; no payloads, byte counts or proof of transfer; requires enabled network extension |
| Running applications | GUI app snapshots every 30 seconds, focus and lifecycle | Not a universal process census; network records add CLI/helper identities |
| Window and screen collectors | Window metadata, selected text when enabled, OCR, capture IDs and local image references | Existing opt-ins/permissions apply; retained images rotate; background screen checks run only when macOS reports another app capturing and contribute assessment metadata, not pixels/OCR |
| Agent hooks | Reported run/tool/call identifiers and available prompts, arguments and results | Only connected integrations; preflight hooks do not observe tool completion; same-user reports are untrusted |
| Browser extension | Document context and reported navigation/copy/paste/upload/request events | Extension opt-in; no verified account identity or file-to-network payload binding |
| Files | Selected-root FSEvents changes | No file-read or responsible-process attribution |
| Clipboard policy | Attempt, classification/decision and context references | No raw clipboard body retained in this packet; attempt is not insertion |
| Software inventory | Up to 128 observations with name/version/path and advisory states | Snapshot findings, not execution or quarantine |

Endpoint Security remains a separate privileged offline journal where available.
The protected build does not assume that entitlement or claim system-wide file/exec
coverage. Missing permissions, disabled collectors, awaiting hooks, retention loss,
truncation and context omissions are represented explicitly.

## Context contract

`WorkflowContext.build` produces `boxcop.workflow-context.v1`:

- Session, revision, generation time, event IDs, original observation times and
  received times; field-level provenance, availability and truncation.
- Typed links: explicit recorded references; reported browser-document and scoped
  agent run/call identifiers; kernel PID + PID version + UID + boot identity.
  Bare PID/responsible-PID matches and browser URL/hostname matches within five
  seconds remain **candidates**, not proof of a request or payload relationship.
- Image artifact references and their availability. References are data; the
  sidecar never opens arbitrary captured paths. OCR is inline where collected.
- Source coverage, omitted event counts, timeline loss and quality issues.

The packet covers the latest ten minutes, at most 64 events and 96 KiB. Selection
preserves a mix of collectors during network bursts, then trims to fit the byte
budget. Links are capped at 256. The live timeline retains 2,000 events; its private
journal retains up to 64 MiB. This is bounded evidence, not a complete recording.

The network importer pages the durable two-segment network journal, rather than
polling the latest 100 UI rows. Cursor expiry, journal drops and write failures
surface as collection-health events. Imports deduplicate source IDs during the
app session; `network_event_id` preserves the original source identity. Reimported
history in a new app session gets new workflow IDs, avoiding conflicting journal
records. Clearing live context prevents old network history from being reimported;
it does not erase the saved journals or separate captures.

## Classifier and judgment access

A dedicated local sidecar receives context at most once every three seconds,
independently of the paste-decision pipe. `workflow_context` validates the bounded
packet and `engine.workflow_context.for_judgment()` provides a detached copy of its
full graph to a judgment consumer. Evidence expires after 15 seconds without a
refresh. `workflow_clear` drops the packet and classifier cache/pending work.

Today this path classifies up to eight available, untruncated text fields per
packet using the existing content classifier. It returns event-linked sensitive
content labels and observed threat-domain blocks, along with counts and explicit
classification omissions. Captured text is untrusted evidence, never system
instructions. The [holistic local judgment worker](workflow-judgment.md) also reviews a compact
linked packet to infer apparent intent, cite concerns and state uncertainties.
It is advisory; existing deterministic protections retain their authority.

Pausing monitoring clears the reviewer and subsequent packets contain only enabled
network/inventory observations. It does not stop the independent network filter.
Collector opt-ins still govern acquisition; this feature does not enable screen,
selected-text or adapter capture silently. Hook arguments and other opted-in text
may contain secrets and can enter the private workflow journal. The SQLite hook
decision audit remains sanitized. Context responses contain counts and signal IDs,
not captured text; the sidecar retains context in memory, not its SQLite audit.

See [offline reconstruction](workflow-reconstruction.md) for explicitly joining
exported native and privileged journals and [network scope](outgoing-connections.md)
for network retention and hostname limitations.

Build 114 was exercised in a SIP-enabled macOS VM with network-only and mixed
network/process/window/screenshot/synthetic-adapter packets. Counts, hashes and
limits are recorded in [live evidence](../artifacts/unified-workflow-context-live-v1.json).
