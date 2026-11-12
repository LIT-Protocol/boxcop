# BoxCop collection and evaluation data format

This is BoxCop's current implementation contract, not Ent's private schema.
Start with the [complete synthetic transfer capture](examples/synthetic-transfer/)
and the commands below. Collector evidence, reconstructed hypotheses, and evaluator
labels are separate data layers. Never put answer labels into model inputs.

## Files and versions

| Artifact | Version / shape | Purpose |
| --- | --- | --- |
| Exported journal | `boxcop.workflow.journal.v1`, JSONL | One envelope and event per newline; replay/reconstruction input. On-disk journals are [encrypted](journal-encryption.md); explicitly decrypt/export first. |
| UI export | `boxcop.workflow.v2`, JSON object | Bounded `events` array plus `synthetic`, `droppedEvents`, retention and limitations; not directly accepted by journal replay |
| Writer health | Unversioned `health.json` | `written`, `dropped`, `evictedSegments` nonnegative integers; `failed` boolean |
| Reconstruction | `boxcop.workflow.reconstruction.v1`, JSON object | Joined evidence graph and possible workflows |
| Replay expectations | `boxcop.workflow.expectations.v1`, JSON object | Counts/order/forbidden-kind assertions; see [replay](workflow-replay.md) |
| Example evaluation labels | `boxcop.eval.labels.v1`, JSON object | Initial fixture convention, not an app wire format or implemented model scorer |

User/native/browser/agent events share the user journal. Endpoint Security has a
separate root-private journal. Each collector timeline has its own session and
sequence; there is no global sequence. Endpoint identity is supplied to the offline
reconstructor, not authenticated by journal contents.

## Journal envelope

Each UTF-8 line is a complete JSON object followed by a newline:

```json
{
  "schemaVersion": "boxcop.workflow.journal.v1",
  "synthetic": true,
  "droppedBefore": 0,
  "event": {
    "id": "a1111111-1111-4111-8111-111111111111",
    "sessionID": "b2222222-2222-4222-8222-222222222222",
    "sequence": 1,
    "observedAt": "2026-01-01T00:00:01Z",
    "receivedAt": "2026-01-01T00:00:01Z",
    "kind": "browser_file_selected",
    "phase": "observed",
    "collector": "browser.extension",
    "provenance": "reported",
    "availability": "available",
    "fields": {
      "file_name": {"value": "report.txt", "provenance": "reported", "availability": "available", "truncated": false}
    },
    "relatedEventIDs": []
  }
}
```

The example above is formatted for reading; JSONL must put the entire object on
one line. `synthetic` describes the capture, independent of provenance. A fake
kernel event can have `provenance: observed` while its envelope is synthetic.
Real VM collection of synthetic interactions currently uses the normal journal
writer (`synthetic: false`); fixture reports separately identify the test. Do not
assume every VM record is synthetic or relabel a whole mixed capture.

`droppedBefore` is a cumulative writer loss counter sampled for the row, not a
per-row delta. Preserve health alongside segments; do not sum cumulative counters
across rows. Retention eviction differs from queue loss and kernel loss. A missing
newline indicates a possible crash-truncated tail, not a valid final record.

## Event and field types

| Event key | Type | Contract |
| --- | --- | --- |
| `id`, `sessionID` | UUID strings | Event identity and timeline lifetime; clearing/restarting a timeline changes its session |
| `sequence` | integer ≥ 1 | Increases within a session; gaps are evidence-quality issues |
| `observedAt`, `receivedAt` | ISO-8601 strings with timezone | Observation and timeline acceptance times; may be equal and are not guaranteed monotonic |
| `kind`, `collector` | nonempty strings | Event family and producing API/adapter |
| `phase` | string | Common values `observed`, `attempted`; not a successful-action flag |
| `provenance` | string | Common values `observed`, `reported`, `derived`, `declared`, `unknown`; preserve rather than upgrade |
| `availability` | string | `available` or a collector-specific failure/coverage reason |
| `bundleID`, `windowTitle` | optional string | Native context when present; Swift omits nil optionals |
| `pid` | optional integer | Native process identifier; insufficient alone to identify a process lifetime |
| `fields` | object of field objects | Kind-specific evidence; numeric values here are strings |
| `relatedEventIDs` | array of UUID strings | Explicit references, usually nearby context; maximum 16 emitted by the timeline; not causal proof |

Each field has `value` (string or null/omitted for Swift nil), `provenance` string,
`availability` string and `truncated` boolean. For example, unavailable file bytes:
`{"value":null,"provenance":"observed","availability":"not_collected","truncated":false}`.
Missing, null and empty are not interchangeable. Unknown is not benign, failed,
or zero. Swift bounds field strings to 4,096 characters and window titles to 512.
The reconstructor excludes unavailable or truncated fields from identity matching.
Collectors may additionally signal truncation through availability or companion
fields; do not treat `truncated: false` as proof of complete source content.

## Collected event families

Fields below are available vocabulary, not guaranteed presence on every event.

| Kinds | Collector / key evidence | Limits |
| --- | --- | --- |
| `app_focus`, app lifecycle events | `NSWorkspace`; native PID/bundle | Focus is not action attribution |
| `window_context` | `Accessibility.focusedWindow`; title, selected text and accessibility context | Requires permission; missing UI attributes remain unavailable |
| `mouse_click` | `NSEvent.mouseDown`; `button`, `target_attribution` | Frontmost app attribution, not exact semantic target |
| `clipboard_change_observed`, `paste_attempt`, `paste_shortcut_passed` | `NSPasteboard+CGEventTap` / `CGEventTap`; `clipboard_revision`, `monitor_generation`, `insertion` | Journal rows do not contain the clipboard payload; shortcut passage does not prove insertion |
| `policy_decision` | `rules+sequence`; `action`, `audit_record_id`, clipboard snapshot IDs | References its observed input; policy output is not ground truth |
| `file_change` | `FSEvents`; `path`, `flags`, `stream_event_id`, unavailable `responsible_process` / `file_read` | Changes, not reads or process attribution |
| `visual_context` | `ScreenCaptureKit.window`; `artifact_path`, derived `recognized_text`, `recognition_confidence` | Screenshot is a separate local artifact; OCR is derived, permission-dependent and bounded |
| `file_open`, `process_exec` | `EndpointSecurity`; `executable`, `effective_uid`, `audit_uid`, `pid_version`, `parent_pid`, `signing_id`, `team_id`, `code_signing_flags`, kernel sequence metadata | Notification only; no file bytes or command arguments |
| `file_open` additional fields | `path`, `open_flags`, unavailable `file_contents` | Open does not prove bytes read; paths can be truncated |
| `collector_health` | Collector-specific availability plus fields such as `missing_events`, `unclean_previous_stop` | Coverage/loss evidence, not user activity |
| `browser_context`, `browser_navigation`, `browser_focus`, `browser_click`, `browser_copy`, `browser_paste`, `browser_file_selected` | `browser.extension`; document identity, URL/title, context/selection, element and file metadata | Same-user reported evidence; untrusted page text; file selection is not upload |
| `browser_request`, `browser_download` | Request/download identifiers and transport state | Completion is not SaaS acceptance or verified destination identity |
| `agent_instruction`, `agent_tool_call`, `agent_tool_result` | `agent.hook`; instruction/run/call/tool/result metadata | Requires explicit hooks/wrapper; not automatic agent discovery |

Browser field vocabulary: `url`, `page_title`, `tab_id`, `frame_id`, `navigation_id`
(Chrome document ID), `browser_session`, `element_role`, `element_label`,
`selected_text`, `context_text`, `context_truncated`, `account_scope`,
`account_evidence`, `file_name`, `file_size`, `mime_type`, `download_id`,
`transfer_state`, `bytes_received`, `referrer`, `request_id`, `request_method`,
`request_type`, `status_code`, `network_error`, `initiator`.
`browser_upload` is accepted by ingress but is not proof that a built-in collector
observed a completed upload. Request states are `started`, `completed`, `failed`;
download completion uses `complete`. HTTP status is a string, e.g. `"403"`.

Agent vocabulary: `run_id`, `parent_id`, `call_id`, `tool`, `instruction`,
`arguments`, `result_summary`, `status`, `resource`, `process_id`, `duration_ms`.
Run/call identity remains reported. `process_id` is a string-valued field and is
not interchangeable with the event's native integer `pid`.

Ingress is a different format: `{"version":1,"kind":"…","fields":{"key":"value"}}`.
It accepts only allowed browser/agent kinds and keys, at most 16 string fields,
4,096 characters per value and 65,536 bytes total. The app adds event IDs, timestamps
and provenance. Browser URL is required; agent `run_id` must be nonempty. URL
userinfo, query and fragment are removed. Requests do not collect bodies, cookies
or authorization headers. Declared personal/managed account scope is not verified
SaaS identity. See `AdapterEvent.decode` in `Workflow.swift` for the allowlist.
`browser_composition` (Gmail draft lifecycle) has its own closed key set and values, with
no page title or text; see [review reminders](human-review-reminders.md#developer-contract).
Browser events carry `observed_at_ms`: browser epoch milliseconds taken when the extension
callback fired, before the native queue, so queued delivery cannot reorder them. The app uses
it as `observedAt`, never later than arrival; `receivedAt` remains arrival time.

## Reconstructed graph as evaluation input

[Reconstruction](workflow-reconstruction.md) documents matching rules and bounds.
The JSON report includes:

- `endpointID`, `synthetic`, `status`, `evidenceComplete`, input/unlinked counts.
- `sources` and `issues`: preserve journal losses, gaps, clock regressions and
  clipping; `evidenceComplete` means no detected issues, not exhaustive visibility.
- `nodes`: original event IDs and provenance with source names. Default output
  keeps selected metadata; `--include-events` preserves full event fields for
  content-dependent evaluations. Unlinked events are counted but not included as
  nodes, even with that option; use the raw journals for complete retained input.
- `links`: `id`, `from`, `to`, `relation`, `strength`, `reason`,
  `causationEstablished`. Strength is `recorded_reference`, `shared_identifier`
  or `candidate`, not a probability. All current links leave causation false.
- `workflows`: `id`, `kind`, `anchorEventID`, `eventIDs`, `linkIDs`,
  `transportOutcomes`, `causationEstablished`, `accountIdentity`. Kinds include
  `possible_file_transfer`, `possible_copy_paste`, `native_paste_attempt`,
  `agent_run`, `agent_tool_activity`. Application outcome and account identity
  remain unknown even after HTTP 201.
- `ambiguities`: candidate counts and emitted counts; do not discard competing
  same-name file paths when constructing an evaluation prompt.

## Generate and validate a synthetic case

```sh
python3 tools/workflows/synthetic_transfer.py /tmp/boxcop-transfer-001
python3 tools/workflows/replay.py /tmp/boxcop-transfer-001/native.jsonl
python3 tools/workflows/replay.py /tmp/boxcop-transfer-001/endpoint.jsonl
python3 tools/workflows/reconstruct.py \
  --source native=/tmp/boxcop-transfer-001/native.jsonl \
  --source endpoint=/tmp/boxcop-transfer-001/endpoint.jsonl \
  --endpoint-id synthetic-endpoint --include-events \
  --report /tmp/boxcop-transfer-001/graph.json
```

The generator refuses an existing output directory, creates private files, uses
deterministic UUIDs/timestamps and makes no network requests. It writes two source
journals and a **separate** `labels.json`. The checked-in example is reproducible.
The older `synthetic.py` remains a small eight-event replay smoke fixture.

The label convention records `caseID`, `endpointID`, `task`, `split`,
`anchorEventID`, `expected`, nullable `policyLabel`, and explanatory `notes`.
The included case tests reconstruction and uncertainty, not allow/block accuracy.
For policy evals, first specify the policy and version in the dataset manifest;
label actions independently of BoxCop's `policy_decision` records. Keep labels
and future events outside the prompt for a decision-at-time task. Separate latent
scenario truth (e.g. a fictional file really was sent) from what the supplied
evidence justifies (e.g. delivery remains unknown).

Use unique session/case IDs when combining generated cases. Keep all variants of
one scenario/template in the same train/dev/test split to avoid leakage. Vary file
names/paths, apps, destinations, timing, process lifetimes, request outcomes and
content, rather than only paraphrasing a single case. Include benign workflows,
sensitive content, duplicate basenames, intervening clipboard copies, PID reuse,
missing document IDs, HTTP rejection/network failure, absent content, truncation,
writer/kernel loss and untrusted page instructions. Do not hide missing evidence
or fabricate trusted actor identity to make cases easy.

Before model benchmarking, freeze a dataset manifest (generator/version/seed,
policy version, split and case hashes), input projection and scoring rubric.
Score uncertainty/abstention and unsupported claims as well as task accuracy;
track local-model latency, memory and false-positive/false-negative rates. No model
runner or policy scoring implementation is added by this data-format document.

For runnable model comparisons using this contract, see the [model evaluation guide](model-evaluation.md).

### Native agent policy audit actions

The policy `EventInput`/SQLite audit contract now also accepts `action=read` and
`action=write`. These are distinct from collector event kinds and do not change
`boxcop.workflow.v2`. Claude native callbacks record `app=claude`, a hashed
session ID, `source=reported-native-hook:<reported cwd>`, and the resolved file
path in `destination`. Read bytes are not loaded by the hook; Write/Edit supplied
text is evaluated transiently and persisted as `[not retained]`. Path resolution
is a preflight snapshot, not proof that the subsequent access used that inode.
The main clipboard history excludes these agent records before pagination;
the audit store retains them for inspection and replay.

### Supply-chain assessment and ordinary-user authorization

The supply-chain slice adds `host_authorization` denial events to the existing workflow
envelope, four deterministic decision policy IDs, and a separate explicit-root inventory
report (`boxcop.software-inventory.v1`). See [field definitions and limits](supply-chain-protection.md#data-and-vm-reproduction).
Metadata findings are not authenticated artifact identity and are not automatically
joined to process events or promoted into OS authorization policy.

## Software exposure inventory

The automatic bounded scanner emits `boxcop.software-inventory.v2` in a private
local cache and `software_inventory` summary events in the workflow journal. See
[the complete format and trust boundary](software-exposure.md#durable-format).
Metadata version matches are findings only; they do not prove executable identity,
exploitation or blocking. Synthetic fixture reports are marked `synthetic: true`.
