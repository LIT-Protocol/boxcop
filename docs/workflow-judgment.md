# Local AI workflow judgments

Activity now has an **AI workflow review** card. It summarizes the apparent task,
flags potential safety concerns, cites evidence events, suggests review steps and
states uncertainties. This is holistic interpretation of linked observations,
not just classification of isolated strings. It is advisory: no model output
changes a policy, authorizes an action, executes a command or blocks a process.

## Running it

BoxCop includes a signed llama.cpp inference engine. No Ollama installation,
terminal commands or separately managed service is needed. When local AI review is
enabled and workflow evidence first arrives, BoxCop downloads Qwen3.5-4B Q4_K_M
(2.74 GB) from Hugging Face. Activity shows download progress, verification and
startup. Allow at least 3 GB of free storage; inference also needs several GB of
available memory. Download failures retry after five minutes. Turning review off
and on retries immediately; turning it off cancels setup and stops inference.
An interrupted download restarts from the beginning. Completed weights are reused
across launches and app updates.

The download uses an immutable revision, exact byte count and SHA-256 verification.
Only a complete verified file is atomically installed in the private directory
`~/Library/Application Support/BoxCop/models/workflow/`. Existing weights are
hashed before first use in each sidecar. Download requests contain no workflow
evidence. The model's Apache 2.0 license ships in the app; inference runtime and
third-party licenses ship under `Contents/Resources/inference/`.

The app owns a randomly ported, authenticated loopback-only inference process.
Requests bypass proxies and reject redirects. There is no cloud inference fallback,
web UI, tool execution, agent mode or disk prompt cache. The process exits when
its owning sidecar stops or dies; idle inference releases the model after two
minutes. Clearing the workflow terminates the model process and invalidates
in-flight results. The separate MiniLM text classifier abstains on uncertain
fields; the holistic reviewer evaluates those fields in context instead of loading
a second large model.

The Activity toggle is remembered across launches. It does not disable timeline
collection or deterministic protections. Existing collection permissions/opt-ins
control the evidence available to review. Review defaults to enabled. Setup,
inference or validation failure produces unavailable, never a safety verdict.

Developers need CMake in addition to the existing build toolchain. The bundle
builder downloads checksum-pinned llama.cpp source, builds a statically linked
runtime with Metal support and a parent-process watchdog, and signs it with the
rest of the app. CI packages the runtime but never downloads the large model.
Runtime and model pins live in `bundle_inference.py` and `server/local_inference.py`.

## Evidence and results

The worker uses [unified workflow context](workflow-context.md), including prompts,
tool calls/results, OCR, browser and window context, process identity, network
destinations, source availability and typed links. Raw image pixels are not sent;
OCR and image-reference metadata are the available visual evidence. Captured paths
are never opened by the reviewer. Inputs can contain sensitive work data.

A compact packet preserves input/event-kind diversity, clips field values to 768
characters, and trims to approximately 10 KiB of UTF-8. Clipping, missing sources,
omitted events and timeline loss mark the assessment incomplete. The model uses a
16,384-token window and a bounded output schema. Model citations are constrained to
supplied event aliases and validated back to original event UUIDs. Findings without
valid citations, contradictory results and incomplete responses are rejected.

Results have four categories: `no_concern_observed`, `needs_review`, `high_risk`,
and `insufficient_evidence`. The first means no concern was identified in the
reviewed evidence, not that the workflow is safe. Reported requests do not prove
execution; candidate links do not prove causation or payload transfer. These
constraints are in the model prompt, but narrative mistakes remain possible.

One background worker retains one latest pending snapshot and starts at most one
review every 30 seconds. Inference has a 180-second socket deadline (including slower CPU-only Macs). First-use setup runs on the worker; after setup it takes the newest pending snapshot. Repeated
unchanged snapshots reuse the result for up to two minutes. Findings identify the
reviewed context, revision, timestamp and evidence IDs; the UI marks them when newer
activity has arrived. Clearing, pausing, switching sessions, disabling review or
closing the sidecar invalidates in-flight results. Context and judgment results
are memory-only in the sidecar, except that on a Mac enrolled in team reporting
under the `team-reporting-v2` disclosure, each completed review rated `needs_review`
or `high_risk` has its risk, completeness, finding count and cited evidence kinds (not its
text) projected into the private team outbox (see
[team reporting](team-reporting.md#security-activity-team-reporting-v2-only)). The existing separate workflow journal retains
collected observations according to its own policy. Model responses are not put
in the decision audit or used by the action gate. Clearing the workflow stops the owned inference process, including its in-memory KV cache.

## Validation and limits

`tests/test_workflow_judgment.py` covers evidence binding, byte budgets, scheduling,
clear/shutdown, stale-result labeling and transport restrictions without a model.
`python tools/evals/workflow_judgment.py --live --report /private/report.json` runs
six synthetic cases against the installed local model. It never executes the
recorded commands or contacts their destinations. This checks risk categories and
citation validity, not production accuracy or narrative factuality.

Prompt isolation, constrained JSON and validation reduce failure modes; they do
not establish resistance to all prompt injections or guarantee factual reasoning.
The small local model can miss risk, misattribute intent or overstate an outcome.
This is why findings remain explicitly advisory and coverage limitations stay
visible. The [llama.cpp server](https://github.com/ggml-org/llama.cpp/blob/7071ba378afa96dcd69c41e1ec2b4912364dbee4/tools/server/README.md) provides constrained JSON output.

Historical [build 116 evaluation evidence](../artifacts/workflow-judgment-evaluation-v1.json)
includes six local-model fixtures and a signed-app VM check. The VM used an explicit
temporary loopback SSH test bridge to the host model; the app has no remote fallback.

Build 116 used the earlier external-runtime integration; it does not qualify the bundled-runtime path.

[Build 118 bundled-runtime evidence](../artifacts/bundled-workflow-inference-v1.json)
records the current six-case evaluation, first-use model installation in the VM,
a locally generated high-risk finding, authenticated transport and process shutdown.
No host inference bridge or external model service was used. CPU-only VM reviews
were substantially slower than host GPU reviews; this is not a performance qualification.
Narratives can still over-infer intent or end in clipped sentences despite valid JSON.

## Local usage totals

The Activity review card shows persistent workflow inference attempts and outcomes.
Counts begin after successful model preparation; model downloads, setup failures,
backoff and reused judgments do not count as inference. Validated insufficient-evidence
results count as uncertain, other validated judgments as ready (not as safe).
Transport failures and invalid responses count separately. Aggregate counters survive
clearing and restarting the reviewer; workflow text and generated findings are not
stored in these counters. The main engine’s MiniLM counters remain separate.

Opt-in [Gmail AI work review](email-review-risk.md) adds draft-specific probability estimates,
pre-action evidence filtering and nonblocking browser warnings. Sending is never blocked;
email review uses a separate focused request to the same local model.
