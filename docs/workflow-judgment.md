# Smart triage: the local model

BoxCop includes a local language model with one job: reviewing linked activity.
The model reads a bounded packet of recent events: network connections and
blocks, software findings, and the engine's own events from the install gate,
containment and agent checks. It describes the apparent task, flags concerns,
cites the events each concern rests on, and states what it could not determine.

Because the engine's events are in the packet, a concern can cite a blocked
install, a refused install-script connection or a denied agent action. The app
shows the model's explanation on the event it cites in the Events list, labelled
as model output.

## The rule: tighten, never loosen

The model reads attacker-controlled text: commands an agent composed, web content
an agent fetched, package and host names. A prompt injection must not be able to
grant access. So:

- No model output allows an action, lifts a block, changes a policy or runs a
  command. Only the user can loosen protection.
- Model output is not written to the decision audit and is not read by the hook
  that decides agent actions, or by the install gate when it decides whether a
  release may be allowed.
- If the model is missing, busy or wrong, the deterministic layers behave exactly
  as they would without it. A setup, inference or validation failure produces
  "unavailable", never a verdict.

Today the model is advisory only. Letting it tighten protection on its own, for
example by recommending that something stays contained, is on the
[roadmap](roadmap.md).

## Runtime and model

The app ships a signed llama.cpp server, built from a checksum-pinned source
archive and statically linked. There is nothing else to install.

The model is Qwen3.5-4B (Q4_K_M quantization, 2.74 GB), downloaded from Hugging
Face the first time triage is used. It uses about 3 GB of memory while running.

- Before downloading, the engine checks free disk space. The model is not
  downloaded unless the disk has room for it plus 4 GB. If it does not, setup
  reports an error that says how much space is needed and how much is available.
- The download uses an immutable revision, an exact byte count and a SHA-256
  check. Only a complete, verified file is installed, atomically, in
  `~/Library/Application Support/BoxCop/models/workflow/`. The download request
  carries no user data.
- An interrupted download starts again from the beginning. A failed download is
  retried after five minutes. Completed weights are reused across launches and
  app updates, and are re-hashed before first use in each engine process.
- The smart triage card under Protections can remove the downloaded model. The
  files are deleted only while the runtime is stopped, and the app reports the
  space freed. Turning triage on again downloads the model again.
- The model's Apache 2.0 license ships in the app. The runtime's license and
  third-party notices are under `Contents/Resources/inference/`.

Exactly one model runtime runs: the engine owns a single `llama-server` process,
on a random loopback port, with an authentication token. Turning smart triage off
stops it. Requests bypass proxies and refuse redirects. There is no
cloud fallback, web interface, tool execution or on-disk prompt cache. The
process exits when the engine stops or dies, and releases the model after two
minutes without work.

Developers need CMake to build the runtime. CI packages the runtime and never
downloads the model. The runtime pin is in
`desktop/macos/scripts/bundle_inference.py`; the model pin is in
`server/local_inference.py`.

## Evidence and results

The reviewer receives the [activity context](workflow-context.md) as untrusted
data. It never opens a path that appears in the evidence.

- The packet is compacted: field values are clipped to 768 characters and the
  whole packet to about 10 KiB. Clipping, missing sources, omitted events and
  dropped history mark the assessment as incomplete.
- The model uses a 16,384-token window and a constrained JSON output schema.
- Citations must refer to events in the packet and are mapped back to the
  original event IDs. A finding without a valid citation, a contradictory result
  or an incomplete response is rejected.

A review has one of four results: `no_concern_observed`, `needs_review`,
`high_risk` or `insufficient_evidence`. The first means no concern was found in
the evidence that was reviewed. It does not mean the activity is safe. A reported
request does not prove execution, and a candidate link between two events does
not prove that one caused the other.

One background worker keeps only the newest pending snapshot and starts at most
one review every 30 seconds. Inference has a 180-second deadline, which allows for
slower CPU-only Macs. An unchanged snapshot reuses its result for up to two
minutes. Clearing the context or closing the engine cancels work in progress.
Context and results are kept in memory only.

The app keeps counts of inference attempts and outcomes. The counts hold no
activity text and no model output.

## Validation and limits

`tests/test_workflow_judgment.py` covers evidence binding, byte budgets,
scheduling, clear and shutdown, stale-result labeling and transport restrictions,
without a model.

Prompt isolation, constrained JSON and validation reduce failure modes. They do
not make the model resistant to every prompt injection or guarantee that its
reasoning is right. A 4B model can miss risk, misread intent or overstate an
outcome, and narratives can end in clipped sentences even when the JSON is valid.
That is the reason for the rule above. How accurate a small local model is at
triage is an open question listed on the [roadmap](roadmap.md).

The constrained output uses the
[llama.cpp server](https://github.com/ggml-org/llama.cpp/blob/7071ba378afa96dcd69c41e1ec2b4912364dbee4/tools/server/README.md).
