# Local human review policies

The Mac app's **Approvals** page offers two opt-in rules, off by default:

- **External communications:** recognizable `mail`, `mailx`, `sendmail`, curl SMTP
  transfers, `gog`/`gws` Gmail send commands, and Gmail `users.messages.send` /
  `users.drafts.send` calls in Node inline code (`-e`/`--eval` or `-p`/`--print`).
  All recipients count; internal-domain exceptions are not implemented.
- **Spending:** Stripe CLI charge/payment-intent create/confirm commands. The
  initial threshold is USD 25. Only the simple command shape
  `stripe charges create -d amount=2500 -d currency=usd` (also `payment_intents`)
  has a known amount in this first version. Amounts strictly above the threshold,
  other currencies, confirmations, additional arguments and unknown amounts require
  review. The UI adjusts the threshold in USD 5 steps.

External communication recognition checks command positions and literal arguments,
including common execution wrappers, pipelines, command lists and shell `-c` bodies.
Lookups such as `command -v`, source searches, filenames and printed examples do not
count as sends. Node recognition checks evaluated code, excluding comments and
string literals; it does not load script files or follow imports.

These remain bounded heuristics, not a full shell/JavaScript parser or universal
action classification. Unsupported shell syntax (including here-documents), aliases,
script files, other SDKs/clients, computed methods and dynamically constructed actions
can escape recognition. The spending rule is still a textual heuristic and can flag
quoted examples. They run on
registered Claude Code, Codex and Cursor shell hooks. No MCP, arbitrary browser, remote agent or remote approver enforcement is added. Installed hook coverage and
vendor enforcement limits still apply; see [agent protection](host-agent-protection.md).

Agent deletion, Git cleanup/reset and SQL drop/truncate commands do not require
destructive-action review. Legacy `destructive` settings are accepted for
compatibility but ignored. Delete-command heuristics apply only to human input.

## Review lifecycle

Existing security decisions run first. Only actions those rules allow can enter this
review gate; approvals never override existing blocks or warnings. A matched action
is denied immediately and appears in the inbox. The user opens **Review and approve
once**, reviews the exact escaped action arguments in a native window, and
authenticates as the Mac owner. Cancelling or failed authentication grants nothing.
Rejecting leaves the exact request denied. The agent must retry after approval;
BoxCop does not execute commands from this inbox.

Approval binds the reported integration, session, working directory, action arguments
and current policies. Vendor transport IDs are excluded because they change on retry.
Changed action arguments need a new review. A locked, atomic state update consumes
approval before returning allow. Concurrent retries can consume it at most once.
Failure after consumption may mean the action never executes; it never restores
approval automatically. A consumed request is not proof of action completion.

Pending and approved requests expire 15 minutes after creation, including time spent
reviewing. Changing policies expires outstanding requests. While BoxCop is open it watches
the inbox: the Approvals page refreshes itself, the sidebar and menu bar show the waiting
count, and each new request posts one macOS notification with sound. The notification
names only the agent and the matched rule, never the command, folder or agent text.
Clicking it opens Approvals. It is withdrawn once the request is resolved or expires.
Turning on a rule asks for notification permission if macOS has never asked. The page
warns when notifications are off. Hooks still hold actions while BoxCop is closed, but
nothing is announced until it is open again.

## Readable requests and local summaries

Each waiting request shows the agent and tool, the matched rule, a **Sandbox disabled**
flag when the agent asked to bypass its sandbox, the agent's own description of the
action (a claim, not verification), the decoded command, the working folder, and any
other tool arguments. **Exact request** expands the stored JSON. The native approval
window shows the same fields above the exact request.

When the local workflow model (Qwen3.5-4B) is already installed, BoxCop asks it for a
one- or two-sentence plain-English summary plus up to three concerns. Summaries are
labelled as model output and can be wrong. The command and the agent's text go to the
model as untrusted data. They run on-device through the bundled inference engine.
Requests never trigger the model download: without the model, the page explains how
to turn on Local AI workflow review. Summaries are stored in
`human-review/summaries.json`, beside the request rows rather than inside them, so
they never change what is approved or the review hash. Each request is summarized at
most once, and failures are cached as failed. Entries are removed with their request. Unavailable or busy state fails closed. The final
hook decision, including review holds, is recorded in the ordinary local decision
audit. Updated team reporting accepts the `human-review-required` policy identifier
and sends only the existing decision metadata; command contents and approval
requests remain local. The inbox separately retains review/consumption timestamps
and statuses.

State is stored under `~/Library/Application Support/BoxCop/human-review` with
private directory/file permissions. It retains full action arguments to enable exact
review, unlike the content-suppressed decision audit. Up to 100 active requests and
100 recent terminal records are retained, further bounded by storage size; older
terminal records are removed to make room. Full active storage denies new requests.
These files are not encrypted. Keep secrets out of command arguments.

This is cooperative same-user enforcement. A process with access to the user's
files can modify policies/state or bypass registered hooks. Mac authentication on
the approval path does not provide tamper resistance against such a process. Separate approver roles, host containment
and provider-specific purchase/email integrations remain future work.

## Validation

`tests/test_human_review.py` covers disabled defaults, matching and thresholds,
exact-action binding, expiry, rejection, cancellation, concurrent consumption and
review invalidation. `tests/test_communication_commands.py` covers lookup/search
false positives and outbound CLI/inline Gmail SDK recognition. A real Python hook
subprocess guards a harmless local effect for both mail and Node command shapes:
no file before approval, one write after approval, and no duplicate on replay.
The test reviewer is synthetic; this does not establish native UI/authentication or
live vendor acceptance. Build the Swift app to check the native integration.

## Team configuration

In the web console, open **Policies → Team app settings → Human review policies**.
Choose **Team enforces**, select the rules and enter a USD spending threshold,
then **Save team settings**. Choose **Member chooses** to release the override.
The team configuration replaces personal review settings, including rules
turned off by the admin. Personal preferences remain saved underneath it.

The existing authenticated `/v1/admin/managed-policy` endpoint accepts an optional
`review` object with the same strict fields as local policies. Updates require the
current revision; competing writes return 409. Browser writes require the existing
session, Origin and CSRF checks. Device and read-only tokens cannot change policy.
Organization identity comes from authentication, never request fields.

Account-backed Macs receive the configuration through `/v1/device/policy` on their
existing one-minute sync while BoxCop is open. Hooks read the private cached policy
without network calls, even while the app is closed. Cached rules survive offline
operation and revocation; explicit leave restores personal settings. The Approvals
page identifies the managing team and disables local policy editing; its service
also rejects local configuration changes. A changed team revision invalidates
outstanding approvals, including changes received during authentication.

Migration 004 stores review configuration in a separate organization-scoped table.
Deploy the service before distributing an updated app. Older apps reject the new
policy shape when review rules are configured and need an update. Saving a policy
is not delivery/enforcement acknowledgement; the console does not claim receipt.
This adds central rule configuration, not remote approvals, MDM enforcement or
resistance to same-user state modification. Legacy accountless reporter enrollment
does not adopt team rules.
