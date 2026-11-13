# Data formats

BoxCop has two processes that exchange data: the Swift app and the Python engine
(`boxcop-engine`). This page describes the protocol between them, the security
event format the app shows, and the files BoxCop writes.

## The engine's command-line modes

| Mode | Purpose |
| --- | --- |
| `--data-dir DIR` | The pipe service the app keeps running. See the next section. |
| `--self-test` | Offline check of the frozen engine. Prints one line of JSON and exits 0 on success. |
| `--protection-status --data-dir DIR` | One-shot state of package and script routing. |
| `--host-agent-hook claude\|codex\|cursor` | Evaluates one agent action from standard input and prints the agent's allow or deny response. |
| `--host-agent-integrations auto\|install\|status\|remove` | Manages BoxCop's entries in agent settings. |
| `--package-setup status\|disable` | Reports or removes package routing without the app. |
| `--software-inventory [--cache] [--root PATH]` | Scans installed software and prints the inventory. |
| `--software-remediation prepare\|apply` | Prepares or applies a guided update. |
| `--contain [--allow-host HOST[:PORT]]... -- COMMAND` | Runs one command contained. |

`--self-test` output:

```json
{"ok": true, "schema": "boxcop.self-test.v1", "engine": "rules", "protocol": 1,
 "checks": {"rules": true, "package_feed": true, "registry_firewall": true,
            "containment": true, "inventory": true, "triage": true}}
```

It touches no user data, opens no network connection and loads no model. The
build runs it against the frozen engine before and after signing.

`--protection-status` output:

```json
{"schema": "boxcop.protection-status.v1",
 "package": {"configured": false, "routed": false, "listening": false},
 "scripts": {"routed": false, "listening": false}}
```

`configured` means the build carries a malware feed channel. `routed` means the
user's `~/.npmrc` points at BoxCop. `listening` means the local listener is
answering, which is only true while the app's engine is running.

## The pipe protocol

The app starts `boxcop-engine --data-dir <dir>` and exchanges newline-delimited
JSON over standard input and output. There is no HTTP server on this path.

Request: `{"version": 1, "id": "<1-64 chars of A-Z a-z 0-9 _ ->", "op": "<operation>", ...}`

Response: `{"version": 1, "id": "<same id>", "ok": true, "result": {...}}`, or
`{"version": 1, "id": ..., "ok": false, "error": {"code": ..., "message": ...}}`.

| Operation | Extra fields | Result |
| --- | --- | --- |
| `status` | none | `ready`, `protocol`, `engine`, `network_listener`, and `package_registry_listener` / `install_script_listener` when those listeners are up |
| `security_events` | `limit` (1 to 200) | `events`: a list, newest first |
| `package_protection` | `action`: `status`, `enable`, `disable`, `allow`, `revoke`. For `allow` and `revoke`: `ecosystem` (`npm` or `PyPI`), `package`, `version` | `packageProtection`, which always includes `exceptions` |
| `script_protection` | `action`: `status`, `enable`, `disable`, `allow`, `revoke`; `package`; `host` | `scriptProtection` |
| `workflow_context` | `context` | `workflow`: counts and signals for [smart triage](workflow-context.md) |
| `workflow_clear` | optional `remove_model`: `true` | `workflowCleared`. With `remove_model`, the downloaded model files are deleted, only while the model runtime is stopped, and the result reports the bytes freed. |
| `shutdown` | none | `stopped`; the engine then exits |

Rules:

- Each line is at most 262,144 bytes including the newline, in both directions.
  A longer request ends the session.
- A request must have exactly the fields of its operation. Unknown operations,
  extra fields, duplicate keys and non-finite numbers are rejected with
  `invalid_request`.
- Error messages are fixed text. They never include request content or internal
  error details.

`package_protection` with `allow` adds an exception for one exact release that the
feed reports as malware but has not confirmed; `revoke` removes it. Both take `ecosystem` (`npm` or `PyPI`), `package` and `package_version`; the release version cannot be called `version` because every request already uses that key for the protocol version. Confirmed
malware and the test package are refused. The firewall checks the tier again on
every request, so an exception stops working if the feed later confirms the
release. Every `package_protection` reply lists
the current exceptions:

```json
"exceptions": [{"ecosystem": "npm", "package": "some-pkg", "version": "1.2.3",
                "added": "2026-11-12T20:15:03Z"}]
```

Example:

```json
{"version":1,"id":"a","op":"status"}
{"version":1,"id":"a","ok":true,"result":{"ready":true,"protocol":1,"engine":"rules","monitoring":false,"network_listener":false}}
```

## Security events

`security_events` returns one list of what the engine's layers blocked.
The app merges it with network extension events and software findings, which it
reads from their own sources, to build the Events list.

```json
{"id": "stable string",
 "time": "2026-11-12T20:15:03Z",
 "layer": "install_gate",
 "outcome": "blocked",
 "title": "Blocked install of evil-pkg 1.2.3",
 "reason": "This release is listed as malicious by datadog.",
 "subject": "evil-pkg@1.2.3",
 "agent": null,
 "command": null,
 "package": "evil-pkg",
 "host": null,
 "ecosystem": "npm",
 "version": "1.2.3",
 "allowable": false,
 "policy_ids": ["known-malicious-package"]}
```

| Field | Values |
| --- | --- |
| `layer` | `install_gate`, `containment`, `agent_actions` |
| `outcome` | `blocked`, `warned` |
| `title` | A short plain sentence |
| `reason` | One or two plain sentences saying why |
| `subject` | `package@version`, a host, a path, or a short command summary |
| `agent` | `claude`, `codex`, `cursor` or null |
| `command` | A redacted command line, or null |
| `package`, `host` | A name, or null |
| `ecosystem` | `npm`, `PyPI` or null. Set on install gate events. |
| `version` | The exact version that was refused, or null |
| `allowable` | `true` only for a block of an exact version in the reported tier that is not already allowed. The app shows **Allow this release** for these. |
| `policy_ids` | The rules that matched |

Events never contain secrets or file content. The sources are:

| Source | Layer | Stored in |
| --- | --- | --- |
| Agent hook denials | `agent_actions`, or `install_gate` for skill files and known-malicious packages | the audit database |
| Registry firewall blocks | `install_gate` | `package-protection/blocks.json` |
| Refused connections from contained scripts and runs | `containment` | `script-protection/blocked-connections.json` |

## Files

Everything the engine and app write is under
`~/Library/Application Support/BoxCop/`. The directory is mode 0700 and files
are 0600. The engine refuses to start with a data directory that is not private
and owned by the user.

| Path | Contents | Holds command text or content? |
| --- | --- | --- |
| `events.sqlite3` | Decision audit: one row per evaluated agent action with the agent, action kind, hashed session, working directory, matched policies and decision | No. Content is stored as `[not retained]`. |
| `<agent>-receipt.json`, `<agent>-<action>-receipt.json` | Last hook callback per agent and per action | No |
| `agent-integrations.json`, `*.config-backup` | What BoxCop added to agent settings, and exact backups of the settings it edited | The backups are copies of your agent settings |
| `package-protection/` | The verified malware list (`policy.json`), keys for local artifact links, `blocks.json`, the releases you have allowed (`exceptions.json`, at most 200) | Package names and versions |
| `script-protection/` | The script wrapper, `exceptions.json`, `blocked-connections.json`, the `~/.npmrc` change receipt | Package names and hostnames |
| `software-inventory.json` | Latest inventory, schema `boxcop.software-inventory.v2` | Software names, versions and paths |
| `software-remediation-results.json`, `software-console/` | Outcomes and console output of guided updates | Package manager output, with URL credentials redacted |
| `models/workflow/` | The local model | No |
| `workflows/` | The app's activity journal, encrypted | Event details; see [journal-encryption.md](journal-encryption.md) |

The network extension runs as root and keeps its history separately, encrypted,
under `/Library/Application Support/BoxCopNetwork.noindex/`; see
[outgoing-connections.md](outgoing-connections.md). The app talks to it over the
Unix socket `/var/run/local.boxcop.network.sock`.

Blocked-event logs (`blocks.json`, `blocked-connections.json`) are bounded to the
newest 200 entries. A repeat of the same block raises a counter instead of adding
an entry. Logging is best effort: a failed log write never changes a block
decision.

## Schemas named in the code

| Schema | Where |
| --- | --- |
| `boxcop.self-test.v1` | `server/self_test.py` |
| `boxcop.protection-status.v1` | `server/self_test.py`, `BoxCopCore/ProtectionStatus.swift` |
| `boxcop.status.v1` | `BoxCop --status --json`, `BoxCopCore/ProtectionStatus.swift` |
| `boxcop.software-inventory.v2` | `server/software_inventory.py` |
| `boxcop.workflow-context.v1` | `server/workflow_context.py`, `BoxCopCore/WorkflowContext.swift` |
| `boxcop.package-channel.v1` | `server/package_channel.py`: the feed URL and key pinned in a build |
| `boxcop.package-policy.v1` | `server/package_intelligence.py`: the signed malware list. Publisher and client use the BoxCop wire format. |
| `boxcop.encrypted.v1` | `BoxCopCore/JournalEncryption.swift`: one encrypted journal record |
