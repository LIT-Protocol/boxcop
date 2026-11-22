# Agent action checks

BoxCop registers **pre-action hooks** in the user configuration of Claude Code,
Codex and Cursor. Before the agent runs a shell command or, where the agent
supports it, reads or writes a file, the hook asks BoxCop whether to allow it.
You launch agents as usual. There is no wrapper, API server, token or model on
this path.

The hooks are cooperative. They add a check to ordinary agent sessions. They do
not sandbox the agent, authenticate its identity or contain what an allowed
command does. See [Limits](#limits).

## What is registered

| Agent | User configuration | Intercepted actions |
| --- | --- | --- |
| Claude Code | `~/.claude/settings.json` | `PreToolUse` for `Bash`, `Read`, `Write`, `Edit` |
| Codex | `~/.codex/hooks.json` | `PreToolUse` for `Bash` (its name for shell tools) |
| Cursor | `~/.cursor/hooks.json` | `beforeShellExecution`, `beforeReadFile`, `beforeTabFileRead` |

Each entry runs `/Applications/BoxCop.app/Contents/MacOS/BoxCop --host-agent-hook
<agent>`. The native executable passes the request to the engine in the same
bundle and does not open the app's window. Hooks work while the app's window is
closed, as long as the app stays installed at that path.

The installer:

- keeps other hooks and settings, and makes a private exact backup first;
- refuses malformed, duplicate-key or symlinked configuration files;
- remembers only its own entries, for updates and removal;
- never changes an agent's permission settings or hook trust database;
- respects `disableAllHooks` in Claude Code and Codex. Cursor's setting of the
  same name is reported as unverified, because the Cursor CLI we tested kept
  calling hooks with it set.

It only finds agents whose configuration directory exists. After installing a new
agent, open it once and then install hooks again.

**Codex needs one manual step.** Codex skips hooks it has not been told to trust.
Open `/hooks` in Codex, select `PreToolUse`, review the BoxCop command and trust
it, then start a new session. BoxCop does not bypass this.

```sh
BOXCOP=/Applications/BoxCop.app/Contents/MacOS/BoxCop
$BOXCOP --host-agent-integrations status    # read-only
$BOXCOP --host-agent-integrations install   # add or repair BoxCop's entries
$BOXCOP --host-agent-integrations remove    # remove them and stop automatic registration
```

## What is denied

The decision is deterministic. An action is allowed or denied. There is no
warn-and-continue, and nothing waits for a person to decide. A denial gives the
agent a fixed reason, a reference to the audit record and an instruction to
revise the action.

- **Shell commands** (all three agents): recognizable credential access,
  exfiltration, fetch-to-shell and other dangerous command shapes, including
  through common wrappers, pipelines and `sh -c` bodies. Existing path arguments
  are checked for symlinks into credential stores.
- **File reads and writes** (Claude Code `Read`, `Write`, `Edit`; Cursor Agent and
  Tab reads): conventional credential paths such as `.env`, `~/.aws/credentials`
  and SSH private keys. `.env.example` and public keys are allowed. Paths are
  resolved through existing symlinks. Content supplied in the hook call is checked
  for secrets.
- **Skill and instruction files**: see [skill-security.md](skill-security.md).
- **Known-malicious packages** named in an install command, using the same signed
  list as the [registry firewall](package-registry-firewall.md).

## Health

A registered hook is not proof that it runs. The app and `--host-agent-integrations
status` keep these apart:

- **Registered**: every expected entry is present with the right matcher and
  failure options. A partial or edited registration does not count.
- **Called**: the last time each action's hook reached the engine, per agent and
  per action. A shell callback says nothing about file hooks.
- **Stale**: a callback older than 24 hours, or one that predates an edit to the
  agent's configuration, needs fresh evidence.
- **Error**: the last callback could not be evaluated and was denied.

Receipts are small files in BoxCop's data folder. Each holds a fixed action name,
a timestamp, the decision, hashed session and audit identifiers and the elapsed
time. They hold no command text or file content. They are diagnostics written by
the same user, not tamper-proof records.

## Timing and failures

- The engine has a three-second deadline per callback. The native launcher waits
  at most 3.5 seconds and denies if the engine is missing, crashes, hangs or
  answers with something malformed.
- Database lock waits are limited to one second to tolerate brief contention
  between callbacks. The overall three-second callback deadline still applies.
  A parse or audit failure is a denial.
- Hook entries ask for a five-second timeout. Cursor entries also set
  `failClosed: true`. Whether an agent honors these is up to the agent.
- If the app has been deleted, or the operating system cannot start the hook at
  all, the agent decides what happens, and some agents continue.

## What is recorded

Each decision goes to the private audit database
`~/Library/Application Support/BoxCop/events.sqlite3` with the agent name, the
kind of action, a hashed session identifier, the reported working directory and
the policies that matched. For denied shell commands, the hook saves a local review copy with recognizable
credentials and URL parameters removed. Commands flagged for sensitive content
are withheld. Select the event and expand Command to inspect it. For a fully
visible command flagged only for download and execution, **Allow one retry**
permits the same command, agent session and directory for five minutes. Start
the retry in the agent. Approving does not execute the command.
The session, working directory and parent process are what the agent reported;
they are not verified.

## Limits

- **Cooperative.** The agent must call the hook. A user or a process running as
  the user can remove hooks or change settings.
- **Text rules.** Command rules read the command line. They do not read the
  scripts a command runs or follow what a program does. Aliases, indirect
  execution and commands that hide their intent can evade them.
- **Partial tool coverage.** Codex is shell-only. Cursor attachment bytes are not
  supplied to hooks. MCP tool calls, remote or cloud agents and background agent
  operations are not covered.
- **No desktop agent apps.** Claude Cowork and the ChatGPT and Codex desktop apps
  are not covered.
- **Time of check.** A file can change after it was inspected.
- **No prompt-injection detection.** The hooks judge the action, not the content
  that led the agent to it.
- **Version-specific.** Agent hook contracts change. Re-check after an agent
  update. The contracts are documented by
  [Claude Code](https://code.claude.com/docs/en/hooks),
  [Codex](https://learn.chatgpt.com/docs/hooks) and
  [Cursor](https://cursor.com/docs/hooks).

## Validation

```sh
python -m pytest -q tests/test_host_agents.py tests/test_host_agent_health.py \
  tests/test_host_agent_verification.py tests/test_broader_hooks.py \
  tests/test_beta_interventions.py tests/test_incident_gaps.py
```

These run the real hook entry point as a subprocess with synthetic agent payloads
and isolated configuration and data directories. They check allow and deny
responses, installation and removal, per-action health, stale and corrupt
receipts, and failure handling. They do not run a real agent. Whether a given
agent version loads the hook and honors a denial is checked with that agent
signed in on the [lab VM](vm-lab.md).
