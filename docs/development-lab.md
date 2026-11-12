# Development lab and technical reference

Run commands below from the repository root. This developer lab is separate from the installed macOS product. For product direction and current protection boundaries, see the [project README](../README.md).

## Play with the installed lab

From the repository root, once the setup below has been done:

```sh
env -u PYTHONPATH -u PYTHONHOME .venv/bin/python -m server
```

Open **http://127.0.0.1:8791/** in a browser running as the same OS user. Keep that terminal running; Ctrl-C stops the service. The production console is served by the backend, not a separate Vite server. **`python -m server` is the only supported launcher**; it fixes the bind address and disables proxy-header trust. Do not substitute a generic Uvicorn command or put a reverse proxy in front of it.

If using a different computer, forward the port through **your own SSH account on this host** (not another user's reverse proxy):

```sh
ssh -N -L 127.0.0.1:8791:127.0.0.1:8791 chris@dedicated-m64-hope
```

Then open http://127.0.0.1:8791/ on your computer. Substitute your configured SSH hostname if needed. **Use forwarding only from a trusted, single-user computer.** Anyone able to connect to its forwarded port reaches the backend through your server-side SSH process and can obtain a dashboard cookie; the backend cannot distinguish those client users. Binding the forwarding listener to loopback does not make it private to your OS account. No public tunnel or remote deployment is configured. An SSH connection must already work; this project does not provision accounts, credentials, TLS, or DNS.

### Five-minute tour

1. **Playground → Engineer interpreter**: the harmless command is allowed **as an evaluation**, not executed.
2. Run **Same command, HR role**: the same text produces a warning because the declared role differs. Role is caller-supplied context, not verified identity.
3. Run **Credential to public AI**, **Patient record to AI**, **Remote script pipeline**, and **Agent credential upload**: examine the blocking rules and evidence.
4. Run **HR-system copy to AI paste**, then **Same text, no sensitive copy**: the identical, innocuous-looking text is blocked only when it was copied from a declared HR system earlier in the same session. Open the blocked paste to see the linked copy ID. Correlation is exact-content, bounded to five minutes in memory, and resets on restart; the source system is caller-declared, not verified.
5. **Evaluate an event**: compare `python3 -c 'print(1)'` as engineering and HR, with Action set to Command. Evaluation never runs the text or contacts its destination.
6. **Guarded paste workbench**: paste harmless text, then an obviously fake `api_key=FAKE_EXAMPLE_VALUE_123456`. Only an allow is inserted. Warnings, blocks, service errors, and stale focus/selection keep it out.
7. **Analyze locally**: run the optional MiniLM encoder on a paragraph. These are real CPU embeddings, but nearest-example similarity is advisory—not a probability or permission decision.
8. **Overview**: filter decisions and inspect reasons/labels/context. **Policies**: a confirmed toggle changes the real evaluator and persists. Re-enable policies after experiments. **Coverage** states what is and is not instrumented.

Scenario labels are synthetic, not discovered attacks. Audit rows from browser/CLI tests are explicitly submitted live/manual events, not passive monitoring.

## Skill security

[Offline skill scanning and agent file-hook checks](../docs/skill-security.md) add
SkillSpector-inspired checks for instruction overrides, concealed actions,
credential exfiltration and remote execution. Scan a downloaded skill with
`python3 tools/skill_scan.py /path/to/skill`. Findings require review; a complete
scan with no matches does not establish safety.

## Opt-in CLI

```sh
# Default: preflight only, nothing executed.
python3 adapters/guard.py -- python3 -c 'print("hello")'

# Actual harmless execution only after a valid allow.
python3 adapters/guard.py --execute -- python3 -c 'print("hello")'

# Warning: refused, even with --execute.
python3 adapters/guard.py --execute --role hr -- python3 -c 'print("hello")'
```

Only supplied argv is run, using `shell=False`; the wrapper is voluntary and **not a sandbox**. An allowed interpreter/script can do things the text heuristics do not see. Do not rely on it to run untrusted commands. It does not inspect files, monitor children, restrict permissions, or prevent time-of-check/time-of-use changes.

The legacy lab browser extension matches **only the local fixture**. The native app’s separate browser-context extension collects HTTP(S) context after installation. Native test and manual installation instructions are in `adapters/README.md`. Nothing has been installed in your normal browser or shell.

## Fresh setup

Tested with Python 3.12 and Node 22. Dependencies are pinned. From the repository root:

```sh
uv venv .venv --python 3.12
uv pip sync --python .venv/bin/python requirements.txt
npm --prefix web ci --ignore-scripts
npm --prefix web run build

# Optional: download the pinned ~23 MB open model; setup verifies SHA256 hashes.
env -u PYTHONPATH -u PYTHONHOME .venv/bin/python scripts/setup_model.py

env -u PYTHONPATH -u PYTHONHOME .venv/bin/python -m server
```

Without the model, rules and the console still work; the semantic panel reports unavailable. Runtime inference does not call cloud services or download weights. The initial model status is `not_loaded` until the first analysis.

## Security and privacy boundary

- The supported launcher binds only `127.0.0.1:8791`; no public listener. Direct Linux production connections must use a socket owned by the server's OS UID. This trusts same-UID programs, SSH forwarders and root; it is not isolation from malware running as you. A proxy or tunnel can hide the original client's UID.
- Linux peer attribution uses `/proc/net/tcp` and fails closed on all read/parse errors, including missing proc data and resource exhaustion. `BOXCOP_SINGLE_USER_HOST=1` cannot disable Linux checks. On non-Linux hosts only, that explicit opt-in accepts the weaker single-user loopback boundary; never use it on shared hosts. Containers with different UIDs or network namespaces may be rejected.
- Requests carrying `Forwarded`, `X-Real-IP`, or any `X-Forwarded-*` header are refused before cookie bootstrap or API authentication. Reverse proxies are unsupported. The Vite development proxy still changes the connecting UID even without those headers: use it only on a trusted single-user host, never as production access control.
- Validated Host/Origin/Referer/fetch metadata, no broad CORS, JSON-only mutations, bounded bodies, no exec/fetch API. API access requires the same-origin HttpOnly/SameSite session or the private `.local/api-token`. Never paste the token into chat or the fixture.
- **Caller-submitted content is not persisted**, regardless of the synthetic flag. Labels, decisions, timestamps and pattern-sanitized metadata are retained in SQLite. Server-authored fixed demo scenarios alone may retain redacted previews. Do not put real secrets or private details in metadata: regex sanitization cannot recognize everything.
- Full raw and sanitized/whitespace-normalized copies of content are suppressed from metadata as defense in depth. Fragments, encodings and arbitrary private metadata are not guaranteed to be removed. Upgrading a version-0 or version-1 database discards historical free-text metadata and previews rather than attempting to repair lossy old redaction; event IDs, timestamps, labels, decisions and policy settings remain. This does not erase old backups or storage-device remnants.
- Session/content correlation hashes and their random key live only in bounded memory; no durable content fingerprints. The five-minute matching window uses a monotonic clock, not the audit wall clock. Expired entries are purged on the next evaluation, not by a background eraser. Restarting clears lineage, but leaves decisions and policy settings intact.
- There is no age-based audit deletion in this prototype; manage `.local/` retention yourself. It is ignored by Git, mode 0700, with private files. Backups, snapshots, process memory and browser input fields are outside the database-content guarantee.
- Default hard rules are narrow heuristics. Remote execution, credential exfiltration, and medical/personnel patterns have both false positives and evasion routes. `allow` means no enabled rule matched—not “safe.” Model results cannot weaken rules.
- Performance is not hardened for hostile inputs. An exploratory long-input sanitizer comparison timed out during review and has not been diagnosed; passing the bounded functional tests is not load/DoS assurance. Keep this a trusted local lab.
- The **lab server and fixture adapters** do not perform OS monitoring, screenshot capture, keyboard hooks, global clipboard listening, process killing, kernel drivers, external telemetry, paid model calls, or automatic policy generation. The separate native macOS implementation has explicit opt-in app/clipboard observation and shortcut filtering; its coverage and native runtime limitations are documented in `desktop/macos/README.md`.
- The cooperative paste guard is not a hostile-page security boundary. Earlier page handlers can see a paste; typing, uploads, network APIs and other actions are not universally mediated.

## Tests and evidence

```sh
env -u PYTHONPATH -u PYTHONHOME PYTHONDONTWRITEBYTECODE=1 \
  .venv/bin/python -m pytest -p no:cacheprovider tests/ -q
node --test tests/extension/*.test.cjs
npm --prefix web test
npm --prefix web run build

# Actual backend must be running for these:
node tests/browser-console.mjs
# Native extension also needs the fixture server:
python3 -m http.server 8792 --bind 127.0.0.1 --directory adapters/fixture
# In another terminal:
node tests/extension-native.mjs
```

Browser acceptance uses the project's Playwright Chromium in a disposable profile. If absent, install explicitly with `cd web && npx playwright install chromium`. These tests add labeled audit rows and manipulate only fake data. Browser policy tests restore toggles; the backend must be a test lab, not an operational deployment.

Evidence locations:
- `artifacts/`: test/review reports and native-extension evidence.
- `web/artifacts/browser/`: actual-console screenshots and JSON acceptance report (Git-ignored).
- `research/ent-architecture.md`: primary-source research, known unknowns, and scope differences.
- `research/source-manifest.json`: cached-source provenance and hashes; raw vendor pages are Git-ignored.
- `research/model-evaluation.md`: real inference benchmark, pinned model provenance, and all four errors in the twelve-example illustrative evaluation. It is not a detection-accuracy study.

## Layout

- `desktop/macos/`: native menu-bar app implementation, portable Swift core, standalone-engine packaging and native acceptance checklist.
- `server/`: FastAPI boundary, policies, SQLite, in-memory correlation, offline embedding inference; separate no-network desktop IPC entry point.
- `web/`: original React/TypeScript console.
- `adapters/`: CLI preflight, local-only MV3 extension, cooperative fixture.
- `tests/`: unit, HTTP, subprocess, browser and extension acceptance.
- `.local/`: local token, audit DB and downloaded model; not source-controlled.

The native macOS work addresses the installed endpoint product boundary rather than just broadening the lab regexes. VM permission/intervention tests exist, but supported release acceptance remains outstanding; shortcut filtering is not a secure execution sandbox or universal paste mediation.

Live Terminal testing now passes 30 input checks, including substituted browser
copy text, invisible command controls, credential-file reads and destructive
commands. All text goes to an inert receiver; commands are never executed.
Typed and menu routes remain uncovered.

Expanded protected-presentation testing found a medical-record gap: a fictional
named patient record was readable by OCR but released to the owned output.
The generic health-article control remained visible. Medical-record sharing
protection is not qualified; see the live VM campaign for this failure.

Real Zoom meeting-chat testing also passes seven checks: a fake credential stays
out on first paste and retry, while an ordinary agenda link reaches the isolated
receiver. This covers native Command-V text paste; attachments and final-send
mediation remain unqualified. The non-ES campaign has 33 scenarios with scoped
live evidence, two live failures and 85 documented missing-control blockers.
