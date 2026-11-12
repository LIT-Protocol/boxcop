# Install gate: skill and instruction file checks

Skills and agent instruction files are things an agent "installs" into its own
behaviour. BoxCop checks them offline with original checks informed by the threat
categories in [NVIDIA SkillSpector](https://github.com/NVIDIA/SkillSpector). It
does not install, invoke or vendor SkillSpector, and does not claim its coverage.

Four default-enabled policies hold agent file reads/writes whose supplied content
matches instruction overrides, concealed actions, credential-store exfiltration,
or fetch/decode-to-execution and download-then-execute patterns. A hold appears
in the app's Events list and in the decision audit. Reasons are fixed text; scanned
content is not retained in the audit.

## Where the checks run

- Cursor's registered file-read hooks inspect the content supplied by the harness.
- Claude's registered Read hook reads a bounded snapshot for `SKILL.md`, `AGENTS.md`,
  `CLAUDE.md`, and files beneath a `skills` or `.skills` directory. Unsupported,
  unreadable or oversized files on this route deny the action. The full file is
  checked even when the tool requests a line range. Other Claude reads remain
  path-only checks.
- Existing agent Write/Edit events inspect the supplied new content. An Edit is
  only a fragment, not a scan of the resulting file.

Registered hooks must actually be called for a hold to take effect. Skill loading
that bypasses hooks, shell-based file reads, Cursor attachment content, MCP tool
metadata and Codex's shell-only integration are not covered by these file checks.
This is cooperative preflight, not filesystem authorization or a universal install
gate. A file may change after inspection. Automatic skill loading at agent startup
is not guaranteed to trigger a Read hook.

## Scan a downloaded skill before use

From the repository root:

```sh
.venv/bin/python tools/skill_scan.py /path/to/downloaded/skill
```

The explicit local-root CLI scans all regular UTF-8 files in the bundle, including
supporting scripts, without importing code, running commands, installing packages,
or making network calls. Download/extract archives separately. Exit codes:

- `0`: complete scan with no matching pattern; this does not establish safety.
- `1`: findings require review.
- `2`: incomplete scan, including when findings were also discovered.

JSON includes policy IDs and fixed explanations. It omits file names and excerpts;
`entry` is an ordinal within that traversal, not a stable file identity. To isolate
a finding, scan individual files. Directory traversal is bounded to 256 entries,
20,000 bytes per file and 1 MiB total scanned bytes. Symlinks, special files, binary
or invalid UTF-8 files, missing paths and exceeded bounds make the scan incomplete.
Scan a stable local copy: this is not race-free traversal of an actively hostile
filesystem. Do not use a no-match report as authorization to execute a bundle.

## Coverage limits

Patterns are deliberately narrow and can miss paraphrases, encodings, dynamic
behavior and payloads split across files. Quoted examples and negated instructions
can produce false positives. There is no semantic model, AST/taint analysis,
recursive archive extraction, dependency resolution, CVE lookup, MCP permission
analysis or automatic quarantine. The command checks described in
[agent action checks](host-agent-protection.md) operate independently. Review the source of a finding before changing
policy settings; disabling a policy affects all events using that policy.

Tests use synthetic content and actual local hook subprocesses. They do not
qualify vendor integration behavior or a packaged macOS release.
