# Daily security feed review

This workflow keeps the [machine health](software-exposure.md) advisories current.
Run it manually from your local checkout:

```sh
# One-time prerequisites: Python 3.12+, curl, Git, gh, and the Codex CLI.
# Sign in with `gh auth login` and `codex login` if not already authenticated.

# Daily: fetch, review, test, push a new branch and open a draft PR.
./update_from_feed.sh
```

The root-level launcher creates `.venv` using `python3` if needed, then runs
`.venv/bin/python -m pip install -r requirements.txt` before each full review.
Already installed requirements are reused. Installation failures stop the run
before fetching feeds or starting a review. This installs the full regression
suite dependencies, including `pytest`, without changing your system Python.
The launcher forwards all arguments and also works when invoked by absolute path
from another directory. `--fetch-only` and help skip dependency setup, using the
existing virtual environment or falling back to `python3`.

The review uses your configured Codex model/account and consumes its usage allowance.
It sends public feed content and relevant repository context to Codex. It does not
inventory your Mac. Codex runs with workspace-write sandboxing and network access
for primary-source verification; the Python wrapper performs Git publication.
The command can take several minutes. Follow its progress in the printed run
folder's `agent.log`. Run from a trusted checkout.

The inputs are [pwn.watch's JSON Feed](https://pwn.watch/feed.json) and
[Cloudflare Zero Wire RSS](https://radar.cloudflare.com/security/zero-wire/rss),
the machine-readable counterpart of the requested
[Zero Wire page](https://radar.cloudflare.com/security/zero-wire). On November 3,
2026, direct requests to the HTML page returned 403 while RSS worked. Both feeds
must download and parse successfully before review starts; a challenge, empty
feed, invalid schema, HTTP error or oversized response fails the run. There is no
silent fallback to yesterday's data.

```sh
# Fetch/validate only: no model call, branch, commit, push or PR.
./update_from_feed.sh --fetch-only

# Perform the model review and tests, but retain local changes without publishing.
./update_from_feed.sh --no-publish
```

Each run uses a new branch and isolated worktree based on freshly fetched
`origin/main`, under `.context/security-feed-review/`. Your current branch and
uncommitted work are preserved. Only one automated feed PR may be open at a time:
subsequent runs print that PR's URL and stop after fetching. Merge or close it
before the next review. A per-workspace lock prevents overlapping invocations;
do not launch simultaneous runs from different workspaces.

The model reviews every fetched entry against the current implementation, not
just new URLs. Content fingerprints catch revisions even when dates are unchanged.
The checked-in [review ledger](../research/security-feed-review.json) accounts for
each item as `covered`, `partial`, `gap`, `out_of_scope`, or `unresolved`, with a
specific explanation and evidence. Historical entries are retained when they roll
off a feed. This is not a complete historical CVE corpus: pwn.watch currently
returns its latest 50 entries. Cross-feed reports are assessed individually so
neither source's context disappears.

The ledger was ported with the code. It is a conservative implementation triage,
not primary-source verification of every incident. As of the November 4, 2026
review it held 74 entries: 47 partial, 23 out of scope, 3 gaps and 1 unresolved.
No row claims universal prevention, and removing a gap row does not remove the
documented enforcement and verification limits.

For a supported new check, the reviewer must verify primary sources, implement
both matching and discovery where necessary, and test affected, fixed, unknown
and benign cases. Large engineering gaps and unavailable sources remain explicit.
No news URL is automatically made a blocked domain; no feed prompt or exploit is
executed. Tests distinguish inventory advice from prevention at an actual boundary.
The wrapper validates ledger completeness and fingerprints, requires repository
evidence for coverage claims, reruns its fixed Python regression suite and changed Python test files, runs Swift
tests for native changes, and checks the diff before committing. It cannot prove
that a model's reasoning or cited evidence is correct: inspect the draft PR.

If tests fail, the model exits unsuccessfully, or validation fails, nothing is
pushed. The worktree, downloads and log remain for diagnosis. If pushing succeeds
but PR creation fails, the branch remains on origin; use `gh pr create --draft
--base main --head <printed-branch> --body-file <worktree>/.context/security-feed-review/pr-body.md`
to finish publication. `--no-publish` worktrees can be reviewed and published
manually in the same way after committing their changes. No automatic merges,
app builds, installation, signing or deployment occur.

Clean up retained worktrees with `git worktree remove <path>` after inspecting
and saving any uncommitted changes, then remove their enclosing run directories.
Raw feed downloads and model logs stay gitignored under `.context/`.

The CLI invocation follows the installed CLI's help and OpenAI's
[non-interactive mode documentation](https://learn.chatgpt.com/docs/non-interactive-mode).
