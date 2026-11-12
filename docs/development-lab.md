# Development

How to work on BoxCop from a checkout. For building the app see
[releasing.md](releasing.md); for the Swift package see
[desktop/macos/README.md](../desktop/macos/README.md).

## Setup

You need a Mac running macOS 14 or later, Xcode Command Line Tools and
Python 3.12. CMake is needed only to build the app bundle.

```sh
python3.12 -m venv .venv
.venv/bin/python -m pip install -r requirements.txt
```

`requirements.txt` is compiled from `requirements.in` with
`uv pip compile --python-version 3.12 requirements.in -o requirements.txt`.

## Tests

```sh
.venv/bin/python -m pytest -q tests          # the engine and the build pipeline
swift test --package-path desktop/macos      # the app core and the network filter
```

The Python tests use temporary directories and never touch
`~/Library/Application Support/BoxCop`, your `~/.npmrc` or your agent settings.
Tests that need npm, pnpm, uv or the macOS sandbox skip themselves when the tool
is missing. They also run on Linux, where the macOS-only ones skip.

CI runs both suites on every pull request and push to `main`, then builds a
limited-development app and runs the first-launch smoke test; see
`.github/workflows/ci.yml`.

## Running the engine from source

The engine is the Python package in `server/`. The app talks to it over a pipe,
and each one-shot job is a command-line mode. `desktop/macos/scripts/engine_entry.py`
runs it from the checkout exactly as the frozen `boxcop-engine` runs in the app.

```sh
engine() { .venv/bin/python -I -B desktop/macos/scripts/engine_entry.py "$@"; }

engine --self-test                                   # offline check; one JSON line
engine --protection-status --data-dir /tmp/boxcop-dev-data
engine --software-inventory --root /Applications     # read-only scan, JSON
engine --contain --allow-host example.com -- curl -sS https://example.com
```

The pipe service reads one JSON request per line on standard input and writes
one response per line:

```sh
printf '%s\n' \
  '{"version":1,"id":"a","op":"status"}' \
  '{"version":1,"id":"b","op":"security_events","limit":20}' \
  '{"version":1,"id":"c","op":"shutdown"}' \
  | engine --data-dir /tmp/boxcop-dev-data
```

Use a scratch `--data-dir` for experiments. The engine creates it with mode 0700
and refuses a directory that other users can read. The protocol and the files it
writes are described in [data-format.md](data-format.md).

Some modes act on your real home directory: `--host-agent-integrations install`
edits agent settings, and the `package_protection` and `script_protection`
operations edit `~/.npmrc`. Run those in the [lab VM](vm-lab.md), not on your own
Mac.

## Command-line tools

```sh
.venv/bin/python tools/skill_scan.py /path/to/downloaded/skill    # check a skill before use
.venv/bin/python tools/supply_inventory.py --root /path/to/project  # inventory one folder
.venv/bin/python -m tools.package_feed --help                     # build a signed malware feed
./update_from_feed.sh --fetch-only                                # fetch the security feeds
```

See [skill-security.md](skill-security.md), [software-exposure.md](software-exposure.md),
[package-registry-firewall.md](package-registry-firewall.md) and
[security-feed-review.md](security-feed-review.md).

## Rules for changes

- **A layer is "On" only while it enforces.** If a change can leave a layer
  routed but not answering, the state must say so.
- **The model may tighten, never loosen.** No model output may approve, unblock
  or change a policy. See [workflow-judgment.md](workflow-judgment.md).
- **Do not store what you do not need.** The decision audit holds no command
  text or file content. New logs hold names and hostnames, not payloads.
- **Fail closed where a person asked for protection.** A stopped proxy makes
  routed installs fail. It does not redirect around the check.
- **Ported protections.** Before designing a protection, check how the reference
  tools solve it, and follow the porting rule in [layers.md](layers.md).
- **Test on the VM** anything that changes system state.

## Layout

| Path | Contents |
| --- | --- |
| `server/` | The engine |
| `tools/` | Command-line tools that use the engine's modules |
| `scripts/security_feed_review.py`, `update_from_feed.sh` | The security feed review |
| `tests/` | Python tests |
| `desktop/macos/Sources/` | Swift targets `BoxCopCore`, `BoxCop`, `BoxCopNetworkFilter`, `BoxCopProbe` |
| `desktop/macos/scripts/` | Build, signing, release and lab scripts |
| `desktop/macos/Resources/` | `Info.plist`, icon, DMG artwork, the bundled threat list |
| `docs/` | Documentation |
