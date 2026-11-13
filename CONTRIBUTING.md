# Contributing to BoxCop

Contributions are welcome. Start with the [README](README.md) for development
setup and the [roadmap](docs/roadmap.md) for priorities.

## Issues and proposals

For bugs, include your macOS version, build profile, enabled protections, steps to
reproduce, and expected versus actual behavior. Remove credentials, personal
paths, and sensitive event data from logs. Discuss substantial features in an
issue before implementation.

## Pull requests

Keep changes focused and describe the problem, resulting behavior, and validation.
Update documentation when behavior or protection coverage changes. Add regression
coverage for fixes and meaningful tests for new enforcement behavior. Use inert
fixtures rather than live malware.

Run the relevant Python tests with `.venv/bin/python -m pytest -q tests` and Swift
tests with `swift test --package-path desktop/macos`. Note any checks you could
not run. Test system-changing features in a dedicated macOS VM; see
[the VM guide](docs/vm-lab.md).

Security claims must match tested coverage. Model output must never loosen policy
or bypass a deterministic block. Preserve third-party licenses and attribution;
do not copy code with incompatible licensing.

Do not include signing keys, provisioning credentials, tokens, or private logs in
commits. Contributions are provided under the repository's Apache-2.0 license.
