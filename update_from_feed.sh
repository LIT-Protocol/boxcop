#!/bin/bash
# Run the daily feed review from any working directory.
set -euo pipefail

repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
cd "$repo_root"

if [[ -x "$repo_root/.venv/bin/python" ]]; then
  python_bin="$repo_root/.venv/bin/python"
elif command -v python3 >/dev/null 2>&1; then
  python_bin="$(command -v python3)"
else
  echo 'Python 3.12+ is required. See docs/security-feed-review.md for setup.' >&2
  exit 1
fi

# Fetch-only and help use only the standard library.
needs_dependencies=true
for arg in "$@"; do
  case "$arg" in
    --fetch-only|--help|-h) needs_dependencies=false ;;
  esac
done

if "$needs_dependencies"; then
  if [[ ! -x "$repo_root/.venv/bin/python" ]]; then
    echo 'Creating .venv for the security feed review...'
    "$python_bin" -m venv "$repo_root/.venv"
  fi
  python_bin="$repo_root/.venv/bin/python"
  echo 'Ensuring security feed review dependencies are installed...'
  "$python_bin" -m pip install -r "$repo_root/requirements.txt"
fi

exec "$python_bin" "$repo_root/scripts/security_feed_review.py" "$@"
