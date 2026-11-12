#!/usr/bin/env bash
# CI-only launch smoke for a freshly built BoxCop.app on a macOS CI runner.
#
# Proves only that the packaged bundle launches through LaunchServices, stays up on the
# first-run setup screen, and starts no engine and writes no audit data before the person
# turns protection on. It does not click the UI or exercise any protection.
set -euo pipefail

if [ "$#" -ne 2 ]; then
  echo "usage: $0 /path/to/BoxCop.app /path/to/evidence-dir" >&2
  exit 2
fi
APP="$1"
EVIDENCE="$2"
EXE="$APP/Contents/MacOS/BoxCop"
SUPPORT="$HOME/Library/Application Support/BoxCop"
LOG="$EVIDENCE/launch-smoke.txt"
mkdir -p "$EVIDENCE"
: > "$LOG"
say() { echo "$*" | tee -a "$LOG"; }
fail() { say "LAUNCH_SMOKE_FAIL: $*"; exit 1; }

[ -x "$EXE" ] || fail "missing app executable"
[ ! -e "$SUPPORT" ] || fail "runner already has BoxCop application-support data; refusing to mix evidence"
pgrep -x BoxCop >/dev/null && fail "another BoxCop process is already running"

release_profile="$("$EXE" --release-profile)"
case "$release_profile" in distribution|limited-development) ;; *) fail "expected packaged distribution or limited-development profile" ;; esac
say "release profile=$release_profile"

# Packaged apps stop at an installation prompt when run from outside /Applications.
# Exercise the installed first-run path without overwriting another BoxCop copy.
installed_app="/Applications/BoxCop-CI-$(uuidgen).app"
mkdir "$installed_app"
pid=""
cleanup() {
  if [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null; then
    kill -TERM "$pid" 2>/dev/null || true
    for _ in $(seq 1 20); do
      kill -0 "$pid" 2>/dev/null || break
      sleep 0.5
    done
    if kill -0 "$pid" 2>/dev/null; then
      say "app is still running; leaving $installed_app in place"
      return
    fi
  fi
  rm -rf "$installed_app"
}
trap cleanup EXIT
ditto "$APP" "$installed_app"
say "installed smoke-test copy at $installed_app"
open -n "$installed_app"
for _ in $(seq 1 40); do
  pid="$(pgrep -x BoxCop | head -n 1 || true)"
  [ -n "$pid" ] && break
  sleep 0.5
done
[ -n "$pid" ] || fail "BoxCop did not launch"
say "launched pid=$pid"

# The setup screen and the single-owner lock are created at launch; give AppKit time to settle.
sleep 8
kill -0 "$pid" 2>/dev/null || fail "BoxCop exited during first run"
say "still running after 8s"

if pgrep -x boxcop-engine >/dev/null; then fail "engine started before setup was confirmed"; fi
say "no boxcop-engine process before setup"
# The engine owns every database in the support directory, so none may exist yet.
if find "$SUPPORT" -name '*.sqlite3*' -print -quit 2>/dev/null | grep -q .; then fail "audit database created before setup was confirmed"; fi
say "no audit database before setup"
[ -f "$SUPPORT/native-owner.lock" ] || fail "single-owner lock was not created"
say "owner lock present; support dir mode=$(stat -f '%Lp' "$SUPPORT"), lock mode=$(stat -f '%Lp' "$SUPPORT/native-owner.lock")"
[ "$(stat -f '%Lp' "$SUPPORT")" = "700" ] || fail "application-support directory is not 0700"

# Best effort: hosted runners may deny screen capture, which then shows only the desktop.
if screencapture -x "$EVIDENCE/first-run.png" 2>/dev/null; then
  say "screenshot saved (window content depends on the runner's screen-capture permission)"
else
  say "screenshot unavailable on this runner"
fi

kill -TERM "$pid"
for _ in $(seq 1 20); do
  kill -0 "$pid" 2>/dev/null || break
  sleep 0.5
done
if kill -0 "$pid" 2>/dev/null; then fail "BoxCop did not exit after SIGTERM"; fi
pgrep -x boxcop-engine >/dev/null && fail "an engine process outlived the app"
say "LAUNCH_SMOKE_PASS: launched, stayed up, no engine or audit data before setup, exited"
