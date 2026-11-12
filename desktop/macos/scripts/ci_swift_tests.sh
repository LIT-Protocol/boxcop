#!/usr/bin/env bash
# CI-only: run the Swift package tests on a macOS CI runner with streamed output and a
# hard deadline per run.
#
# First runs the XCTest bundle directly with unbuffered output, so the log shows which test
# is running. Then runs `swift test --skip-build` the way build_app.py does. If a run passes
# its deadline, this script records the matching processes and a `sample` call graph of each,
# kills them and fails. A hang therefore fails within minutes with evidence, rather than
# holding the runner until the job timeout with no output.
set -uo pipefail

if [ "$#" -ne 2 ]; then
  echo "usage: $0 deadline-seconds evidence-dir" >&2
  exit 2
fi
DEADLINE="$1"
EVIDENCE="$2"
PACKAGE="$(cd "$(dirname "$0")/.." && pwd)"
mkdir -p "$EVIDENCE"

# run_with_deadline NAME PROCESS-PATTERN COMMAND...
run_with_deadline() {
  local name="$1" pattern="$2"
  shift 2
  local log="$EVIDENCE/run-$name.log"
  NSUnbufferedIO=YES "$@" >"$log" 2>&1 &
  local pid=$!
  tail -n +1 -f "$log" &
  local tail_pid=$!
  local waited=0 status=""
  while kill -0 "$pid" 2>/dev/null; do
    if [ "$waited" -ge "$DEADLINE" ]; then
      echo "::error title=Swift tests hung::$name still running after ${DEADLINE}s; sampling test processes"
      # ps (not pgrep) keeps parent PIDs, state and elapsed time in the evidence.
      # shellcheck disable=SC2009
      ps -axo pid,ppid,stat,etime,command | grep -E "$pattern|peer[.]pl" | grep -v grep | tee "$EVIDENCE/$name-processes.txt"
      for target in $(pgrep -f "$pattern" || true); do
        if sudo -n /usr/bin/sample "$target" 3 -file "$EVIDENCE/$name-sample-$target.txt" >/dev/null 2>&1; then
          echo "=== $name: call graph of pid $target ==="
          sed -n '/^Call graph:/,/^Total number in stack/p' "$EVIDENCE/$name-sample-$target.txt" | cut -c1-220 | head -n 400
        else
          echo "=== $name: could not sample pid $target ==="
        fi
      done
      pkill -KILL -f "$pattern" 2>/dev/null || true
      kill -KILL "$pid" 2>/dev/null || true
      pkill -KILL -f 'Fixtures/peer[.]pl' 2>/dev/null || true
      status=124
      break
    fi
    sleep 2
    waited=$((waited + 2))
  done
  if [ -z "$status" ]; then
    wait "$pid"
    status=$?
  fi
  sleep 1
  kill "$tail_pid" 2>/dev/null || true
  echo "$name: exit status $status after about ${waited}s"
  return "$status"
}

swift build --package-path "$PACKAGE" --build-tests || exit 1
BIN="$(swift build --package-path "$PACKAGE" --show-bin-path)"
BUNDLE="$BIN/BoxCopPackageTests.xctest"
if [ ! -d "$BUNDLE" ]; then
  echo "missing test bundle: $BUNDLE" >&2
  exit 1
fi

run_with_deadline bundle-1 'xctest .*BoxCopPackageTests' xcrun xctest "$BUNDLE" || exit $?
# Repeat the real-process tests: the hang this script was added for appeared in about half of the runs.
for round in 2 3; do
  run_with_deadline "bundle-$round" 'xctest .*BoxCopPackageTests' xcrun xctest -XCTest BoxCopCoreTests.ProcessTests "$BUNDLE" || exit $?
done
run_with_deadline package 'swift-test |swiftpm-testing-helper|xctest .*BoxCopPackageTests' \
  swift test --package-path "$PACKAGE" --skip-build
