#!/usr/bin/env bash
# E2E test runner — orchestrates phase scripts.
#
# Usage:
#   bash tests/e2e/run.sh                    # run all phases
#   bash tests/e2e/run.sh 1 2 3 4            # run specific phases
#   bash tests/e2e/run.sh container          # phases 1-6
#   bash tests/e2e/run.sh vm                 # phase 7 only
#   E2E_PORT_BASE=19100 bash tests/e2e/run.sh  # custom port base

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
export REPO_ROOT="${REPO_ROOT:-$(cd "$SCRIPT_DIR/../.." && pwd)}"

# ── parse args ───────────────────────────────────────────────────────
PHASES=()
if [ $# -eq 0 ]; then
  PHASES=(1 2 3 4 5 6 7)
else
  for arg in "$@"; do
    case "$arg" in
      container) PHASES+=(1 2 3 4 5 6) ;;
      vm)        PHASES+=(7) ;;
      all)       PHASES=(1 2 3 4 5 6 7) ;;
      [1-7])     PHASES+=("$arg") ;;
      -h|--help)
        echo "Usage: $0 [PHASE...] [container|vm|all]"
        echo ""
        echo "Phases:"
        echo "  1  Container lifecycle & core security"
        echo "  2  Audit, logs & HAR capture"
        echo "  3  Secret injection & management"
        echo "  4  Domain management & hot-reload"
        echo "  5  Backup/restore & multi-cage isolation"
        echo "  6  Security hardening & edge cases"
        echo "  7  VM mode (requires Lima + KVM)"
        echo ""
        echo "Shortcuts:"
        echo "  container   Phases 1-6"
        echo "  vm          Phase 7 only"
        echo "  all         Phases 1-7 (default)"
        echo ""
        echo "Environment:"
        echo "  E2E_PORT_BASE    Port base for test cages (default: 19080)"
        exit 0
        ;;
      *)
        echo "Unknown argument: $arg (use -h for help)"
        exit 1
        ;;
    esac
  done
fi

# ── preflight ────────────────────────────────────────────────────────
echo "agentcage E2E test suite"
echo "========================"
echo ""

# Check for stale e2e cages
STALE=$(agentcage cage list 2>/dev/null | grep -E "^e2e-" | awk '{print $1}' || true)
if [ -n "$STALE" ]; then
  echo "Cleaning up stale e2e cages..."
  for cage in $STALE; do
    agentcage cage destroy "$cage" -y >/dev/null 2>&1 || true
  done
fi

# ── master cleanup ───────────────────────────────────────────────────
cleanup_all() {
  echo ""
  echo "Final cleanup..."
  for name in basic e2e-har e2e-secrets e2e-second e2e-clone e2e-hardened e2e-vm; do
    podman rm -f "${name}-mock" >/dev/null 2>&1 || true
    agentcage cage destroy "$name" -y >/dev/null 2>&1 || true
  done
}
trap cleanup_all EXIT

# ── run phases ───────────────────────────────────────────────────────
SUITE_START=$(date +%s)

PHASE_SCRIPTS=(
  [1]="phase1_lifecycle.sh"
  [2]="phase2_audit_logs.sh"
  [3]="phase3_secrets.sh"
  [4]="phase4_domains.sh"
  [5]="phase5_backup.sh"
  [6]="phase6_hardening.sh"
  [7]="phase7_vm.sh"
)

TOTAL_PASS=0
TOTAL_FAIL=0
TOTAL_SKIP=0
PHASE_RESULTS=()
SUITE_FAILED=false

# ── helpers ─────────────────────────────────────────────────────────

# _tally_output PHASE RC ELAPSED RAW_OUTPUT
#   Shared result-counting logic: strip ANSI, count PASS/FAIL/SKIP,
#   update totals and PHASE_RESULTS, set SUITE_FAILED on failure.
_tally_output() {
  local phase="$1" rc="$2" elapsed="$3" raw="$4"

  local clean p f s
  clean=$(echo "$raw" | sed $'s/\033\[[0-9;]*m//g')
  p=$(echo "$clean" | grep -cE "^  PASS " || true)
  f=$(echo "$clean" | grep -cE "^  FAIL " || true)
  s=$(echo "$clean" | grep -cE "^  SKIP " || true)

  TOTAL_PASS=$((TOTAL_PASS + p))
  TOTAL_FAIL=$((TOTAL_FAIL + f))
  TOTAL_SKIP=$((TOTAL_SKIP + s))

  if [ "$rc" -eq 0 ] && [ "$f" -eq 0 ]; then
    PHASE_RESULTS+=("Phase $phase: PASS ($p passed, ${elapsed}s)")
  else
    PHASE_RESULTS+=("Phase $phase: FAIL ($p/$f, ${elapsed}s)")
    SUITE_FAILED=true
  fi
}

# Run a phase, capture output to a temp file, and record timing.
# Usage: run_phase PHASE_NUM [ENV_VAR=VALUE ...]
run_phase() {
  local phase="$1"; shift
  local script="${PHASE_SCRIPTS[$phase]}"
  local outfile
  outfile=$(mktemp /tmp/e2e-phase${phase}-XXXXXX.log)

  local start end elapsed rc
  start=$(date +%s)
  set +e
  env "$@" bash "$SCRIPT_DIR/$script" > "$outfile" 2>&1
  rc=$?
  set -e
  end=$(date +%s)
  elapsed=$((end - start))

  echo "$rc $elapsed $outfile" > "/tmp/e2e-result-${phase}.txt"
}

# Run a phase sequentially and tally results immediately
run_and_tally() {
  local phase="$1"; shift
  local script="${PHASE_SCRIPTS[$phase]}"

  local start end elapsed rc output
  start=$(date +%s)
  set +e
  output=$(env "$@" bash "$SCRIPT_DIR/$script" 2>&1)
  rc=$?
  set -e
  end=$(date +%s)
  elapsed=$((end - start))

  echo "$output"
  _tally_output "$phase" "$rc" "$elapsed" "$output"
}

# Tally results from a background phase's temp file
tally_bg_phase() {
  local phase="$1"
  local result_file="/tmp/e2e-result-${phase}.txt"
  [ -f "$result_file" ] || return

  local rc elapsed outfile
  read -r rc elapsed outfile < "$result_file"
  rm -f "$result_file"

  local raw
  raw=$(cat "$outfile")
  rm -f "$outfile"

  echo "$raw"
  _tally_output "$phase" "$rc" "$elapsed" "$raw"
}

# ── determine which phases to run ──────────────────────────────────
HAS_PHASE() { for p in "${PHASES[@]}"; do [ "$p" = "$1" ] && return 0; done; return 1; }

# Phases 1, 2, 4 share the "basic" cage — must run sequentially.
# Phases 3, 5, 6 create their own cages — can run in parallel.
# Phase 7 (VM) runs last, after container phases complete.

# ── sequential chain: 1 → 2 → 4 (shared "basic" cage) ────────────
KEEP_BASIC=false
if HAS_PHASE 1; then
  # Keep the cage if phase 2 or 4 follows
  if HAS_PHASE 2 || HAS_PHASE 4; then
    KEEP_BASIC=true
  fi
fi

# ── run sequential chain first: 1 → 2 → 4 (shared "basic" cage) ──
# Fail-fast: stop the chain on first failure.
if HAS_PHASE 1; then
  if [ "$KEEP_BASIC" = true ]; then
    run_and_tally 1 E2E_KEEP_BASIC=1
  else
    run_and_tally 1
  fi
fi
if HAS_PHASE 2 && [ "$SUITE_FAILED" = false ]; then
  run_and_tally 2
fi
if HAS_PHASE 4 && [ "$SUITE_FAILED" = false ]; then
  run_and_tally 4
fi

# Destroy the shared basic cage after the sequential chain
agentcage cage destroy basic -y >/dev/null 2>&1 || true

if [ "$SUITE_FAILED" = true ]; then
  echo ""
  echo "Sequential chain failed — skipping remaining phases."
fi

# ── launch independent phases (3, 5, 6) in parallel ─────────────
# These create their own cages on unique ports, so no contention.
# Run after the sequential chain to avoid Podman resource contention
# with the basic cage operations (domain add/rm, stop/start).
# Skip if sequential chain already failed.
BG_PIDS=()
BG_PHASES=()

if [ "$SUITE_FAILED" = false ]; then
  for phase in 3 5 6; do
    if HAS_PHASE "$phase"; then
      run_phase "$phase" &
      BG_PIDS+=($!)
      BG_PHASES+=("$phase")
    fi
  done
fi

# ── wait for parallel phases and collect results ───────────────────
for i in "${!BG_PIDS[@]}"; do
  wait "${BG_PIDS[$i]}" 2>/dev/null || true
  tally_bg_phase "${BG_PHASES[$i]}"
done

# ── phase 7 (VM) runs last ────────────────────────────────────────
if HAS_PHASE 7 && [ "$SUITE_FAILED" = false ]; then
  run_and_tally 7
fi

# ── summary ──────────────────────────────────────────────────────────
echo ""
echo "╔══════════════════════════════════════╗"
echo "║       E2E Test Suite Summary         ║"
echo "╠══════════════════════════════════════╣"
for result in "${PHASE_RESULTS[@]}"; do
  printf "║  %-36s║\n" "$result"
done
echo "╠══════════════════════════════════════╣"
SUMMARY="Total: ${TOTAL_PASS} passed"
[ "$TOTAL_FAIL" -gt 0 ] && SUMMARY="$SUMMARY, $TOTAL_FAIL failed"
[ "$TOTAL_SKIP" -gt 0 ] && SUMMARY="$SUMMARY, $TOTAL_SKIP skipped"
printf "║  %-36s║\n" "$SUMMARY"
SUITE_END=$(date +%s)
SUITE_ELAPSED=$((SUITE_END - SUITE_START))
SUITE_MIN=$((SUITE_ELAPSED / 60))
SUITE_SEC=$((SUITE_ELAPSED % 60))
printf "║  %-36s║\n" "Wall time: ${SUITE_MIN}m${SUITE_SEC}s"
echo "╚══════════════════════════════════════╝"
echo ""

if [ "$SUITE_FAILED" = true ] || [ "$TOTAL_FAIL" -gt 0 ]; then
  exit 1
fi
