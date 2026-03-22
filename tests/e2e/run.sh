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

# Phases 1-4 share the "basic" cage — tell phase 1 to keep it
HAS_FOLLOW_UP=false
for p in "${PHASES[@]}"; do
  if [ "$p" = "2" ] || [ "$p" = "4" ]; then
    HAS_FOLLOW_UP=true
  fi
done

for phase in "${PHASES[@]}"; do
  script="${PHASE_SCRIPTS[$phase]}"
  if [ -z "$script" ]; then
    echo "Unknown phase: $phase"
    continue
  fi

  # Tell phase 1 to keep the basic cage if phase 2 or 4 follows
  if [ "$phase" = "1" ] && [ "$HAS_FOLLOW_UP" = "true" ]; then
    export E2E_KEEP_BASIC=1
  else
    unset E2E_KEEP_BASIC 2>/dev/null || true
  fi

  # Run the phase in a subshell to isolate exit codes
  PHASE_START=$(date +%s)
  set +e
  OUTPUT=$(bash "$SCRIPT_DIR/$script" 2>&1)
  RC=$?
  set -e
  PHASE_END=$(date +%s)
  PHASE_ELAPSED=$((PHASE_END - PHASE_START))

  echo "$OUTPUT"

  # Strip ANSI codes and count actual test result lines
  CLEAN=$(echo "$OUTPUT" | sed $'s/\033\[[0-9;]*m//g')
  P=$(echo "$CLEAN" | grep -cE "^  PASS " || true)
  F=$(echo "$CLEAN" | grep -cE "^  FAIL " || true)
  S=$(echo "$CLEAN" | grep -cE "^  SKIP " || true)

  TOTAL_PASS=$((TOTAL_PASS + P))
  TOTAL_FAIL=$((TOTAL_FAIL + F))
  TOTAL_SKIP=$((TOTAL_SKIP + S))

  if [ "$RC" -eq 0 ] && [ "$F" -eq 0 ]; then
    PHASE_RESULTS+=("Phase $phase: PASS ($P passed, ${PHASE_ELAPSED}s)")
  else
    PHASE_RESULTS+=("Phase $phase: FAIL ($P/$F, ${PHASE_ELAPSED}s)")
  fi
done

# Destroy the shared basic cage if we kept it
agentcage cage destroy basic -y >/dev/null 2>&1 || true

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

if [ "$TOTAL_FAIL" -gt 0 ]; then
  exit 1
fi
