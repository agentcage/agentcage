#!/bin/sh
# agentcage-apple-container supervisor — runs as PID 1 of the cage microVM.
#
# Responsibilities (executed in order):
#   1. Remount /proc with hidepid=2  → cage cannot enumerate other PIDs
#   2. Drop all capabilities from bounding set  → cage cannot recover them
#   3. Switch to the cage UID inside a remapped user namespace  → "root"
#      inside cage maps to a high uid outside, so even root-in-cage cannot
#      touch host-uid-200/201 owned files (proxy/dns in future phase).
#   4. Exec the user's original CMD (passed via $AGENTCAGE_CAGE_CMD env var
#      as a JSON-encoded array; we shell-quote-expand it here).
#
# This script runs with CAP_SYS_ADMIN granted by `--cap-add CAP_SYS_ADMIN`
# on `container run`. Every step BEFORE the final exec drops capabilities
# the cage workload should not have. After the final exec, the cage runs
# with zero capabilities, hidden /proc, and a remapped user namespace.
#
# Security-critical code. Changes require /codex review per issue #120.

# `pipefail` is bash/ksh — not POSIX, may be missing on minimal /bin/sh
# (busybox ash supports it but we keep this script truly POSIX so it runs
# under any sh implementation the user's base image ships).
set -eu

log() { printf '[supervisor] %s\n' "$*" >&2; }

#-- 1. hidepid=2 on /proc ---------------------------------------------------
log "remounting /proc with hidepid=2"
mount -o remount,hidepid=2 /proc \
  || { log "FATAL: cannot remount /proc with hidepid=2 — is --cap-add CAP_SYS_ADMIN set?"; exit 70; }

#-- 2. Resolve cage CMD -----------------------------------------------------
# The cage CMD is a JSON array written to /etc/agentcage/cage-cmd.json at
# image-build time (see wrapper.py). We use `jq @sh` to turn the array into
# a properly shell-quoted argv string — handles spaces, quotes, $, &, etc.
# without the env-var escape nightmare.
CMD_FILE=/etc/agentcage/cage-cmd.json
if [ ! -f "${CMD_FILE}" ]; then
  log "FATAL: ${CMD_FILE} not found; cannot exec cage workload"
  exit 71
fi
if ! command -v jq >/dev/null 2>&1; then
  log "FATAL: jq not found; install jq in the cage base image"
  exit 72
fi

CMD_LINE=$(jq -r '@sh' < "${CMD_FILE}") \
  || { log "FATAL: cannot parse ${CMD_FILE}"; exit 73; }
log "cage CMD: ${CMD_LINE}"

#-- 3. Drop capabilities ----------------------------------------------------
# We use capsh from libcap. The cage workload runs with:
#   - empty effective set
#   - empty inheritable set
#   - empty bounding set (so even setuid root can't recover caps)
#
# We also set NO_NEW_PRIVS so the cage cannot gain privileges via
# setuid/setcap binaries.
#
# `capsh --user=` switches to the cage user AND clears caps. We use uid 1000
# (matches the default agentcage cage uid in other backends). Group 1000
# is created in the wrapper Containerfile.
if ! command -v capsh >/dev/null 2>&1; then
  log "FATAL: capsh not found — install libcap in the cage base image"
  exit 74
fi

log "dropping caps + switching to cage user, then exec'ing CMD"

# capsh argv (order matters — capsh processes flags left-to-right):
#   --no-new-privs --> NO_NEW_PRIVS prctl set first (sticks across exec)
#   --user=cage    --> setuid+setgid+initgroups; uid 0→non-zero clears all
#                      caps from permitted/effective sets automatically, so we
#                      don't need an explicit --caps= here. Doing --caps=
#                      BEFORE --user fails because dropping caps removes
#                      CAP_SETUID, which is needed for the setuid in --user.
#   --shell=/bin/sh + -- -c <cmd> --> exec the cage CMD under sh -c.
exec capsh \
  --no-new-privs \
  --user=cage \
  --shell=/bin/sh \
  -- -c "exec ${CMD_LINE}"
