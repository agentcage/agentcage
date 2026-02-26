#!/bin/sh
# dns-audit.sh — wrapper around dnsmasq that emits structured JSON audit
# entries on stderr for blocked (and optionally allowed) DNS lookups.
#
# Usage: dns-audit.sh [--log-allowed] -- dnsmasq [dnsmasq-args...]
#
# The wrapper runs dnsmasq with --log-facility=- so all log output goes to
# stdout.  It parses that output, emits audit JSON to stderr, and also
# passes the original log lines through to stderr (preserving cage logs).
#
# Blocked lookups are detected by "config <domain> is 198.51.100.1" lines
# (the black-hole IP used by dnsmasq --address=/#/198.51.100.1).
#
# Allowed lookups are detected by "reply", "forwarded", and "cached" lines.
# These are only emitted as audit entries when --log-allowed is given.

set -eu

LOG_ALLOWED=0

# Parse our own flags (before the -- separator)
while [ $# -gt 0 ]; do
    case "$1" in
        --log-allowed) LOG_ALLOWED=1; shift ;;
        --) shift; break ;;
        *) break ;;
    esac
done

# $@ is now the dnsmasq command with its arguments.
# Force --log-facility=- so dnsmasq writes log lines to stderr.
# We merge stderr into stdout for unified parsing.
"$@" --log-facility=- 2>&1 | while IFS= read -r line; do
    # Pass every original line through to stderr unchanged
    echo "$line" >&2

    # Emit audit JSON for blocked lookups:
    #   "config <domain> is 198.51.100.1"
    case "$line" in
        *"config "*" is 198.51.100.1")
            # Extract domain: strip everything up to "config " then up to " is"
            _after_config="${line#*config }"
            domain="${_after_config% is 198.51.100.1}"
            ts=$(date -u +"%Y-%m-%dT%H:%M:%S+00:00")
            printf '{"ts":"%s","direction":"outbound","method":"DNS","host":"%s","port":53,"path":"","url":"dns://%s","decision":"blocked","reason":"domain not in allowlist","inspectors":[{"name":"dns","action":"block","reason":"domain not in allowlist","severity":"warning"}]}\n' \
                "$ts" "$domain" "$domain" >&2
            ;;
    esac

    # Emit audit JSON for allowed lookups (if enabled):
    #   "reply <domain> is <ip>"  /  "forwarded <domain> to <ip>"  /  "cached <domain> is <ip>"
    if [ "$LOG_ALLOWED" = 1 ]; then
        case "$line" in
            *reply\ *\ is\ *)
                _after="${line#*reply }"
                domain="${_after%% is *}"
                ts=$(date -u +"%Y-%m-%dT%H:%M:%S+00:00")
                printf '{"ts":"%s","direction":"outbound","method":"DNS","host":"%s","port":53,"path":"","url":"dns://%s","decision":"allowed","reason":"","inspectors":[{"name":"dns","action":"allow","reason":"domain in allowlist","severity":"info"}]}\n' \
                    "$ts" "$domain" "$domain" >&2
                ;;
            *forwarded\ *\ to\ *)
                _after="${line#*forwarded }"
                domain="${_after%% to *}"
                ts=$(date -u +"%Y-%m-%dT%H:%M:%S+00:00")
                printf '{"ts":"%s","direction":"outbound","method":"DNS","host":"%s","port":53,"path":"","url":"dns://%s","decision":"allowed","reason":"","inspectors":[{"name":"dns","action":"allow","reason":"domain in allowlist","severity":"info"}]}\n' \
                    "$ts" "$domain" "$domain" >&2
                ;;
            *cached\ *\ is\ *)
                _after="${line#*cached }"
                domain="${_after%% is *}"
                ts=$(date -u +"%Y-%m-%dT%H:%M:%S+00:00")
                printf '{"ts":"%s","direction":"outbound","method":"DNS","host":"%s","port":53,"path":"","url":"dns://%s","decision":"allowed","reason":"","inspectors":[{"name":"dns","action":"allow","reason":"domain in allowlist","severity":"info"}]}\n' \
                    "$ts" "$domain" "$domain" >&2
                ;;
        esac
    fi
done
