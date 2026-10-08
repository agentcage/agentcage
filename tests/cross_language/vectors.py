"""Shared fixture data for rules and formats that exist on both sides.

Plain data, no imports — which is the point. RUST-PORT-PLAN.md §2.2 turns
exactly this kind of table into a language-neutral JSON fixture in PR **A4**,
asserted by both the Rust suite and pytest. Keeping the data in one importable
module now means A4 has a single place to serialise from, and means a host-side
file and a proxy-side file split apart by PR A6 cannot silently test different
inputs in the meantime.

Importing this module does not make a test file straddle the boundary: it is
test support, not either implementation.

── SSRF / never-grant vectors ────────────────────────────────────────
Asserted by three files that must not be allowed to drift apart:

* ``tests/test_policy_api_ssrf_guard.py``  — proxy-side (``policy_api``)
* ``tests/test_ssrf_guard_host.py``        — host-side (``cli`` / ``config``)
* ``tests/cross_language/test_ssrf_guard_conformance.py`` — the two agree
"""

from __future__ import annotations

# Every one of these reaches a non-global address through a public name.
BYPASS = [
    "169-254-169-254.nip.io",      # AWS/GCP/Azure metadata (link-local)
    "169.254.169.254.nip.io",      # dotted form
    "127-0-0-1.nip.io",            # loopback
    "10-0-0-1.sslip.io",           # RFC1918
    "192-168-1-1.traefik.me",      # RFC1918, different service
    "172.17.0.1.xip.io",           # docker bridge
    "100-64-0-1.example.com",      # CGNAT — service-independent
]

# These must NOT be blocked: over-blocking a legitimate host is its own bug.
ALLOWED = [
    "registry.npmjs.org",
    "raw.githubusercontent.com",
    "codecov.io",
    "93-184-216-34.nip.io",   # encodes a PUBLIC ip — no worse than naming it
    "10-years.example.com",   # starts with digits, encodes nothing
    "1-2-3.example.com",      # too few octets
    "999-999-999-999.nip.io",  # not a valid address at all
]


# ── canonical `agents` block ──────────────────────────────────────────
# The cage.yaml `agents` schema is a format contract: the host validates and
# writes it (`config.validate_agents_raw`, `state.save_proxy_config`) and the
# addon reads it back (`addon._init_domain_requests` / `_init_watcher`). One
# canonical sample, consumed by both halves of the split
# `test_agents_config*.py`, so neither half can drift onto a shape the other
# does not produce. A4 folds this into the format-contract fixtures.

AGENTS_CLIENT = {
    "provider": "openrouter", "model": "m", "api_key": "env:TESTKEY",
    "timeout_seconds": 45, "max_tokens": 16384,
    "base_url": "https://models.example.com",
}

CANONICAL_AGENTS_CONFIG = {
    "name": "test", "isolation": "container", "dns_servers": ["1.1.1.1"],
    "container": {"image": "node:22-slim"},
    "domains": {"allow": ["example.com"]},
    "agents": {
        "decider": {
            "enable": True, "host": "custom.test", "context": "CI cage\n",
            "rate_limit": {"requests_per_second": 0, "burst": 0},
            **AGENTS_CLIENT,
        },
        "watcher": {
            "enable": True, "interval_seconds": 900, "window_seconds": 7200,
            "max_flows": 150, "auto_revoke": False, "dedup_samples": False,
            "max_digest_tokens": 8000, "context": "Audit CI traffic\n",
            **AGENTS_CLIENT, "api_key": "env:WATCHKEY",
        },
    },
}
