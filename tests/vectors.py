"""Shared input data for proxy tests that must not drift apart.

Plain data. Several proxy-side test files assert against the
same inputs; keeping them in one importable module means those files
cannot silently test different cases. ``tests/test_contract_fixtures.py``
also checks that the contract fixtures under ``tests/fixtures/contracts/``
cover every SSRF vector here, so the Rust suite, which asserts the same
fixtures, sees them too.

── SSRF / never-grant vectors ────────────────────────────────────────
``BYPASS`` must be refused and ``ALLOWED`` must not be, by
``tests/test_policy_api_ssrf_guard.py``.
"""

from __future__ import annotations

import json
from pathlib import Path

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
# The cage.yaml `agents` schema is a host/proxy format contract, so the
# sample lives in tests/fixtures/contracts/agents_config.json, where the
# Rust suite asserts the host accepts it too (contract_agents_config.rs).

_AGENTS = json.loads(
    (Path(__file__).parent / "fixtures" / "contracts" / "agents_config.json")
    .read_text()
)["cases"][0]["config"]

CANONICAL_AGENTS_CONFIG = _AGENTS

# The LLM client keys both agents share (the watcher overrides api_key).
AGENTS_CLIENT = {
    k: v for k, v in _AGENTS["agents"]["decider"].items()
    if k in ("provider", "model", "api_key", "timeout_seconds", "max_tokens", "base_url")
}
