"""Cross-language conformance: assertions that belong to neither side.

Everything in this directory imports **both** the host side (``src/agentcage/**``,
which becomes Rust) and the proxy side (``src/agentcage/data/proxy/**``, which
stays Python) — on purpose. Each test here exists solely to assert that two
implementations of the same rule, one per side of the trust boundary, agree.

That assertion has no home after the language split: it cannot be deleted with
the host tests without dropping the drift guard, and it cannot stay as a pytest
import of a module that no longer exists in Python.

**This directory is temporary.** RUST-PORT-PLAN.md §2.2 calls for a
language-neutral conformance fixture: a JSON file of ``(input, expected)`` cases
per contract, generated from the Python implementation and asserted
independently by a Rust test and a pytest test, so neither side can drift
silently. PR **A4** builds those fixtures and dissolves this directory.

Until then these tests keep the coverage alive and, crucially, keep the list of
shared-logic sites visible in one place. ``scripts/classify-tests.py`` reports
this directory separately from the ``both`` violations it fails CI on.
"""
