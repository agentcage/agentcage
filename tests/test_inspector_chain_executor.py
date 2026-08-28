"""Tests for the shared inspector-chain executor helper (#223).

``inspectors/_chain.py`` factors the inspector chain (previously an
inline loop in both ``addon.py`` and ``relays/smtp.py``) into a single
synchronous core (``run_inspector_chain_sync``) plus an async wrapper
(``run_inspector_chain``) that runs the chain via
``loop.run_in_executor(None, ...)`` so the asyncio loop stays responsive
while body inspection runs in a worker thread.

These tests cover both surfaces:
  * the sync core returns results in order, short-circuits on ``block``,
    honours the ``skip`` predicate and the ``method`` selector, and
    accumulates ``ctx.prior_results`` exactly like the old inline loops;
  * the async wrapper preserves the same result through the executor;
  * the event loop stays responsive while a slow inspector runs — a
    concurrent task completes during the inspector's ``time.sleep``.
"""

from __future__ import annotations

import asyncio
import time

import pytest

from inspectors._chain import (
    run_inspector_chain,
    run_inspector_chain_sync,
)
from inspectors.base import InspectionContext, InspectionResult, Inspector


# ── Fakes ────────────────────────────────────────────────


class _RecordingInspector(Inspector):
    """Returns a fixed verdict; records the order it ran in."""

    def __init__(self, name: str, verdict: InspectionResult | None):
        self.name = name
        self._verdict = verdict
        self.calls = 0

    def inspect_request(self, ctx):  # noqa: ARG002
        self.calls += 1
        return self._verdict

    def inspect_response(self, ctx):  # noqa: ARG002
        self.calls += 1
        return self._verdict


class _SlowInspector(Inspector):
    """Sleeps for a while, then abstains — simulates CPU-bound body work."""

    name = "slow"

    def __init__(self, delay: float = 0.1):
        self._delay = delay

    def inspect_request(self, ctx):  # noqa: ARG002
        # time.sleep blocks the thread it runs in — if it ran on the
        # event loop, every concurrent task would stall.
        time.sleep(self._delay)
        return None

    def inspect_response(self, ctx):  # noqa: ARG002
        return None


class _ThreadNameInspector(Inspector):
    """Records the name of the thread it ran on; abstains."""

    name = "thread-name"

    def __init__(self):
        self.thread_name: str | None = None

    def inspect_request(self, ctx):  # noqa: ARG002
        import threading
        self.thread_name = threading.current_thread().name
        return None


def _ctx(body_text="hello", host="api.example.com"):
    return InspectionContext(
        url="https://api.example.com/v1/do",
        host=host,
        method="POST",
        headers=[],
        content_type="application/json",
        body_bytes=body_text.encode(),
        body_text=body_text,
        body_size=len(body_text),
        body_entropy=None,
    )


def _res(name, action="block"):
    return InspectionResult(
        inspector=name, action=action, reason=f"{name}-{action}",
        severity="warning",
    )


# ── Sync core ────────────────────────────────────────────


def test_sync_returns_results_in_order():
    a = _RecordingInspector("a", _res("a", "flag"))
    b = _RecordingInspector("b", _res("b", "flag"))
    ctx = _ctx()
    out = run_inspector_chain_sync([a, b], ctx, method="request")
    assert [r.inspector for r in out] == ["a", "b"]
    assert a.calls == 1 and b.calls == 1


def test_sync_short_circuits_on_block():
    a = _RecordingInspector("a", _res("a", "block"))
    b = _RecordingInspector("b", _res("b", "flag"))
    ctx = _ctx()
    out = run_inspector_chain_sync([a, b], ctx)
    assert len(out) == 1
    assert out[0].action == "block"
    # Short-circuit: b never ran.
    assert b.calls == 0


def test_sync_appends_to_prior_results():
    a = _RecordingInspector("a", _res("a", "flag"))
    b = _RecordingInspector("b", _res("b", "flag"))
    ctx = _ctx()
    run_inspector_chain_sync([a, b], ctx)
    assert [r.inspector for r in ctx.prior_results] == ["a", "b"]


def test_sync_skip_predicate_skips_inspector():
    a = _RecordingInspector("a", _res("a", "block"))
    ctx = _ctx()
    out = run_inspector_chain_sync([a], ctx, skip=lambda i: i.name == "a")
    assert out == []
    assert a.calls == 0


def test_sync_method_response_routes_to_inspect_response():
    class _Resp(Inspector):
        name = "resp"
        request_calls = 0
        response_calls = 0

        def inspect_request(self, ctx):  # noqa: ARG002
            self.request_calls += 1
            return None

        def inspect_response(self, ctx):  # noqa: ARG002
            self.response_calls += 1
            return None

    r = _Resp()
    run_inspector_chain_sync([r], _ctx(), method="response")
    assert r.response_calls == 1 and r.request_calls == 0


def test_sync_abstaining_inspectors_yield_empty_list():
    a = _RecordingInspector("a", None)
    ctx = _ctx()
    assert run_inspector_chain_sync([a], ctx) == []


# ── Async wrapper ────────────────────────────────────────


def threading_main_thread_name() -> str:
    import threading
    return threading.main_thread().name


def test_async_preserves_result_through_executor():
    """The async wrapper returns the same verdicts the sync core would."""
    a = _RecordingInspector("a", _res("a", "flag"))
    b = _RecordingInspector("b", _res("b", "block"))
    ctx = _ctx()

    out = asyncio.run(run_inspector_chain([a, b], ctx, method="request"))

    assert [r.inspector for r in out] == ["a", "b"]
    assert out[1].action == "block"
    assert [r.inspector for r in ctx.prior_results] == ["a", "b"]
    # Short-circuit honoured through the executor.
    assert b.calls == 1


def test_async_runs_chain_off_the_event_loop_thread():
    """The inspector chain runs on a worker thread, not the loop thread."""
    inspector = _ThreadNameInspector()
    asyncio.run(run_inspector_chain([inspector], _ctx()))
    # asyncio's default executor uses threads named "ThreadPoolExecutor-...",
    # never "MainThread". A blocking chain on the loop would run on
    # MainThread and freeze the loop — assert it did not.
    assert inspector.thread_name is not None
    assert inspector.thread_name != threading_main_thread_name()


def test_async_loop_stays_responsive_during_slow_inspector():
    """While a slow inspector sleeps in the executor, a concurrent asyncio
    task must make progress — proof the event loop is not blocked."""
    slow = _SlowInspector(delay=0.15)
    progressed_at: list[float] = []

    async def _concurrent_heartbeat():
        # Repeatedly yields; if the loop were blocked by the inspector
        # chain this would not advance until the chain finished.
        for i in range(5):
            progressed_at.append(time.monotonic())
            await asyncio.sleep(0.02)

    async def _main():
        chain = asyncio.create_task(run_inspector_chain([slow], _ctx()))
        hb = asyncio.create_task(_concurrent_heartbeat())
        await asyncio.gather(chain, hb)

    start = time.monotonic()
    asyncio.run(_main())
    elapsed = time.monotonic() - start
    # The heartbeat completed well before the full 0.15s inspector
    # sleep — i.e. the loop kept scheduling it instead of stalling.
    assert elapsed < 0.15 + 0.1  # generous upper bound (chain + hb)
    # And the heartbeat did actually advance (5 ticks recorded).
    assert len(progressed_at) == 5
    # Robust responsiveness check (matches the sibling tests in
    # ``test_addon_inspector_chain.py`` and ``test_protocol_relays_smtp.py``):
    # if the loop were blocked for the 0.15s inspector sleep, the gap
    # between the first heartbeat tick (~0) and the second (~0.15s)
    # would blow past this bound. Normal scheduling jitter is well
    # under 0.02s per tick.
    assert progressed_at[-1] - start < 0.15
    gaps = [progressed_at[i] - progressed_at[i - 1]
            for i in range(1, len(progressed_at))]
    assert max(gaps) < 0.1


def test_async_preserves_skip_predicate_and_method():
    a = _RecordingInspector("a", _res("a", "block"))
    ctx = _ctx()

    out = asyncio.run(
        run_inspector_chain([a], ctx, method="request",
                            skip=lambda i: i.name == "a")
    )

    assert out == []
    assert a.calls == 0
