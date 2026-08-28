"""Inspector chain execution helpers (sync + off-loop executor wrapper).

The inspector chain (secret patterns, entropy, content-type, body-size,
domain) does CPU-bound work — for a 5 MB DATA payload through 19 secret
patterns plus entropy and content-type checks that's ~50–300 ms. Running
that synchronously on the asyncio event loop blocks every other client
session, the IMAP relay, and any HTTP request flowing through mitmproxy.

These helpers factor out the shared "run the chain" shape used by both
the SMTP relay (``SmtpRelay._run_inspectors``) and the mitmproxy HTTP
addon (``Agentcage.request`` / ``Agentcage.response`` /
``Agentcage.websocket_message``). The synchronous core
(``run_inspector_chain_sync``) is the single source of truth for chain
order, short-circuit-on-block, and ``ctx.prior_results`` accumulation.
``run_inspector_chain`` wraps it in ``loop.run_in_executor(None, ...)``
so the asyncio loop stays responsive while body inspection runs in a
worker thread — the same concurrency shape in both callers, with no
duplicated chain logic.

Thread safety: every shipped inspector is a pure function of its
``InspectionContext`` argument plus its own configuration, which is built
in a local and rebound atomically in ``configure()`` and never touched
on the ``inspect_*`` path. No module-level globals or class-level caches
are touched during inspection, so running the chain off-loop on the
default ``ThreadPoolExecutor`` is safe (verified by reading each
inspector in ``inspectors/``). A custom inspector that mutates shared
state would need its own guarding; that is out of scope for this
refactor.
"""

from __future__ import annotations

import asyncio
import functools
from typing import Callable, Optional

from inspectors.base import InspectionContext, InspectionResult, Inspector

__all__ = ["run_inspector_chain", "run_inspector_chain_sync"]


def run_inspector_chain_sync(
    inspectors: list[Inspector],
    ctx: InspectionContext,
    *,
    method: str = "request",
    skip: Optional[Callable[[Inspector], bool]] = None,
) -> list[InspectionResult]:
    """Run ``inspectors`` against ``ctx`` on the calling thread.

    ``method`` selects ``inspect_request`` ("request") or
    ``inspect_response`` ("response"). ``skip(inspector)`` returns True
    to skip an inspector entirely (e.g. ``DomainInspector`` on
    reverse-proxy relay traffic). The first ``block`` result
    short-circuits the chain.

    Returns every non-None result in invocation order (including the
    short-circuiting block, if any). Each result is also appended to
    ``ctx.prior_results`` so later inspectors in the chain can see it —
    matching the historical in-line loop semantics exactly, so callers
    that switched off the inline loop keep the same return shape and
    exception behaviour.
    """
    results: list[InspectionResult] = []
    for inspector in inspectors:
        if skip is not None and skip(inspector):
            continue
        result = (
            inspector.inspect_request(ctx)
            if method == "request"
            else inspector.inspect_response(ctx)
        )
        if result is None:
            continue
        results.append(result)
        ctx.prior_results.append(result)
        if result.action == "block":
            break
    return results


async def run_inspector_chain(
    inspectors: list[Inspector],
    ctx: InspectionContext,
    *,
    method: str = "request",
    skip: Optional[Callable[[Inspector], bool]] = None,
) -> list[InspectionResult]:
    """Async wrapper: run ``run_inspector_chain_sync`` in a thread.

    Uses the running loop's default ``ThreadPoolExecutor``
    (``loop.run_in_executor(None, ...)``) so the inspector chain's
    CPU-bound body scanning does not block the event loop. Preserves
    the exact return shape (list of results, short-circuit on block)
    and exception behaviour of the synchronous path.

    ``inspectors`` and ``ctx`` must be safe to touch from another
    thread. Built-in inspectors are pure over their input (see the
    module docstring); a per-call ``InspectionContext`` is never shared
    across concurrent invocations, so appending to its
    ``prior_results`` from the worker thread is safe.
    """
    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(
        None,
        functools.partial(
            run_inspector_chain_sync,
            inspectors,
            ctx,
            method=method,
            skip=skip,
        ),
    )
