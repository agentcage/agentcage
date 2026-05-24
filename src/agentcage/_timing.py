"""Wall-time instrumentation for cage-creation phases.

The cage-creation path on macOS routes through ``VmBackend`` and
``LimaInstance`` and takes 60-180s on a fresh Mac. Without per-phase
timings, every perf change is a guess. This module provides the smallest
useful primitive: a ``Phase`` context manager that records ``{label, ms,
ts}`` into a per-cage JSONL ledger, and a reader for ``agentcage cage
timings``.

Default behavior:
- JSONL append is always on (cheap, fixed-size rotation).
- ``AGENTCAGE_TIMING=1`` also echoes ``[timing] <label>: <ms>ms`` to
  stderr for live observation. No env var, no stderr noise.

Failure mode: file I/O errors are swallowed. Instrumentation must never
break the operation being timed.
"""

from __future__ import annotations

import json
import os
import time
from pathlib import Path
from types import TracebackType

import click


_DATA_DIR = Path(
    os.environ.get("XDG_DATA_HOME", os.path.expanduser("~/.local/share"))
) / "agentcage"

# Keep the last N timing files per cage. Each cage-create run is one file.
_MAX_FILES_PER_CAGE = 20

# Module-level: lock the run file per (cage, pid) so all phases in a single
# CLI invocation land in one JSONL.
_run_files: dict[tuple[str, int], Path] = {}


def _timings_dir(cage: str) -> Path:
    return _DATA_DIR / cage / "timings"


def _run_file(cage: str) -> Path:
    """Return the JSONL path for this process's run on *cage*, creating it on first use."""
    key = (cage, os.getpid())
    if key not in _run_files:
        d = _timings_dir(cage)
        d.mkdir(parents=True, exist_ok=True)
        # Rotate to leave room for the file we're about to add, so the
        # post-write directory holds at most _MAX_FILES_PER_CAGE entries.
        _rotate(d, keep=_MAX_FILES_PER_CAGE - 1)
        # ISO-ish timestamp + pid, sortable lexically.
        ts = time.strftime("%Y%m%dT%H%M%S", time.gmtime())
        _run_files[key] = d / f"{ts}-{os.getpid()}.jsonl"
    return _run_files[key]


def _rotate(d: Path, *, keep: int) -> None:
    """Delete oldest timing files so at most *keep* remain."""
    try:
        files = sorted(d.glob("*.jsonl"))
        for old in files[:-keep] if keep > 0 else files:
            old.unlink(missing_ok=True)
    except OSError:
        pass


def _append(cage: str, label: str, ms: float) -> None:
    record = {"label": label, "ms": round(ms, 2), "ts": time.time()}
    try:
        with _run_file(cage).open("a", encoding="utf-8") as f:
            f.write(json.dumps(record) + "\n")
    except OSError:
        pass


class Phase:
    """Time a code block and append the result to the cage's JSONL ledger.

        with Phase("build.proxy", cage=name):
            inst.exec([...])

    If *cage* is None, the phase is echoed (when AGENTCAGE_TIMING=1) but
    not persisted — useful in code paths that don't yet know the cage name.
    """

    def __init__(self, label: str, *, cage: str | None = None) -> None:
        self.label = label
        self.cage = cage
        self._t0 = 0.0
        self.ms = 0.0

    def __enter__(self) -> "Phase":
        self._t0 = time.perf_counter()
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        self.ms = (time.perf_counter() - self._t0) * 1000
        if self.cage:
            try:
                _append(self.cage, self.label, self.ms)
            except Exception:
                # Instrumentation must never break the code it wraps.
                pass
        if os.environ.get("AGENTCAGE_TIMING") == "1":
            click.echo(f"[timing] {self.label}: {self.ms:.0f}ms", err=True)


def print_summary(cage: str, *, echo=None) -> None:
    """Print a phase/ms/% table for the most recent run of *cage*.

    No-op (with a one-line note) if no timings exist. Always silent on
    error — this is a diagnostic, not a critical path.
    """
    if echo is None:
        echo = click.echo
    path, records = load_latest(cage)
    if not records:
        echo("(no timing data for this run)", err=True)
        return
    total = sum(r.get("ms", 0) for r in records) or 1.0
    label_w = max(24, max(len(r.get("label", "")) for r in records) + 2)
    sep = "─" * (label_w + 18)
    echo("")
    echo(f"{'Phase':<{label_w}}{'ms':>10}{'%':>8}")
    echo(sep)
    for r in records:
        label = r.get("label", "?")
        ms = r.get("ms", 0)
        pct = (ms / total) * 100
        echo(f"{label:<{label_w}}{ms:>10.0f}{pct:>7.0f}%")
    echo(sep)
    echo(f"{'Total':<{label_w}}{total:>10.0f}{100:>7.0f}%   ({total/1000:.1f}s)")


def load_latest(cage: str) -> tuple[Path | None, list[dict]]:
    """Return (path, records) for the most recent timing file, or (None, [])."""
    d = _timings_dir(cage)
    if not d.is_dir():
        return None, []
    files = sorted(d.glob("*.jsonl"))
    if not files:
        return None, []
    latest = files[-1]
    records: list[dict] = []
    try:
        with latest.open(encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    records.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
    except OSError:
        return latest, []
    return latest, records
