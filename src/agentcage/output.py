"""Styled terminal output helpers for agentcage CLI.

Provides a consistent visual style: dim borders, green/red status marks,
compact info lines, and a braille-dot spinner for in-progress steps.
"""

from __future__ import annotations

import contextlib
import itertools
import sys
import threading
import time
from typing import Iterator

import click


def banner_text(ver: str) -> str:
    """Return the ╭─╮ banner with version as a string."""
    title = f" \u273b agentcage v{ver} "
    width = max(len(title) + 2, 44)
    padding = width - len(title)
    lines = [
        dim(f"\u256d{'\u2500' * width}\u256e"),
        dim("\u2502") + click.style(title, bold=True) + " " * padding + dim("\u2502"),
        dim(f"\u2570{'\u2500' * width}\u256f"),
        "",
    ]
    return "\n".join(lines)


def banner(ver: str) -> None:
    """Print the ╭─╮ banner with version."""
    click.echo(banner_text(ver))


def step_done(msg: str) -> None:
    """Print a green ✓ status line."""
    click.echo(f"  {green('\u2713')} {msg}")


def step_fail(msg: str) -> None:
    """Print a red ✗ status line to stderr."""
    click.echo(f"  {red('\u2717')} {msg}", err=True)


def info(label: str, value: str) -> None:
    """Print a dim label + value info line."""
    click.echo(f"  {dim(label.ljust(9))}{value}")


def separator() -> None:
    """Print a dim horizontal rule."""
    click.echo(dim("\u2500" * 44))


def dim(text: str) -> str:
    return click.style(text, dim=True)


def green(text: str) -> str:
    return click.style(text, fg="green")


def red(text: str) -> str:
    return click.style(text, fg="red")


# Module-level reference to the currently-active Spinner, if any.
# Used by ``pause_active_spinner`` so subprocess wrappers that stream their
# own progress to stderr (e.g. Apple's ``container`` CLI) can temporarily
# silence our braille spinner to avoid two writers fighting for the same
# terminal line.
_active: "Spinner | None" = None


class Spinner:
    """Context manager that shows a braille spinner on the current line.

    Falls back to a static ``…`` prefix when stderr is not a TTY.
    """

    _FRAMES = "\u280b\u2819\u2839\u2838\u283c\u2834\u2826\u2827\u2807\u280f"

    def __init__(self, msg: str) -> None:
        self.msg = msg
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    def __enter__(self) -> Spinner:
        global _active
        _active = self
        if not sys.stderr.isatty():
            click.echo(f"  \u2026 {self.msg}", err=True)
            return self
        self._thread = threading.Thread(target=self._spin, daemon=True)
        self._thread.start()
        return self

    def __exit__(self, *exc: object) -> None:
        global _active
        self._stop.set()
        if self._thread:
            self._thread.join()
            self._thread = None
        if sys.stderr.isatty():
            click.echo("\r\033[K", nl=False, err=True)
        # Defensive: only clear _active if it still points at us, so a
        # hypothetical nested spinner can't accidentally unset its parent.
        if _active is self:
            _active = None

    def pause(self) -> None:
        """Stop the spin thread and clear the current line.

        ``self.msg`` is preserved so ``resume()`` can restart cleanly.
        No-op when stderr is not a TTY (the static "… msg" line stays).
        """
        if not sys.stderr.isatty():
            return
        self._stop.set()
        if self._thread:
            self._thread.join()
            self._thread = None
        click.echo("\r\033[K", nl=False, err=True)

    def resume(self) -> None:
        """Re-spawn the spin thread after a ``pause()``.

        No-op when stderr is not a TTY.
        """
        if not sys.stderr.isatty():
            return
        # Recreate the stop event since the old one is already set.
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._spin, daemon=True)
        self._thread.start()

    def _spin(self) -> None:
        for frame in itertools.cycle(self._FRAMES):
            if self._stop.is_set():
                break
            click.echo(f"\r  {frame} {self.msg}", nl=False, err=True)
            time.sleep(0.08)


@contextlib.contextmanager
def pause_active_spinner() -> Iterator[None]:
    """Pause the active Spinner for the duration of the ``with`` block.

    Use this around subprocess calls that stream their own progress to
    stderr (e.g. Apple's ``container`` CLI), so two writers don't fight
    over the same terminal line. No-op if no Spinner is currently active.
    """
    spinner = _active
    if spinner is None:
        yield
        return
    spinner.pause()
    try:
        yield
    finally:
        spinner.resume()
