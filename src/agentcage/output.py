"""Styled terminal output helpers for agentcage CLI.

Provides a consistent visual style: dim borders, green/red status marks,
compact info lines, and a braille-dot spinner for in-progress steps.
"""

from __future__ import annotations

import itertools
import sys
import threading
import time

import click


def header(scaffold: str) -> None:
    """Print the ╭─╮ header box."""
    title = f" \u273b agentcage run \u00b7 {scaffold} "
    width = max(len(title) + 2, 44)
    padding = width - len(title)
    click.echo(dim(f"\u256d{'\u2500' * width}\u256e"))
    click.echo(dim("\u2502") + click.style(title, bold=True) + " " * padding + dim("\u2502"))
    click.echo(dim(f"\u2570{'\u2500' * width}\u256f"))
    click.echo()


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
        if not sys.stderr.isatty():
            click.echo(f"  \u2026 {self.msg}", err=True)
            return self
        self._thread = threading.Thread(target=self._spin, daemon=True)
        self._thread.start()
        return self

    def __exit__(self, *exc: object) -> None:
        self._stop.set()
        if self._thread:
            self._thread.join()
        if sys.stderr.isatty():
            click.echo("\r\033[K", nl=False, err=True)

    def _spin(self) -> None:
        for frame in itertools.cycle(self._FRAMES):
            if self._stop.is_set():
                break
            click.echo(f"\r  {frame} {self.msg}", nl=False, err=True)
            time.sleep(0.08)
