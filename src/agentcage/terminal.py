"""Host terminal hygiene around interactive cage sessions.

``cage exec`` / ``cage shell`` hand the operator's terminal to a program
running *inside* the cage (``container exec -it``, ``podman exec -it``,
``limactl shell``). Full-screen programs in there — pi, claude, vim, less —
switch the host terminal into modes they promise to undo on exit: raw
input, bracketed paste, the Kitty keyboard protocol (whose key-*release*
reporting makes every later keystroke echo an escape sequence), xterm
``modifyOtherKeys``, focus/mouse reporting, hidden cursor.

They keep that promise when they exit on their own terms. They cannot when
the cage is stopped, destroyed, or rebuilt underneath them: the microVM /
container vanishes, the program is gone before it can write its restore
sequence, and the exec client simply closes. The operator is left with a
mangled terminal and no idea why (``reset`` usually doesn't fix Kitty mode).

The program inside the cage can't help — it's dead. The exec client doesn't
know what modes the program pushed. The only party that can reliably clean
up is the agentcage CLI on the host, *after* the session ends. Hence this
module: :func:`run_interactive` replaces the former ``os.execvp`` hand-off
with a child process plus an unconditional post-session restore.
"""

from __future__ import annotations

import os
import signal
import subprocess
import sys
from contextlib import contextmanager
from typing import Iterator, NoReturn

# Written to the terminal after every interactive session. Each item is a
# no-op on a terminal that's already in that state, so it's safe to send
# unconditionally — including to terminals that don't implement the
# corresponding protocol (unknown CSI sequences are ignored).
RESTORE_SEQUENCE = (
    b"\x1b[<u"        # Kitty keyboard protocol: pop one flags entry
    b"\x1b[=0;1u"     # Kitty keyboard protocol: force current flags to 0
    b"\x1b[>4;0m"     # xterm modifyOtherKeys off
    b"\x1b[?2004l"    # bracketed paste off
    b"\x1b[?1004l"    # focus reporting off
    b"\x1b[?1000l"    # mouse tracking off (all variants)
    b"\x1b[?1002l"
    b"\x1b[?1003l"
    b"\x1b[?1006l"
    b"\x1b[?2026l"    # synchronized output: end any open frame
    b"\x1b[?25h"      # cursor visible
    b"\x1b[0m"        # SGR reset
)


def is_interactive() -> bool:
    """True when stdin is a terminal.

    This is the same test the backends use to decide whether to allocate a
    pty (``-it``) — and therefore whether the program inside the cage can
    have touched the host terminal at all. It is deliberately ``sys.stdin``
    rather than fd 0: test harnesses (click's ``CliRunner``, pytest) swap
    ``sys.stdin`` for a non-tty object while leaving fd 0 attached to the
    developer's terminal.
    """
    try:
        return sys.stdin.isatty()
    except (AttributeError, ValueError):
        return False


def controlling_tty_fd() -> int | None:
    """Return a file descriptor on the controlling terminal, or ``None``.

    Prefers stdout (where the session's output went), then stderr, then
    stdin — the last covers ``cage exec ... | tee`` style invocations where
    only stdin is still the terminal.
    """
    for fd in (1, 2, 0):
        try:
            if os.isatty(fd):
                return fd
        except (OSError, ValueError):
            continue
    return None


def _ignore_sigint(signum, frame) -> None:  # pragma: no cover - trivial
    # A Python-level handler (rather than SIG_IGN) so that the disposition
    # is NOT inherited across exec: children start with SIG_DFL. SIG_IGN
    # *would* survive exec and silently make Ctrl-C a no-op inside the cage.
    return None


@contextmanager
def restored_terminal() -> Iterator[None]:
    """Snapshot the controlling terminal; put it back when the block ends.

    Restores the termios attributes (raw mode, echo, ...) and writes
    :data:`RESTORE_SEQUENCE` to undo terminal-application modes, whether
    the block exits normally or via an exception. SIGINT is diverted to a
    no-op in the *parent* for the duration, so Ctrl-C reaches the session's
    child process instead of unwinding the CLI mid-session (children still
    get the default disposition — see :func:`_ignore_sigint`).

    A no-op when the session isn't interactive or no terminal is attached.
    """
    if not is_interactive():
        yield
        return
    fd = controlling_tty_fd()
    if fd is None:
        yield
        return

    import termios  # POSIX only; agentcage doesn't run on Windows.

    try:
        saved = termios.tcgetattr(fd)
    except termios.error:
        saved = None

    previous = signal.signal(signal.SIGINT, _ignore_sigint)
    try:
        yield
    finally:
        signal.signal(signal.SIGINT, previous)
        if saved is not None:
            try:
                termios.tcsetattr(fd, termios.TCSADRAIN, saved)
            except termios.error:
                pass
        try:
            os.write(fd, RESTORE_SEQUENCE)
        except OSError:
            pass


def exit_status(returncode: int) -> int:
    """Map a ``subprocess`` return code to a shell-style exit status.

    ``subprocess`` reports a signal death as ``-signum``; shells report it
    as ``128 + signum``. Callers that scripted around the old ``os.execvp``
    hand-off saw the latter, so keep it.
    """
    if returncode < 0:
        return 128 + (-returncode)
    return returncode


def run_interactive(argv: list[str]) -> NoReturn:
    """Run ``argv`` as the operator's session and exit with its status,
    restoring the host terminal afterwards.

    Without a terminal on stdin there is nothing to restore, so this keeps
    the historical ``os.execvp`` semantics (agentcage is replaced by the
    exec client; the exit status is the client's). With a terminal, the
    client runs as a child so that the CLI is still alive to clean up once
    the session ends — however it ends.
    """
    if not is_interactive():
        os.execvp(argv[0], argv)
        raise AssertionError("unreachable")  # pragma: no cover
    with restored_terminal():
        proc = subprocess.run(argv)
    sys.exit(exit_status(proc.returncode))
