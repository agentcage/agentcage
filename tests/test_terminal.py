"""Tests for agentcage.terminal — host terminal restore around cage sessions."""

import os
import pty
import select
import signal
import sys
import termios
from unittest.mock import patch

import pytest

from agentcage import terminal


def _drain(fd: int, timeout: float = 0.5) -> bytes:
    out = b""
    while True:
        r, _, _ = select.select([fd], [], [], timeout)
        if not r:
            return out
        chunk = os.read(fd, 4096)
        if not chunk:
            return out
        out += chunk


@pytest.fixture
def fake_tty():
    """A pty pair, with the module convinced the slave is the controlling tty."""
    master, slave = pty.openpty()
    with patch.object(terminal, "is_interactive", return_value=True), \
         patch.object(terminal, "controlling_tty_fd", return_value=slave):
        yield master, slave
    os.close(master)
    os.close(slave)


class TestRestoreSequence:
    def test_pops_kitty_and_clears_flags(self):
        # Pop one level *and* zero the current flags — either alone leaves
        # some terminals with key-release reporting on.
        assert b"\x1b[<u" in terminal.RESTORE_SEQUENCE
        assert b"\x1b[=0;1u" in terminal.RESTORE_SEQUENCE

    def test_undoes_paste_modifyotherkeys_cursor(self):
        assert b"\x1b[?2004l" in terminal.RESTORE_SEQUENCE
        assert b"\x1b[>4;0m" in terminal.RESTORE_SEQUENCE
        assert b"\x1b[?25h" in terminal.RESTORE_SEQUENCE

    def test_never_touches_the_alternate_screen(self):
        # DECRST 1049 on a terminal that isn't in the alternate screen also
        # performs DECRC, which on some emulators homes the cursor over the
        # prompt. Not worth it for a mode our own sessions don't leak.
        assert b"1049" not in terminal.RESTORE_SEQUENCE


class TestRestoredTerminal:
    def test_writes_restore_sequence_on_normal_exit(self, fake_tty):
        master, _ = fake_tty
        with terminal.restored_terminal():
            pass
        assert _drain(master) == terminal.RESTORE_SEQUENCE

    def test_writes_restore_sequence_on_exception(self, fake_tty):
        master, _ = fake_tty
        with pytest.raises(RuntimeError):
            with terminal.restored_terminal():
                raise RuntimeError("cage vanished")
        assert _drain(master) == terminal.RESTORE_SEQUENCE

    def test_restores_termios_after_block_left_raw_mode(self, fake_tty):
        _, slave = fake_tty
        before = termios.tcgetattr(slave)
        assert before[3] & termios.ECHO
        with terminal.restored_terminal():
            # Simulate the exec client (or a dead program) leaving raw mode on.
            attrs = termios.tcgetattr(slave)
            attrs[3] &= ~(termios.ECHO | termios.ICANON)
            termios.tcsetattr(slave, termios.TCSANOW, attrs)
            assert not termios.tcgetattr(slave)[3] & termios.ECHO
        after = termios.tcgetattr(slave)
        assert after[3] & termios.ECHO
        assert after[3] & termios.ICANON

    def test_sigint_diverted_only_for_the_duration(self, fake_tty):
        previous = signal.getsignal(signal.SIGINT)
        with terminal.restored_terminal():
            handler = signal.getsignal(signal.SIGINT)
            assert handler is not previous
            assert handler is not signal.SIG_IGN, (
                "SIG_IGN would be inherited across exec and make Ctrl-C a "
                "no-op inside the cage; use a Python handler instead"
            )
        assert signal.getsignal(signal.SIGINT) is previous

    def test_noop_when_not_interactive(self):
        with patch.object(terminal, "is_interactive", return_value=False), \
             patch("os.write") as mock_write:
            with terminal.restored_terminal():
                pass
        mock_write.assert_not_called()

    def test_noop_when_no_tty_fd(self):
        with patch.object(terminal, "is_interactive", return_value=True), \
             patch.object(terminal, "controlling_tty_fd", return_value=None), \
             patch("os.write") as mock_write:
            with terminal.restored_terminal():
                pass
        mock_write.assert_not_called()


class TestExitStatus:
    @pytest.mark.parametrize("rc,expected", [
        (0, 0), (1, 1), (129, 129), (137, 137),
        (-signal.SIGINT, 130), (-signal.SIGKILL, 137), (-signal.SIGHUP, 129),
    ])
    def test_shell_style(self, rc, expected):
        assert terminal.exit_status(rc) == expected


class TestRunInteractive:
    def test_non_interactive_keeps_exec_semantics(self):
        with patch.object(terminal, "is_interactive", return_value=False), \
             patch("os.execvp", side_effect=SystemExit(0)) as mock_execvp:
            with pytest.raises(SystemExit):
                terminal.run_interactive(["container", "exec", "-it", "x", "sh"])
        mock_execvp.assert_called_once_with(
            "container", ["container", "exec", "-it", "x", "sh"])

    def test_interactive_runs_child_and_restores(self, fake_tty):
        master, _ = fake_tty
        # The child leaves the terminal dirty and dies by signal, the way a
        # program does when its cage is destroyed underneath it.
        argv = [sys.executable, "-c",
                "import os, signal; os.kill(os.getpid(), signal.SIGKILL)"]
        with pytest.raises(SystemExit) as exc:
            terminal.run_interactive(argv)
        assert exc.value.code == 128 + signal.SIGKILL
        assert _drain(master) == terminal.RESTORE_SEQUENCE

    def test_interactive_propagates_exit_code(self, fake_tty):
        with pytest.raises(SystemExit) as exc:
            terminal.run_interactive([sys.executable, "-c", "raise SystemExit(7)"])
        assert exc.value.code == 7

    def test_child_starts_with_default_sigint(self, fake_tty):
        # The parent's SIGINT diversion must not leak into the session.
        probe = ("import signal, sys; "
                 "sys.exit(0 if signal.getsignal(signal.SIGINT) "
                 "is signal.default_int_handler else 9)")
        with pytest.raises(SystemExit) as exc:
            terminal.run_interactive([sys.executable, "-c", probe])
        assert exc.value.code == 0


class TestCliWiring:
    """cage exec / cage shell must go through the restore path."""

    def test_cli_has_no_direct_exec_handoff_for_sessions(self):
        import inspect
        from agentcage import cli
        for fn in (cli.cage_exec, cli.cage_shell):
            src = inspect.getsource(fn.callback)
            assert "os.execvp(" not in src, f"{fn.name} bypasses terminal restore"
            assert "terminal.run_interactive" in src or \
                   "terminal.restored_terminal" in src
