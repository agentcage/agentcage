"""Unit tests for ``agentcage.output``.

These exercise the spinner pause/resume mechanism that prevents
agentcage's braille spinner from fighting with subprocess-owned
progress writers (Apple's ``container`` CLI) for the same terminal line.
"""

from __future__ import annotations

import threading
from unittest.mock import MagicMock, patch

from agentcage import output


# ---------------------------------------------------------------------------
# pause_active_spinner
# ---------------------------------------------------------------------------

def test_pause_active_spinner_noop_when_no_active():
    """No active spinner -> the context manager is a silent no-op."""
    # Sanity: nothing else in the test process should have left an active
    # spinner behind. If it has, we want to know.
    assert output._active is None
    with output.pause_active_spinner():
        pass  # Should not raise.
    assert output._active is None


def test_pause_active_spinner_calls_pause_and_resume_on_active():
    """When _active is set, the CM should call pause() then resume()."""
    fake = MagicMock(spec=output.Spinner)
    with patch.object(output, "_active", fake):
        with output.pause_active_spinner():
            fake.pause.assert_called_once_with()
            fake.resume.assert_not_called()
        fake.pause.assert_called_once_with()
        fake.resume.assert_called_once_with()


def test_pause_active_spinner_resumes_even_on_exception():
    """resume() must be called even if the body raises."""
    fake = MagicMock(spec=output.Spinner)
    with patch.object(output, "_active", fake):
        try:
            with output.pause_active_spinner():
                raise RuntimeError("boom")
        except RuntimeError:
            pass
    fake.pause.assert_called_once_with()
    fake.resume.assert_called_once_with()


# ---------------------------------------------------------------------------
# Spinner.pause / Spinner.resume (non-TTY branch)
# ---------------------------------------------------------------------------

def test_spinner_pause_resume_noop_when_not_a_tty():
    """No thread is ever spawned in non-TTY mode; pause/resume must not crash."""
    with patch("sys.stderr.isatty", return_value=False):
        s = output.Spinner("hello")
        with s:
            assert s._thread is None  # No thread in non-TTY mode.
            s.pause()  # Must not raise / must not spawn a thread.
            assert s._thread is None
            s.resume()  # Must not raise / must not spawn a thread.
            assert s._thread is None


# ---------------------------------------------------------------------------
# Spinner.pause / Spinner.resume (TTY branch)
# ---------------------------------------------------------------------------

def test_spinner_pause_stops_thread_and_resume_restarts_it():
    """In TTY mode, pause() must stop the thread and resume() must start a new one."""
    with patch("sys.stderr.isatty", return_value=True):
        s = output.Spinner("hello")
        with s:
            t1 = s._thread
            assert t1 is not None
            assert t1.is_alive()
            s.pause()
            assert s._thread is None
            # The original thread should have exited.
            assert not t1.is_alive()
            s.resume()
            t2 = s._thread
            assert t2 is not None
            assert t2.is_alive()
            assert t2 is not t1  # Must be a freshly spawned thread.
        # After __exit__, no thread should be running.
        assert not t2.is_alive()


def test_spinner_enter_sets_active_and_exit_clears():
    """The active reference must track the spinner lifecycle."""
    with patch("sys.stderr.isatty", return_value=False):
        assert output._active is None
        s = output.Spinner("hello")
        with s:
            assert output._active is s
        assert output._active is None


def test_spinner_pause_preserves_msg_for_resume():
    """pause() must not destroy ``self.msg`` -- resume relies on it."""
    with patch("sys.stderr.isatty", return_value=True):
        s = output.Spinner("the-message")
        with s:
            s.pause()
            assert s.msg == "the-message"
            s.resume()
            assert s.msg == "the-message"


def test_spinner_pause_uses_a_fresh_stop_event_after_resume():
    """resume() must give us a fresh Event so a later __exit__ stops the thread."""
    with patch("sys.stderr.isatty", return_value=True):
        s = output.Spinner("hello")
        with s:
            s.pause()
            old_stop = s._stop
            assert old_stop.is_set()
            s.resume()
            # New stop event after resume.
            assert s._stop is not old_stop
            assert isinstance(s._stop, threading.Event)
            assert not s._stop.is_set()
