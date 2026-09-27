"""Cancellation when the OS refuses to signal a child (AppArmor's tshark profile).

The children are real processes whose ``kill``/``terminate``/``send_signal``
raise ``PermissionError``, like tshark under the enforced profile, so the
fallback (close its stdout, wait, else a reaper thread) runs for real:
cancellation must still raise CancelledError and leave no pipe or process
behind (pytest turns ResourceWarning into errors).
"""

import contextlib
import os
import signal
import subprocess
import sys
import threading
import time
from collections.abc import Iterator
from typing import Any

import pytest

from pcap_backend import procs, sandbox
from pcap_backend import tshark as ts
from pcap_backend.cancellation import CancelledError, CancelToken
from pcap_backend.pcap_service import PcapService
from pcap_backend.protocol import RequestContext
from pcap_backend.tshark import StreamResult

posix_only = pytest.mark.skipif(os.name != "posix", reason="polls pipes; POSIX signals")

CHATTY = "import time\nwhile True:\n    print('x' * 100, flush=True); time.sleep(0.005)"
SILENT = "import time; time.sleep(60)"


def _deny(*_args: Any) -> None:
    raise PermissionError(13, "Permission denied")


@pytest.fixture(autouse=True)
def fresh_warning() -> Iterator[None]:
    procs._kill_warned.clear()
    yield
    procs._kill_warned.clear()


@pytest.fixture
def denied(monkeypatch: pytest.MonkeyPatch) -> Iterator[list[subprocess.Popen[bytes]]]:
    """Every child started through tshark._popen refuses signals; yields them."""
    started: list[subprocess.Popen[bytes]] = []
    real_popen = ts._popen

    def popen(argv: Any, env: Any = None, stdin: Any = None) -> subprocess.Popen[bytes]:
        proc = real_popen(argv, env, stdin)
        proc.kill = proc.terminate = _deny  # type: ignore[method-assign]
        proc.send_signal = _deny  # type: ignore[method-assign]
        started.append(proc)
        return proc

    monkeypatch.setattr(ts, "_popen", popen)
    monkeypatch.setattr(procs, "STOP_TIMEOUT", 1.0)
    yield started
    # Really stop anything a test left to a reaper, and let the reapers finish.
    for proc in started:
        if proc.poll() is None:
            os.kill(proc.pid, signal.SIGKILL)
    for reaper in procs.pending_reapers():
        reaper.join(timeout=5)
    assert not procs.pending_reapers()


def _cancel_later(token: CancelToken, delay: float = 0.3) -> threading.Timer:
    timer = threading.Timer(delay, token.cancel)
    timer.start()
    return timer


def _closed(proc: subprocess.Popen[bytes]) -> bool:
    return all(p is None or p.closed for p in (proc.stdin, proc.stdout, proc.stderr))


# ---------------------------------------------------------------------- kill_process


class FakeProc:
    """A Popen stand-in: running until ``exit()``; ``kill`` does what it's told."""

    def __init__(self, kill_error: BaseException | None) -> None:
        self.pid = 4242
        self.args = ["/usr/bin/tshark", "-r", "x.pcap"]
        self.returncode: int | None = None
        self.kill_error = kill_error
        self.kills = 0
        self._exited = threading.Event()
        self.stdin = None
        self.stdout = FakePipe()
        self.stderr = FakePipe()

    def poll(self) -> int | None:
        return self.returncode

    def kill(self) -> None:
        self.kills += 1
        if self.kill_error:
            raise self.kill_error
        self.exit(-9)

    def exit(self, code: int) -> None:
        self.returncode = code
        self._exited.set()

    def wait(self, timeout: float | None = None) -> int:
        if not self._exited.wait(timeout):
            raise subprocess.TimeoutExpired(self.args, timeout or 0)
        assert self.returncode is not None
        return self.returncode


class FakePipe:
    closed = False

    def close(self) -> None:
        self.closed = True


def test_kill_process_never_raises(capsys: pytest.CaptureFixture[str]) -> None:
    ok = FakeProc(None)
    assert procs.kill_process(ok) and ok.returncode == -9  # type: ignore[arg-type]
    assert procs.kill_process(FakeProc(ProcessLookupError()))  # type: ignore[arg-type]  # gone
    denied = FakeProc(PermissionError(13, "Permission denied"))
    assert not procs.kill_process(denied)  # type: ignore[arg-type]
    assert not procs.kill_process(FakeProc(PermissionError(13, "again")))  # type: ignore[arg-type]
    err = capsys.readouterr().err
    assert err.count("could not stop tshark (pid 4242)") == 1, "warned once per backend"
    assert "Permission denied" in err and "Its output pipe is closed" in err
    assert capsys.readouterr().out == "", "stdout is the JSON-RPC channel"


def test_refused_kill_names_the_apparmor_rules(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(sandbox, "_apparmor_applies", lambda _program, _profiles: True)
    procs.kill_process(FakeProc(PermissionError(13, "Permission denied")))  # type: ignore[arg-type]
    err = capsys.readouterr().err
    assert "signal (receive) peer=vscode," in err and "signal (receive) peer=unconfined," in err
    assert "sudo apparmor_parser -r /etc/apparmor.d/tshark" in err


def test_stop_process_closes_pipes_then_reaps_later(capsys: pytest.CaptureFixture[str]) -> None:
    proc = FakeProc(PermissionError(13, "Permission denied"))
    reaped = threading.Event()
    assert not procs.stop_process(proc, timeout=0.05, on_reaped=reaped.set)  # type: ignore[arg-type]
    assert proc.stdout.closed, "stdout closed so its next write fails (SIGPIPE)"
    assert "still running after being stopped" in capsys.readouterr().err
    (reaper,) = procs.pending_reapers()
    proc.exit(1)  # it hits the closed pipe
    reaper.join(timeout=5)
    assert reaped.is_set() and proc.stderr.closed and not procs.pending_reapers()

    quick = FakeProc(None)
    assert procs.stop_process(quick)  # type: ignore[arg-type]
    assert quick.returncode == -9 and quick.stdout.closed and quick.stderr.closed


# ---------------------------------------------------------------------- real children


@posix_only
def test_stream_lines_cancel_with_refused_kill_chatty_child(
    denied: list[subprocess.Popen[bytes]],
) -> None:
    token = CancelToken()
    gen = ts.stream_lines([sys.executable, "-c", CHATTY], StreamResult(), token)
    assert next(gen).startswith(b"x")
    token.cancel()  # kill refused: the reader notices the cancel itself
    with pytest.raises(CancelledError):
        list(gen)
    (proc,) = denied
    assert proc.returncode is not None, "exited at its next write to the closed pipe, reaped"
    assert _closed(proc) and len(ts.PROCESSES) == 0 and not procs.pending_reapers()


@posix_only
def test_stream_lines_cancel_with_refused_kill_silent_child(
    denied: list[subprocess.Popen[bytes]], capsys: pytest.CaptureFixture[str]
) -> None:
    token = CancelToken()
    timer = _cancel_later(token)
    start = time.monotonic()
    with pytest.raises(CancelledError):  # not blocked until the child writes or exits
        list(ts.stream_lines([sys.executable, "-c", SILENT], StreamResult(), token))
    assert time.monotonic() - start < 5
    timer.join()
    (proc,) = denied
    assert proc.poll() is None, "it writes nothing, so it's still running"
    assert "still running after being stopped" in capsys.readouterr().err
    assert len(procs.pending_reapers()) == 1 and len(ts.PROCESSES) == 1
    os.kill(proc.pid, signal.SIGKILL)  # when it finally exits...
    procs.pending_reapers()[0].join(timeout=5)
    assert _closed(proc) and len(ts.PROCESSES) == 0  # ...it is reaped and forgotten


@posix_only
def test_run_cancel_with_refused_kill(denied: list[subprocess.Popen[bytes]]) -> None:
    token = CancelToken()
    timer = _cancel_later(token)
    start = time.monotonic()
    with pytest.raises(CancelledError):
        ts.run([sys.executable, "-c", CHATTY], token)
    assert time.monotonic() - start < 5
    timer.join()
    (proc,) = denied
    assert proc.returncode is not None and _closed(proc) and len(ts.PROCESSES) == 0

    token = CancelToken()
    timer = _cancel_later(token)
    with pytest.raises(CancelledError):
        ts.run([sys.executable, "-c", SILENT], token)
    timer.join()
    silent = denied[1]
    assert silent.poll() is None and len(procs.pending_reapers()) == 1
    os.kill(silent.pid, signal.SIGKILL)
    procs.pending_reapers()[0].join(timeout=5)
    assert _closed(silent) and len(ts.PROCESSES) == 0


@posix_only
def test_already_cancelled_token_with_refused_kill(denied: list[subprocess.Popen[bytes]]) -> None:
    token = CancelToken()
    token.cancel()
    with pytest.raises(CancelledError):
        ts.run([sys.executable, "-c", CHATTY], token)
    with pytest.raises(CancelledError):
        list(ts.stream_lines([sys.executable, "-c", CHATTY], StreamResult(), token))
    assert all(p.returncode is not None and _closed(p) for p in denied)
    assert len(ts.PROCESSES) == 0


@posix_only
def test_kill_all_with_refused_kill_does_not_raise(denied: list[subprocess.Popen[bytes]]) -> None:
    token = CancelToken()
    gen = ts.stream_lines([sys.executable, "-c", CHATTY], StreamResult(), token)
    next(gen)
    ts.PROCESSES.kill_all()  # shutdown: the kill is refused, nothing raises
    token.cancel()  # the owner then stops it through its pipes
    with pytest.raises(CancelledError):
        list(gen)
    assert denied[0].returncode is not None and _closed(denied[0])


@posix_only
@pytest.mark.tshark
def test_cancel_filter_with_refused_kill(
    denied: list[subprocess.Popen[bytes]], opened: PcapService
) -> None:
    ctx = RequestContext()
    ctx.token.cancel()
    with pytest.raises(CancelledError):
        opened.set_filter({"expr": "tcp"}, ctx)
    ctx = RequestContext()
    timer = _cancel_later(ctx.token, 0.05)
    with contextlib.suppress(CancelledError):  # (or it finishes first on this tiny capture)
        opened.set_filter({"expr": "udp"}, ctx)
    timer.join()
    assert denied and all(p.returncode is not None and _closed(p) for p in denied)
    assert len(ts.PROCESSES) == 0
