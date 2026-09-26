"""Stopping child processes, also when a sandbox won't let us signal them.

Under Ubuntu's AppArmor ``tshark`` profile, ``kill()`` of tshark raises
``PermissionError`` (see :mod:`pcap_backend.sandbox`). The fallback is to
close our end of the child's stdout: its next write then fails (SIGPIPE comes
from the kernel, which AppArmor doesn't mediate, or EPIPE) and it exits. The
thread that owns the process does this and reaps it, so cancellation never
depends on the signal being delivered. A child that still runs after
``STOP_TIMEOUT`` is handed to a reaper thread (with a warning): it is always
waited for and its pipes closed, so nothing leaks.
"""

import contextlib
import subprocess
import sys
import threading
from collections.abc import Callable, Sequence
from pathlib import Path
from typing import IO, Any

from .sandbox import kill_denied_hint

# How often a thread blocked on a child's output checks for cancellation.
POLL_INTERVAL = 0.2
# How long to wait for a child to exit once it was killed or its pipes closed.
STOP_TIMEOUT = 5.0

Proc = subprocess.Popen[bytes]

_lock = threading.Lock()
_kill_warned = threading.Event()  # the refused-kill warning is logged once per backend
_reapers: set[threading.Thread] = set()


def _log(message: str) -> None:
    print(f"pcap-viewer: {message}", file=sys.stderr, flush=True)  # stdout is the protocol


def _program(proc: Proc) -> Path:
    args: Any = proc.args
    first = args[0] if isinstance(args, (list, tuple)) and args else args
    return Path(str(first))


def kill_process(proc: Proc) -> bool:
    """Kill ``proc`` (TerminateProcess on Windows). Never raises.

    Returns False when the OS refused (``PermissionError``, e.g. AppArmor's
    tshark profile); that is logged once per backend with how to allow it.
    """
    if proc.poll() is not None:
        return True
    try:
        proc.kill()
    except ProcessLookupError:
        return True  # exited meanwhile
    except PermissionError as exc:
        _warn_kill_denied(proc, exc)
        return False
    except OSError as exc:
        _log(f"could not stop {_program(proc).name} (pid {proc.pid}): {exc}")
        return False
    return True


def _warn_kill_denied(proc: Proc, exc: OSError) -> None:
    with _lock:
        if _kill_warned.is_set():
            return
        _kill_warned.set()
    program = _program(proc)
    _log(
        f"could not stop {program.name} (pid {proc.pid}): {exc}. Its output pipe is closed "
        f"instead, so it stops at its next write; until then it keeps running.\n"
        f"{kill_denied_hint(program)}"
    )


def close_pipe(pipe: IO[bytes] | None) -> None:
    if pipe is not None:
        with contextlib.suppress(OSError):
            pipe.close()


def stop_process(
    proc: Proc,
    readers: Sequence[threading.Thread] = (),
    timeout: float | None = None,
    on_reaped: Callable[[], None] | None = None,
) -> bool:
    """Stop ``proc``, wait for it and close its pipes. Call from the thread that
    reads its stdout. ``readers`` are threads reading its other pipes (joined
    before those are closed). Returns True if it was reaped here, False if it
    was still running after ``timeout`` and left to a reaper thread, which
    then calls ``on_reaped``.
    """
    timeout = STOP_TIMEOUT if timeout is None else timeout
    if not kill_process(proc):
        # Can't signal it: make its next write fail instead.
        close_pipe(proc.stdout)
        close_pipe(proc.stdin)
    try:
        proc.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        _log(
            f"{_program(proc).name} (pid {proc.pid}) is still running after being stopped; "
            "it will be reaped when it exits"
        )
        _reap_later(proc, readers, on_reaped)
        return False
    _close_all(proc, readers)
    if on_reaped:
        on_reaped()
    return True


def _close_all(proc: Proc, readers: Sequence[threading.Thread]) -> None:
    for reader in readers:
        reader.join(timeout=STOP_TIMEOUT)
    for pipe in (proc.stdin, proc.stdout, proc.stderr):
        close_pipe(pipe)


def _reap_later(
    proc: Proc, readers: Sequence[threading.Thread], on_reaped: Callable[[], None] | None
) -> None:
    def reap() -> None:
        try:
            proc.wait()
            _close_all(proc, readers)
            if on_reaped:
                on_reaped()
        finally:
            with _lock:
                _reapers.discard(thread)

    thread = threading.Thread(target=reap, name=f"reap-{proc.pid}", daemon=True)
    with _lock:
        _reapers.add(thread)
    thread.start()


def pending_reapers() -> list[threading.Thread]:
    """Reaper threads still waiting for a child (for tests and shutdown)."""
    with _lock:
        return list(_reapers)
