"""Cooperative cancellation shared by the JSON-RPC server and tshark runners."""

from __future__ import annotations

import contextlib
import subprocess
import threading
from collections.abc import Callable


class CancelledError(Exception):
    """Raised inside a request handler once its token has been cancelled."""


class CancelToken:
    """Tracks a request's cancellation state and the child processes it owns.

    Cancelling the token kills every registered process, which unblocks any
    thread reading from their pipes. Handlers call :meth:`raise_if_cancelled`
    at convenient points to stop promptly.
    """

    def __init__(self) -> None:
        self._event = threading.Event()
        self._lock = threading.Lock()
        self._procs: set[subprocess.Popen[bytes]] = set()
        self._callbacks: list[Callable[[], None]] = []

    @property
    def cancelled(self) -> bool:
        return self._event.is_set()

    def cancel(self) -> None:
        with self._lock:
            if self._event.is_set():
                return
            self._event.set()
            procs = list(self._procs)
            callbacks = list(self._callbacks)
        for proc in procs:
            _kill(proc)
        for cb in callbacks:
            cb()

    def raise_if_cancelled(self) -> None:
        if self._event.is_set():
            raise CancelledError("request cancelled")

    def register(self, proc: subprocess.Popen[bytes]) -> None:
        with self._lock:
            if self._event.is_set():
                _kill(proc)
                raise CancelledError("request cancelled")
            self._procs.add(proc)

    def unregister(self, proc: subprocess.Popen[bytes]) -> None:
        with self._lock:
            self._procs.discard(proc)

    def on_cancel(self, cb: Callable[[], None]) -> None:
        with self._lock:
            if not self._event.is_set():
                self._callbacks.append(cb)
                return
        cb()


def _kill(proc: subprocess.Popen[bytes]) -> None:
    if proc.poll() is None:
        with contextlib.suppress(OSError):
            proc.kill()
