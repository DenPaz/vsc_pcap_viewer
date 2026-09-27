"""Live capture: dumpcap writes pcapng to its stdout, and we copy it along.

``dumpcap -w -`` flushes after every packet when it writes to a pipe.
:class:`LiveCapture` reads that stream, cuts it into complete pcapng blocks
and writes them both to the capture file and to a pipe that the index pass's
``tshark -r - -l`` reads, so rows appear as packets arrive and the capture
file is a valid pcapng at every block boundary (other tshark passes read it
while it grows). Only complete blocks are ever written: a dumpcap that has
to be killed (Windows has no SIGINT for a console-less child) still leaves a
readable file. Neither dumpcap nor tshark touch the capture file itself, so
AppArmor's tshark profile (which only allows /tmp and Wireshark's folders)
doesn't matter here.

Stopping: SIGINT (dumpcap then ends its output cleanly, with the interface
statistics block) on POSIX, a kill on Windows; either way dumpcap's stdout
ends, the index pass's stdin is closed, and tshark finishes the rows.
"""

import contextlib
import json
import os
import re
import selectors
import struct
import subprocess
import sys
import threading
import time
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import IO, Any

from . import procs
from .cancellation import CancelledError, CancelToken
from .tshark import IS_WINDOWS, PROCESSES, ToolError, clean_stderr, find_tool

_SHB = 0x0A0D0D0A
_PACKET_BLOCKS = frozenset({6, 3, 2})  # EPB, SPB, obsolete PB
_BYTE_ORDER_MAGIC = 0x1A2B3C4D
# The block total length's upper bound (dumpcap's own maximum is far below).
_MAX_BLOCK = 1 << 28
STATS_INTERVAL_S = 1.0
START_TIMEOUT_S = 20.0
# dumpcap at exit: "Packets received/dropped on interface 'lo': 10/2 (…)".
_DROPPED_RE = re.compile(r"Packets received/dropped on interface .*?: (\d+)/(\d+)")
_PERMISSION_WORDS = (
    "permission",
    "Operation not permitted",
    "not permitted",
    "Access is denied",
    "npcap",
    "Npcap",
    "NPF",
    "wpcap",
    "no interfaces",
    "(BIOCSETIF)",
    "/dev/bpf",
)
# Test hook: a JSON argv prefix used instead of the dumpcap next to tshark.
DUMPCAP_ENV = "PCAP_VIEWER_DUMPCAP"


def dumpcap_command(tshark: Path) -> list[str]:
    """The argv prefix that runs dumpcap: the one installed with tshark."""
    override = os.environ.get(DUMPCAP_ENV)
    if override:
        argv = json.loads(override)
        if not isinstance(argv, list) or not all(isinstance(a, str) for a in argv) or not argv:
            raise ToolError(f"{DUMPCAP_ENV} must be a JSON list of strings")
        return argv
    return [str(find_tool("dumpcap", sibling_of=tshark))]


def permission_hint(stderr: str, platform: str = sys.platform) -> str | None:
    """How to allow capturing, when dumpcap failed for lack of permission."""
    if not any(w in stderr for w in _PERMISSION_WORDS):
        return None
    if platform == "win32":
        return (
            "Capturing on Windows needs Npcap (https://npcap.com; the Wireshark installer "
            "includes it). If it is installed with 'Restrict Npcap driver's access to "
            "Administrators only', run VS Code as administrator or reinstall Npcap without it."
        )
    if platform == "darwin":
        return (
            "Capturing on macOS needs access to the BPF devices: install ChmodBPF (the "
            "'Install ChmodBPF' package in Wireshark's disk image, or 'brew install --cask "
            "wireshark-chmodbpf'), then log out and in again."
        )
    return (
        "dumpcap needs the CAP_NET_RAW and CAP_NET_ADMIN capabilities. On Debian and Ubuntu: "
        "'sudo dpkg-reconfigure wireshark-common' (answer Yes), then "
        "'sudo usermod -aG wireshark $USER' and log in again. Elsewhere: "
        "'sudo setcap cap_net_raw,cap_net_admin=eip $(command -v dumpcap)'."
    )


def capture_error(stderr: str, returncode: int | None, default: str) -> ToolError:
    """A dumpcap failure, with how to allow capturing when that's the problem."""
    text = clean_stderr(stderr)
    lines = [
        ln
        for ln in text.split("\n")
        if ln.strip() and not ln.startswith(("Capturing on", "File: ", "Packets"))
    ]
    message = "\n".join(lines).removeprefix("dumpcap: ") or default
    hint = permission_hint(text)
    if hint:
        message = f"{message}\n\n{hint}"
    return ToolError(message, text, returncode)


@dataclass(frozen=True, slots=True)
class Interface:
    name: str
    description: str
    addresses: tuple[str, ...]
    loopback: bool

    def to_json(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "description": self.description,
            "addresses": list(self.addresses),
            "loopback": self.loopback,
        }


def parse_interfaces(text: str) -> list[Interface]:
    """``dumpcap -D -M``: "N. name<TAB>vendor<TAB>friendly name<TAB>type<TAB>
    addresses<TAB>loopback|network" per interface."""
    out: list[Interface] = []
    for raw in text.split("\n"):
        line = raw.removesuffix("\r")
        m = re.match(r"^\d+\.\s(.*)$", line)
        if not m:
            continue
        cells = m.group(1).split("\t")
        name = cells[0].strip()
        if not name:
            continue
        vendor = cells[1].strip() if len(cells) > 1 else ""
        friendly = cells[2].strip() if len(cells) > 2 else ""
        addresses = tuple(a for a in (cells[4] if len(cells) > 4 else "").split(",") if a)
        kind = cells[5].strip() if len(cells) > 5 else ""
        description = friendly or vendor
        out.append(Interface(name, description, addresses, kind == "loopback"))
    return out


@dataclass(frozen=True, slots=True)
class CaptureOptions:
    interfaces: tuple[str, ...]
    capture_filter: str = ""
    packets: int | None = None  # stop after this many packets
    seconds: float | None = None  # … after this long
    max_bytes: int | None = None  # … once the file is this big (enforced here)
    promiscuous: bool = True
    snaplen: int | None = None

    def dumpcap_args(self) -> list[str]:
        """dumpcap options (after the program): per interface -i, -f, -p and -s
        (each applies to the -i before it), the stop conditions, pcapng to stdout."""
        args = ["-q"]
        for name in self.interfaces:
            args += ["-i", name]
            if self.capture_filter:
                args += ["-f", self.capture_filter]
            if not self.promiscuous:
                args.append("-p")
            if self.snaplen:
                args += ["-s", str(self.snaplen)]
        if self.packets:
            args += ["-c", str(self.packets)]
        if self.seconds:
            args += ["-a", f"duration:{max(1, round(self.seconds))}"]
        return [*args, "-w", "-"]


def filter_problem(stderr: str) -> str | None:
    """The complaint of ``dumpcap -f <filter> -d`` about the filter (it exits
    with 0 either way), None if it accepted it."""
    text = clean_stderr(stderr)
    if "Invalid capture filter" not in text and "isn't a valid capture filter" not in text:
        return None
    for line in text.split("\n"):
        if "isn't a valid capture filter" in line:
            m = re.search(r"\((.*)\)", line)
            return m.group(1) if m else line.strip()
    return next(
        (ln.removeprefix("dumpcap: ").strip() for ln in text.split("\n") if "Invalid" in ln),
        "invalid capture filter",
    )


class _Blocks:
    """Cuts a pcapng byte stream into complete blocks (and counts packets)."""

    def __init__(self) -> None:
        self.pending = bytearray()
        self.endian = "<"
        self.packets = 0

    def feed(self, chunk: bytes) -> bytes:
        """The complete blocks now available (b"" if none yet)."""
        buf = self.pending
        buf += chunk
        pos = 0
        while len(buf) - pos >= 12:
            if struct.unpack_from("<I", buf, pos)[0] == _SHB:  # (the same either way)
                (magic,) = struct.unpack_from("<I", buf, pos + 8)
                self.endian = "<" if magic == _BYTE_ORDER_MAGIC else ">"
            kind, total = struct.unpack_from(self.endian + "II", buf, pos)
            if total < 12 or total % 4 or total > _MAX_BLOCK:
                raise ToolError(f"dumpcap wrote something that isn't pcapng (block length {total})")
            if len(buf) - pos < total:
                break
            if kind in _PACKET_BLOCKS:
                self.packets += 1
            pos += total
        done = bytes(buf[:pos])
        del buf[:pos]
        return done


class LiveCapture:
    """One dumpcap run copied into ``dest`` and into the pipe the index pass reads."""

    def __init__(
        self,
        command: Sequence[str],
        options: CaptureOptions,
        dest: Path,
        notify: Callable[[dict[str, Any]], None],
    ) -> None:
        self.command = list(command)
        self.options = options
        self.dest = dest
        self.notify = notify
        self.started_at = 0.0
        self.ended_at: float | None = None
        self.packets = 0
        self.bytes = 0
        self.dropped: int | None = None
        self.error: str | None = None
        self.returncode: int | None = None
        self.started = threading.Event()  # dumpcap opened the interfaces (first bytes)
        self.ended = threading.Event()  # dumpcap's output ended; the file is complete
        self._stop_requested = False
        self._signal_refused = False
        self._proc: subprocess.Popen[bytes] | None = None
        self._stderr: list[bytes] = []
        self._stderr_thread: threading.Thread | None = None
        self._reader: int | None = None  # the index pass's end of the pipe
        self._writer: int | None = None
        self._thread: threading.Thread | None = None
        self._lock = threading.Lock()

    # ------------------------------------------------------------------ lifecycle

    def start(self, token: CancelToken) -> None:
        """Start dumpcap and wait until it captures (its first bytes come once
        the interfaces are open) or fails (ToolError with its message)."""
        self.dest.parent.mkdir(parents=True, exist_ok=True)
        out = self.dest.open("wb")
        argv = [*self.command, *self.options.dumpcap_args()]
        flags = getattr(subprocess, "CREATE_NO_WINDOW", 0) if IS_WINDOWS else 0
        try:
            proc = subprocess.Popen(
                argv,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                creationflags=flags,
            )
        except OSError as exc:
            out.close()
            raise ToolError(f"could not start dumpcap: {exc}") from exc
        PROCESSES.add(proc)
        self._proc = proc
        self._reader, self._writer = os.pipe()
        self._stderr_thread = threading.Thread(target=self._read_stderr, daemon=True)
        self._stderr_thread.start()
        self.started_at = time.time()
        self._thread = threading.Thread(target=self._copy, args=(proc, out), daemon=True)
        self._thread.start()
        deadline = time.monotonic() + START_TIMEOUT_S
        while not self.started.wait(0.05):
            if self.ended.is_set():
                self.join()
                self.close_reader()
                raise capture_error(
                    self.stderr, self.returncode, self.error or "dumpcap stopped before capturing"
                )
            if token.cancelled or time.monotonic() > deadline:
                self.abort()
                self.join()
                self.close_reader()
                if token.cancelled:
                    raise CancelledError("capture cancelled")
                raise capture_error(self.stderr, None, "dumpcap did not start capturing")

    def take_reader(self) -> int:
        """The read end of the pipe for the index pass (which then owns it)."""
        with self._lock:
            fd, self._reader = self._reader, None
        if fd is None:
            raise ToolError("the capture's output was already taken")
        return fd

    def close_reader(self) -> None:
        with self._lock:
            fd, self._reader = self._reader, None
        if fd is not None:
            with contextlib.suppress(OSError):
                os.close(fd)

    def stop(self) -> bool:
        """Stop capturing (the rows of the packets captured so far still come).
        False if it had stopped already."""
        with self._lock:
            if self.ended.is_set() or self._stop_requested or self._proc is None:
                return False
            self._stop_requested = True
            proc = self._proc
        if not procs.interrupt_process(proc):
            self._signal_refused = True  # the copy loop then closes dumpcap's stdout
        return True

    def abort(self) -> None:
        """Kill dumpcap (closing the capture)."""
        with self._lock:
            self._stop_requested = True
            proc = self._proc
        if proc is not None and not procs.kill_process(proc):
            self._signal_refused = True

    def join(self, timeout: float | None = None) -> None:
        if self._thread is not None:
            self._thread.join(timeout)

    @property
    def running(self) -> bool:
        return self._proc is not None and not self.ended.is_set()

    @property
    def stderr(self) -> str:
        return clean_stderr(b"".join(self._stderr).decode("utf-8", "replace"))

    def describe(self) -> dict[str, Any]:
        o = self.options
        return {
            "interfaces": list(o.interfaces),
            "filter": o.capture_filter,
            "running": self.running,
            "startedAt": self.started_at,
            "endedAt": self.ended_at,
            "packets": self.packets,
            "bytes": self.bytes,
            "dropped": self.dropped,
            "error": self.error,
            "limits": {"packets": o.packets, "seconds": o.seconds, "bytes": o.max_bytes},
        }

    # ------------------------------------------------------------------ threads

    def _read_stderr(self) -> None:
        proc = self._proc
        assert proc is not None and proc.stderr is not None
        for chunk in iter(lambda: proc.stderr.read(4096), b""):  # type: ignore[union-attr]
            if sum(len(c) for c in self._stderr) < 1 << 16:
                self._stderr.append(chunk)

    def _chunks(self, proc: subprocess.Popen[bytes]) -> Any:
        """dumpcap's stdout in chunks; None now and then (about every
        POLL_INTERVAL) while it's quiet, so stats and a refused stop are handled."""
        assert proc.stdout is not None
        if IS_WINDOWS:
            stdout: IO[bytes] = proc.stdout
            while chunk := stdout.read1(1 << 16):  # type: ignore[attr-defined]
                yield chunk
            return
        fd = proc.stdout.fileno()
        with selectors.DefaultSelector() as sel:
            sel.register(fd, selectors.EVENT_READ)
            while True:
                if not sel.select(procs.POLL_INTERVAL):
                    yield None
                    continue
                chunk = os.read(fd, 1 << 16)
                if not chunk:
                    return
                yield chunk

    def _copy(self, proc: subprocess.Popen[bytes], out: IO[bytes]) -> None:
        blocks = _Blocks()
        last_stats = time.monotonic()
        tshark_gone = False
        eof = False
        try:
            for chunk in self._chunks(proc):
                if chunk:
                    data = blocks.feed(chunk)
                    if data:
                        out.write(data)
                        out.flush()
                        if not tshark_gone:
                            tshark_gone = not self._send(data)
                            if tshark_gone:
                                self.stop()  # nobody reads the rows any more
                        with self._lock:
                            self.bytes += len(data)
                            self.packets = blocks.packets
                        self.started.set()
                        limit = self.options.max_bytes
                        if limit and self.bytes >= limit:
                            self.stop()
                if self._signal_refused:
                    break  # closing dumpcap's stdout below makes it exit at its next write
                now = time.monotonic()
                if self.started.is_set() and now - last_stats >= STATS_INTERVAL_S:
                    last_stats = now
                    self.notify({"event": "stats", **self._stats()})
            else:
                eof = True
        except (OSError, ToolError) as exc:
            self.error = str(exc)
        finally:
            out.close()
            writer, self._writer = self._writer, None
            if writer is not None:
                with contextlib.suppress(OSError):
                    os.close(writer)  # the index pass sees the end of the capture
            if eof:
                # Its output ended: let it exit on its own (keeps its exit code).
                with contextlib.suppress(subprocess.TimeoutExpired):
                    proc.wait(timeout=procs.STOP_TIMEOUT)
            readers = [t for t in (self._stderr_thread,) if t is not None]
            procs.stop_process(proc, readers, on_reaped=lambda: PROCESSES.discard(proc))
            self.returncode = proc.returncode
            self._finish()

    def _send(self, data: bytes) -> bool:
        """Write to the index pass's pipe; False once tshark is gone."""
        writer = self._writer
        if writer is None:
            return False
        view = memoryview(data)
        try:
            while view:
                n = os.write(writer, view)
                view = view[n:]
        except OSError:
            return False
        return True

    def _stats(self) -> dict[str, Any]:
        end = self.ended_at or time.time()
        with self._lock:
            return {
                "packets": self.packets,
                "bytes": self.bytes,
                "seconds": round(max(0.0, end - self.started_at), 3),
            }

    def _finish(self) -> None:
        stderr = self.stderr
        drops = [int(m.group(2)) for m in _DROPPED_RE.finditer(stderr)]
        if drops:
            self.dropped = sum(drops)
        if self.error is None and not self._stop_requested and self.returncode not in (0, None):
            self.error = capture_error(
                stderr, self.returncode, f"dumpcap exited with code {self.returncode}"
            ).args[0]
        self.ended_at = time.time()
        self.ended.set()
        event = {"event": "stopped", **self._stats(), "dropped": self.dropped}
        if self.error:
            event["error"] = self.error
        self.notify(event)
