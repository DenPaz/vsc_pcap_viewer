"""tshark/capinfos discovery, argument building and process helpers.

Security rule for this module: commands are always argv lists handed to
``subprocess.Popen`` without a shell. Nothing here ever builds a command
string.
"""

import atexit
import contextlib
import os
import re
import selectors
import shutil
import subprocess
import sys
import tempfile
import threading
from collections.abc import Generator, Iterator, Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path

from . import procs
from .cancellation import CancelledError, CancelToken
from .sandbox import permission_hint

IS_WINDOWS = sys.platform == "win32"


class ToolNotFoundError(Exception):
    """A Wireshark command-line tool could not be located."""

    def __init__(self, tool: str, searched: list[str]) -> None:
        super().__init__(
            f"{tool} was not found. Install Wireshark (which provides {tool}) or set "
            f"'pcapViewer.tsharkPath'. Searched: {', '.join(searched) or '(nothing)'}"
        )
        self.tool = tool
        self.searched = searched


class ToolError(Exception):
    """tshark (or capinfos) failed in a way that produced no usable output."""

    def __init__(self, message: str, stderr: str = "", returncode: int | None = None) -> None:
        super().__init__(message)
        self.stderr = stderr
        self.returncode = returncode


class ConfigError(ValueError):
    """Invalid user configuration (decode-as rule, preference key, script path...)."""


# --------------------------------------------------------------------------- discovery


def _default_locations(exe: str) -> list[Path]:
    if IS_WINDOWS:
        roots = {
            os.environ.get("PROGRAMFILES", r"C:\Program Files"),
            os.environ.get("PROGRAMFILES(X86)", r"C:\Program Files (x86)"),
            os.environ.get("PROGRAMW6432", r"C:\Program Files"),
        }
        return [Path(r) / "Wireshark" / f"{exe}.exe" for r in sorted(roots)]
    if sys.platform == "darwin":
        return [
            Path("/Applications/Wireshark.app/Contents/MacOS") / exe,
            Path("/opt/homebrew/bin") / exe,
            Path("/usr/local/bin") / exe,
        ]
    return [Path("/usr/bin") / exe, Path("/usr/local/bin") / exe, Path("/snap/bin") / exe]


def find_tool(exe: str, configured: str | None = None, sibling_of: Path | None = None) -> Path:
    """Locate a Wireshark CLI tool.

    Order: explicit configuration, the directory of ``sibling_of`` (so capinfos is
    taken from the same install as tshark), ``PATH``, then default install
    locations for the current platform.
    """
    searched: list[str] = []
    if configured:
        p = Path(configured).expanduser()
        searched.append(str(p))
        if p.is_file():
            return p
        raise ToolNotFoundError(exe, searched)
    candidates: list[Path] = []
    if sibling_of is not None:
        name = f"{exe}.exe" if IS_WINDOWS else exe
        candidates.append(sibling_of.parent / name)
    on_path = shutil.which(exe)
    if on_path:
        candidates.append(Path(on_path))
    candidates += _default_locations(exe)
    for c in candidates:
        searched.append(str(c))
        if c.is_file():
            return c
    raise ToolNotFoundError(exe, searched)


# --------------------------------------------------------------------------- options

_DECODE_AS_RE = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_.\-]*(==|:)[^,\s]+,[A-Za-z0-9_.\-]+$")
_PREF_KEY_RE = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_.\-]*$")


@dataclass(frozen=True, slots=True)
class DissectionOptions:
    """Options that change how tshark dissects packets.

    They are applied identically to *every* tshark invocation for a file so that
    the packet list, filters and detail views always agree.
    """

    lua_scripts: tuple[str, ...] = ()
    decode_as: tuple[str, ...] = ()
    prefs: tuple[tuple[str, str], ...] = ()

    @classmethod
    def from_params(
        cls,
        lua: Sequence[str] = (),
        decode_as: Sequence[str] = (),
        prefs: Mapping[str, object] | None = None,
    ) -> DissectionOptions:
        for rule in decode_as:
            if not _DECODE_AS_RE.match(rule):
                raise ConfigError(
                    f"invalid Decode As rule {rule!r}; expected e.g. 'tcp.port==8080,http'"
                )
        pref_items: list[tuple[str, str]] = []
        for key, value in (prefs or {}).items():
            if not _PREF_KEY_RE.match(key):
                raise ConfigError(f"invalid preference name {key!r}")
            text = _pref_value(value)
            if "\n" in text or "\r" in text:
                raise ConfigError(f"preference {key!r} must be a single line")
            pref_items.append((key, text))
        return cls(tuple(lua), tuple(decode_as), tuple(sorted(pref_items)))

    def args(self) -> list[str]:
        out: list[str] = []
        for script in self.lua_scripts:
            out += ["-X", f"lua_script:{script}"]
        for rule in self.decode_as:
            out += ["-d", rule]
        for key, value in self.prefs:
            out += ["-o", f"{key}:{value}"]
        return out

    def check_scripts(self) -> list[str]:
        """Return warnings for Lua scripts tshark would silently ignore."""
        warnings: list[str] = []
        for script in self.lua_scripts:
            if not Path(script).is_file():
                warnings.append(f"Lua script not found: {script}")
        if self.lua_scripts and hasattr(os, "geteuid") and os.geteuid() == 0:
            warnings.append(
                "tshark disables Lua dissectors when running as root; Lua scripts were not loaded"
            )
        return warnings


def _pref_value(value: object) -> str:
    if isinstance(value, bool):
        return "TRUE" if value else "FALSE"
    return str(value)


# --------------------------------------------------------------------------- processes

_NOISE = ("Running as user", "This could be dangerous")


def clean_stderr(text: str) -> str:
    """Strip tshark's harmless root warning and blank lines."""
    lines = [ln for ln in text.splitlines() if ln.strip() and not any(n in ln for n in _NOISE)]
    return "\n".join(lines)


class ProcessRegistry:
    """Every live child process, so shutdown can guarantee no orphans."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._procs: set[subprocess.Popen[bytes]] = set()

    def add(self, proc: subprocess.Popen[bytes]) -> None:
        with self._lock:
            self._procs.add(proc)

    def discard(self, proc: subprocess.Popen[bytes]) -> None:
        with self._lock:
            self._procs.discard(proc)

    def kill_all(self) -> None:
        """Kill every child (shutdown). A child that can't be signalled (AppArmor) is
        stopped by the thread that owns it, which closes its pipes and reaps it."""
        with self._lock:
            live = list(self._procs)
            self._procs.clear()
        for proc in live:
            if procs.kill_process(proc):
                with contextlib.suppress(subprocess.TimeoutExpired):
                    proc.wait(timeout=2)

    def __len__(self) -> int:
        with self._lock:
            return sum(1 for p in self._procs if p.poll() is None)


PROCESSES = ProcessRegistry()


def _popen(argv: Sequence[str], env: Mapping[str, str] | None = None) -> subprocess.Popen[bytes]:
    # No console window flashing up for every tshark run on Windows.
    flags = getattr(subprocess, "CREATE_NO_WINDOW", 0) if IS_WINDOWS else 0
    return subprocess.Popen(
        list(argv),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        creationflags=flags,
        env=None if env is None else dict(env),
    )


@dataclass(slots=True)
class RunResult:
    returncode: int
    stdout: bytes
    stderr: str


@dataclass(slots=True)
class StreamResult:
    """Filled in once a streamed run finishes."""

    returncode: int | None = None
    stderr: str = ""
    lines: int = 0
    warnings: list[str] = field(default_factory=list)


class _StderrCollector(threading.Thread):
    def __init__(self, proc: subprocess.Popen[bytes]) -> None:
        super().__init__(daemon=True)
        self._proc = proc
        self.chunks: list[bytes] = []

    def run(self) -> None:
        assert self._proc.stderr is not None
        for chunk in iter(lambda: self._proc.stderr.read(65536), b""):  # type: ignore[union-attr]
            if sum(len(c) for c in self.chunks) < 1 << 20:  # cap at 1 MiB
                self.chunks.append(chunk)

    @property
    def text(self) -> str:
        return clean_stderr(b"".join(self.chunks).decode("utf-8", "replace"))


def run(
    argv: Sequence[str],
    token: CancelToken | None = None,
    env: Mapping[str, str] | None = None,
) -> RunResult:
    """Run a command to completion, capturing output. Cancellable via ``token``.

    ``env`` replaces the environment when given (defaults to inheriting ours).
    """
    token = token or CancelToken()
    proc = _popen(argv, env)
    PROCESSES.add(proc)
    try:
        token.register(proc)  # kills the process if the token is already cancelled
        try:
            # Poll so cancellation works even if the kill is refused (AppArmor):
            # communicate() can be retried after a timeout without losing output.
            while True:
                try:
                    out, err = proc.communicate(timeout=procs.POLL_INTERVAL)
                    break
                except subprocess.TimeoutExpired:
                    token.raise_if_cancelled()
        finally:
            token.unregister(proc)
    finally:
        if proc.returncode is None:
            # Cancelled: stop it, reap it and close its pipes.
            if procs.kill_process(proc):
                proc.communicate()
                PROCESSES.discard(proc)
            else:
                procs.stop_process(proc, on_reaped=lambda: PROCESSES.discard(proc))
        else:
            PROCESSES.discard(proc)
    token.raise_if_cancelled()
    return RunResult(proc.returncode, out, clean_stderr(err.decode("utf-8", "replace")))


def stream_lines(
    argv: Sequence[str],
    result: StreamResult,
    token: CancelToken | None = None,
    env: Mapping[str, str] | None = None,
) -> Iterator[bytes]:
    """Yield stdout lines (with trailing newline stripped) as the process runs.

    ``result`` receives the exit code and stderr when the generator finishes.
    Closing the generator early kills the process. ``env`` replaces the
    environment when given.
    """
    token = token or CancelToken()
    proc = _popen(argv, env)
    PROCESSES.add(proc)
    collector = _StderrCollector(proc)
    collector.start()
    lines = _lines(proc, token)
    try:
        token.register(proc)
        for line in lines:
            result.lines += 1
            yield line
        if not token.cancelled:
            proc.wait()  # end of output: let it exit on its own (keeps its exit code)
    finally:
        lines.close()
        token.unregister(proc)
        # Stops it if it's still running (an early exit or a cancel), reaps it or
        # leaves it to a reaper if it can't be stopped, and closes its pipes.
        procs.stop_process(proc, [collector], on_reaped=lambda: PROCESSES.discard(proc))
        result.returncode = proc.returncode
        result.stderr = collector.text
    if token.cancelled:
        raise CancelledError("request cancelled")


def _lines(proc: subprocess.Popen[bytes], token: CancelToken) -> Generator[bytes]:
    """stdout lines without the line break; stops early once ``token`` is cancelled.

    On POSIX the pipe is polled, so a cancel is noticed within POLL_INTERVAL
    even when the child writes nothing and can't be killed (AppArmor). Windows
    can't poll pipes, but there the kill always works and ends the read.
    """
    assert proc.stdout is not None
    if IS_WINDOWS:
        for raw in proc.stdout:
            if token.cancelled:
                return
            yield raw.rstrip(b"\r\n")
        return
    fd = proc.stdout.fileno()
    pending = b""
    with selectors.DefaultSelector() as sel:
        sel.register(fd, selectors.EVENT_READ)
        while not token.cancelled:
            if not sel.select(procs.POLL_INTERVAL):
                continue
            chunk = os.read(fd, 1 << 16)
            if not chunk:
                break
            lines = (pending + chunk).split(b"\n")
            pending = lines.pop()
            for line in lines:
                yield line.removesuffix(b"\r")
        else:
            return
    if pending:
        yield pending.removesuffix(b"\r")


# --------------------------------------------------------------------------- tshark


# Minimal valid libpcap header (Ethernet link type); used to compile filters
# without reading the user's capture.
_EMPTY_PCAP = bytes.fromhex("d4c3b2a1020004000000000000000000ffff000001000000")


class _EmptyCapture:
    """One shared empty capture file per process, removed at exit."""

    def __init__(self) -> None:
        self._path: Path | None = None
        self._lock = threading.Lock()
        atexit.register(self.remove)

    def get(self) -> Path:
        with self._lock:
            if self._path is None or not self._path.exists():
                fd, name = tempfile.mkstemp(prefix="pcapviewer-empty-", suffix=".pcap")
                with os.fdopen(fd, "wb") as fh:
                    fh.write(_EMPTY_PCAP)
                self._path = Path(name)
            return self._path

    def remove(self) -> None:
        with self._lock:
            if self._path is not None:
                self._path.unlink(missing_ok=True)
                self._path = None


EMPTY_CAPTURE = _EmptyCapture()

_FOLDERS: dict[Path, str] = {}
_FOLDERS_LOCK = threading.Lock()


class Tshark:
    """A located tshark binary plus the dissection options for one capture."""

    def __init__(
        self,
        path: Path,
        options: DissectionOptions | None = None,
        capinfos: Path | None = None,
    ) -> None:
        self.path = path
        self.options = options or DissectionOptions()
        self.capinfos = capinfos

    @classmethod
    def locate(
        cls,
        tshark_path: str | None = None,
        capinfos_path: str | None = None,
        options: DissectionOptions | None = None,
    ) -> Tshark:
        tshark = find_tool("tshark", tshark_path)
        try:
            capinfos: Path | None = find_tool("capinfos", capinfos_path, sibling_of=tshark)
        except ToolNotFoundError:
            capinfos = None
        return cls(tshark, options, capinfos)

    def with_options(self, options: DissectionOptions) -> Tshark:
        return Tshark(self.path, options, self.capinfos)

    def argv(self, *args: str, capture: str | None = None, dissect: bool = True) -> list[str]:
        """Build a tshark argv. Dissection options are always included when dissecting."""
        out = [str(self.path)]
        if dissect:
            out += self.options.args()
        if capture is not None:
            out += ["-r", capture]
        out += list(args)
        return out

    def field_list(self, token: CancelToken | None = None) -> str:
        """``tshark -G fields`` output, including fields of the configured Lua scripts.

        ``-G`` must be tshark's first option and ignores ``-X lua_script:``, so
        the Lua scripts are copied into a temporary plugin folder and a second
        ``-G fields`` run is made with ``WIRESHARK_PLUGIN_DIR`` pointing at it.
        That run replaces the global plugin folder, so the normal run is kept
        too and the caller merges both.
        """
        outputs = [run([str(self.path), "-G", "fields"], token).stdout.decode("utf-8", "replace")]
        scripts = [Path(s) for s in self.options.lua_scripts if Path(s).is_file()]
        if scripts:
            with tempfile.TemporaryDirectory(prefix="pcapviewer-lua-") as tmp:
                for i, script in enumerate(scripts):
                    # Numbered copies keep load order and avoid name clashes.
                    shutil.copyfile(script, Path(tmp) / f"{i:03d}_{script.name}")
                env = {**os.environ, "WIRESHARK_PLUGIN_DIR": tmp}
                res = run([str(self.path), "-G", "fields"], token, env=env)
                outputs.append(res.stdout.decode("utf-8", "replace"))
        return "\n".join(outputs)

    def folders(self, token: CancelToken | None = None) -> str:
        """``tshark -G folders`` output (configuration and plugin locations), cached."""
        with _FOLDERS_LOCK:
            cached = _FOLDERS.get(self.path)
        if cached is None:
            cached = run([str(self.path), "-G", "folders"], token).stdout.decode("utf-8", "replace")
            with _FOLDERS_LOCK:
                _FOLDERS[self.path] = cached
        return cached

    def error(self, stderr: str, returncode: int | None, default: str) -> ToolError:
        """A ToolError for a failed run, explaining sandbox permission problems."""
        message = stderr or default
        hint = permission_hint(self.path, stderr)
        if hint:
            message = f"{message}\n\n{hint}"
        return ToolError(message, stderr, returncode)

    def version(self) -> str:
        res = run([str(self.path), "--version"])
        first = res.stdout.decode("utf-8", "replace").splitlines()
        return first[0].strip() if first else "unknown"

    def validate_filter(self, expr: str, token: CancelToken | None = None) -> str | None:
        """Return ``None`` if ``expr`` compiles, else tshark's error message."""
        if not expr.strip():
            return None
        res = run(self.argv("-Y", expr, capture=str(EMPTY_CAPTURE.get())), token)
        if res.returncode == 0:
            return None
        msg = res.stderr.strip()
        return msg.removeprefix("tshark: ") if msg else f"invalid filter (exit {res.returncode})"
