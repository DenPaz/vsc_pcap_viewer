"""Saved packet-list indexes, so reopening an unchanged capture skips the index pass.

The index pass (one tshark ``-T fields`` run over the whole capture) takes
about 30 s per million packets. Its result, the rows file and the line
offsets, is saved under the extension's storage folder, keyed by everything
that changes it (:func:`index_key`): the file's identity, the tshark binary
and version, the dissection options (Lua scripts by content), tshark's
personal configuration and plugins, and the custom columns. Anything else
makes a different key, so a stale index is never used.

Each entry is a folder ``<key>/`` with ``rows.tsv``, ``offsets.bin`` (one
unsigned 64-bit offset per frame), ``meta.json`` and optional
``colors-<rules>.bin`` (one coloring-rule byte per frame) and
``filter-<expr>.bin`` (a display filter's matching frame numbers, 32-bit). Entries are
written to a temporary folder and renamed into place, so a reader never sees
half an entry. The total size is capped: the least recently used entries go
first (``meta.json``'s mtime is touched on every hit).

``meta.json`` says whether the entry is ``complete`` (the index pass read the
whole capture and tshark ended on its own) and how many ``frames`` it holds.
An incomplete entry is what a streaming open had indexed when it was closed:
the next open shows those rows at once and re-reads the capture from the
start to go on (see pcap_service). Only complete entries are loaded as a
finished index, and only they keep colors and filter results.

The rows file holds packet summaries (addresses, the Info column); it lives in
the user's own extension storage and can be turned off or cleared.
"""

import contextlib
import hashlib
import json
import os
import shutil
import sys
from array import array
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

# Bump when the rows, offsets or meta change meaning: old entries are then ignored.
# 2: meta.json has ``complete`` and ``frames`` (format 1 could save a closed,
# unfinished pass as a finished index).
CACHE_FORMAT = 2
MAX_COLORINGS = 4  # coloring results kept per entry
MAX_FILTERS = 8  # display-filter results kept per entry
_MAX_CONFIG_FILES = 500  # personal config/plugin files hashed into the key


@dataclass(frozen=True, slots=True)
class CachedIndex:
    rows: Path
    offsets: array[int]
    meta: dict[str, Any]

    @property
    def complete(self) -> bool:
        """The whole capture (else the rows indexed before a streaming open was closed)."""
        return self.meta.get("complete") is True


def _log(message: str) -> None:
    print(f"pcap-viewer: index cache: {message}", file=sys.stderr, flush=True)  # noqa: T201 - stderr


def _file_fingerprint(path: Path) -> list[Any]:
    try:
        st = path.stat()
    except OSError:
        return [str(path), None]
    return [str(path), st.st_size, st.st_mtime_ns]


def folder_fingerprint(folders: Iterable[Path]) -> list[Any]:
    """Names, sizes and mtimes of the files in ``folders`` (recursively, bounded):
    tshark's personal preferences, Decode As entries, enabled/disabled protocols
    and personal plugins all change dissection."""
    out: list[Any] = []
    for folder in folders:
        if not folder.is_dir():
            continue
        files = []
        for root, _dirs, names in os.walk(folder):
            files += [Path(root) / n for n in names]
            if len(files) > _MAX_CONFIG_FILES:
                break
        out += [_file_fingerprint(f) for f in sorted(files)[:_MAX_CONFIG_FILES]]
    return out


def _sha256(path: Path) -> str | None:
    try:
        return hashlib.sha256(path.read_bytes()).hexdigest()
    except OSError:
        return None


def _pref_file(value: Any) -> list[Any]:
    """Size and mtime of the file a preference value names (absolute paths only)."""
    if not isinstance(value, str) or not value or not Path(value).is_absolute():
        return []
    fingerprint = _file_fingerprint(Path(value))
    return fingerprint[1:] if fingerprint[1] is not None else []


def system_hosts_file() -> Path:
    """The operating system's hosts file, which tshark reads for network names."""
    if sys.platform == "win32":
        root = os.environ.get("SYSTEMROOT", r"C:\Windows")
        return Path(root, "System32", "drivers", "etc", "hosts")
    return Path("/etc/hosts")


def index_key(
    *,
    capture: Path,
    tshark: Path,
    tshark_version: str,
    lua_scripts: Sequence[str],
    decode_as: Sequence[str],
    prefs: Mapping[str, Any],
    columns: Sequence[str],
    config: Sequence[Any],
    names: str | None = None,
) -> str:
    """The cache key of a capture's index (a hex digest), or raises OSError if
    the capture can't be read."""
    st = capture.stat()
    parts = {
        "format": CACHE_FORMAT,
        "capture": [str(capture.resolve()), st.st_size, st.st_mtime_ns, st.st_ino],
        "tshark": [str(tshark.resolve()), tshark_version],
        "lua": [[s, _sha256(Path(s))] for s in lua_scripts],
        "decodeAs": list(decode_as),
        # A preference naming a file (e.g. tls.keylog_file) depends on its contents too.
        "prefs": sorted([str(k), str(v), *_pref_file(v)] for k, v in prefs.items()),
        "columns": list(columns),
        "config": list(config),
        # Name resolution; network names also come from the system's hosts file
        # (the personal one is in ``config``).
        "names": [
            names,
            *(_file_fingerprint(system_hosts_file()) if names and "n" in names else []),
        ],
    }
    blob = json.dumps(parts, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(blob).hexdigest()


def filter_key(expr: str) -> str:
    """Short digest of a display filter, naming its results file."""
    return hashlib.sha256(expr.encode()).hexdigest()[:24]


def rules_key(rules: Any) -> str:
    """Short digest of a coloring-rules list, naming its colors file."""
    blob = json.dumps(rules, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(blob).hexdigest()[:24]


class IndexCache:
    def __init__(self, root: Path, max_bytes: int) -> None:
        self.root = root
        self.max_bytes = max_bytes

    def _entry(self, key: str) -> Path:
        if not key.isalnum():
            raise ValueError("bad cache key")
        return self.root / key

    def load(self, key: str) -> CachedIndex | None:
        """The saved index for ``key``, complete or not (see ``complete``), or
        None (missing or unreadable)."""
        entry = self._entry(key)
        try:
            meta = json.loads((entry / "meta.json").read_text(encoding="utf-8"))
            if meta.get("format") != CACHE_FORMAT:
                return None
            offsets = array("Q")
            offsets.frombytes((entry / "offsets.bin").read_bytes())
            rows = entry / "rows.tsv"
            if (
                len(offsets) != meta.get("rows")
                or meta.get("frames") != len(offsets)
                or not isinstance(meta.get("complete"), bool)
                or not rows.is_file()
            ):
                return None
            os.utime(entry / "meta.json")  # most recently used
        except OSError, ValueError, TypeError:
            return None
        return CachedIndex(rows, offsets, meta)

    def save(
        self,
        key: str,
        rows: Path,
        offsets: array[int],
        meta: Mapping[str, Any],
        *,
        complete: bool,
    ) -> bool:
        """Save an index (``rows`` is copied, or hard-linked when possible):
        ``complete``, or the rows a closed streaming open had indexed. Either
        replaces the entry as a whole (colors and filter results included)."""
        entry = self._entry(key)
        tmp = self.root / f".{key}.{os.getpid()}.tmp"
        try:
            self.root.mkdir(parents=True, exist_ok=True)
            shutil.rmtree(tmp, ignore_errors=True)
            tmp.mkdir()
            try:
                os.link(rows, tmp / "rows.tsv")
            except OSError:  # another filesystem, or no hard links
                shutil.copyfile(rows, tmp / "rows.tsv")
            (tmp / "offsets.bin").write_bytes(offsets.tobytes())
            full = {
                **meta,
                "format": CACHE_FORMAT,
                "rows": len(offsets),
                "frames": len(offsets),
                "complete": complete,
            }
            (tmp / "meta.json").write_text(json.dumps(full), encoding="utf-8")
            shutil.rmtree(entry, ignore_errors=True)
            tmp.rename(entry)
        except OSError as exc:
            _log(f"could not save an index: {exc}")
            shutil.rmtree(tmp, ignore_errors=True)
            return False
        self.prune()
        return True

    def load_colors(
        self, key: str, rules: str, frames: int
    ) -> tuple[array[int], dict[str, Any]] | None:
        """Saved coloring result: one rule byte per frame, and its ``{colored, errors}``."""
        entry = self._entry(key)
        if not self._complete(entry):
            return None
        try:
            data = (entry / f"colors-{rules}.bin").read_bytes()
            extra = json.loads((entry / f"colors-{rules}.json").read_text(encoding="utf-8"))
        except OSError, ValueError:
            return None
        if len(data) != frames + 1 or not isinstance(extra, dict):
            return None
        return array("B", data), extra

    def save_colors(
        self, key: str, rules: str, colors: array[int], extra: Mapping[str, Any]
    ) -> None:
        entry = self._entry(key)
        if not self._complete(entry):
            return  # no finished index saved for this capture (yet)
        try:
            for suffix, data in ((".json", json.dumps(extra).encode()), (".bin", colors.tobytes())):
                tmp = entry / f".colors-{rules}{suffix}.{os.getpid()}.tmp"
                tmp.write_bytes(data)
                tmp.replace(entry / f"colors-{rules}{suffix}")
            kept = sorted(entry.glob("colors-*.bin"), key=lambda p: p.stat().st_mtime)
            for old in kept[:-MAX_COLORINGS]:
                old.unlink(missing_ok=True)
                old.with_suffix(".json").unlink(missing_ok=True)
        except OSError as exc:
            _log(f"could not save colors: {exc}")

    def load_filter(self, key: str, expr: str, frames: int) -> array[int] | None:
        """Saved matches of display filter ``expr`` (ascending frame numbers)."""
        entry = self._entry(key)
        if not self._complete(entry):
            return None
        path = entry / f"filter-{filter_key(expr)}.bin"
        try:
            data = path.read_bytes()
            os.utime(path)  # most recently used filter of this entry
        except OSError:
            return None
        if len(data) % 4:
            return None
        matched = array("I")
        matched.frombytes(data)
        if matched and not 1 <= matched[0] <= matched[-1] <= frames:
            return None
        return matched

    def save_filter(self, key: str, expr: str, matched: array[int]) -> None:
        """Save a display filter's matches; only the MAX_FILTERS most recent stay."""
        entry = self._entry(key)
        if not self._complete(entry):
            return  # no finished index saved for this capture (yet)
        name = f"filter-{filter_key(expr)}.bin"
        try:
            tmp = entry / f".{name}.{os.getpid()}.tmp"
            tmp.write_bytes(matched.tobytes())
            tmp.replace(entry / name)
            kept = sorted(entry.glob("filter-*.bin"), key=lambda p: p.stat().st_mtime)
            for old in kept[:-MAX_FILTERS]:
                old.unlink(missing_ok=True)
        except OSError as exc:
            _log(f"could not save filter results: {exc}")
            return
        self.prune()

    @staticmethod
    def _complete(entry: Path) -> bool:
        """Whether ``entry`` holds a finished index (colors and filter results
        belong only to those: an incomplete entry's frame count grows)."""
        try:
            meta = json.loads((entry / "meta.json").read_text(encoding="utf-8"))
        except OSError, ValueError:
            return False
        return (
            isinstance(meta, dict)
            and meta.get("format") == CACHE_FORMAT
            and meta.get("complete") is True
        )

    def discard(self, key: str) -> None:
        """Remove ``key``'s entry (an incomplete one that no longer matches)."""
        with contextlib.suppress(OSError):
            shutil.rmtree(self._entry(key))

    def entries(self) -> list[tuple[Path, float, int]]:
        """(folder, last use, size in bytes) of every entry."""
        out: list[tuple[Path, float, int]] = []
        if not self.root.is_dir():
            return out
        for entry in self.root.iterdir():
            if entry.name.startswith(".") or not entry.is_dir():
                continue
            try:
                used = (entry / "meta.json").stat().st_mtime
                size = sum(f.stat().st_size for f in entry.iterdir() if f.is_file())
            except OSError:
                continue
            out.append((entry, used, size))
        return out

    def prune(self) -> None:
        """Remove the least recently used entries until the total fits ``max_bytes``."""
        entries = sorted(self.entries(), key=lambda e: e[1])
        total = sum(size for _, _, size in entries)
        for entry, _used, size in entries:
            if total <= self.max_bytes:
                break
            with contextlib.suppress(OSError):
                shutil.rmtree(entry)
                total -= size

    def clear(self) -> tuple[int, int]:
        """Remove every entry; returns (entries, bytes) removed."""
        removed = freed = 0
        for entry, _used, size in self.entries():
            with contextlib.suppress(OSError):
                shutil.rmtree(entry)
                removed += 1
                freed += size
        return removed, freed
