"""Capture-file service: indexing, filtering, paging, sorting and packet detail.

One ``PcapService`` serves one capture file (the extension starts one backend
process per open editor). All heavy lifting is delegated to tshark:

* ``open`` runs a single ``-T fields`` pass and stores the packet-list columns
  on disk (:class:`~pcap_backend.cache.RowStore`).
* ``set_filter`` runs ``-Y <expr> -T fields -e frame.number`` once and keeps the
  matching frame numbers; scrolling never re-runs tshark. With ``stream`` the
  matches are shown as they come ("filter" notifications report the pass).
* ``packet_detail`` runs ``-T pdml`` and ``-x`` for one frame, reading only up
  to that frame (``-c N``) so dissection state from earlier packets (TCP
  reassembly etc.) is still correct.
* ``set_coloring`` runs one ``--color`` pass and keeps a one-byte rule index
  per frame; ``list_packets`` rows then carry their ``color``. ``open`` can
  evaluate the rules in its own pass instead (``coloring``), so colors come
  with the rows.
* ``export`` writes filtered captures with tshark (``-Y … -w``) and the packet
  list (CSV/JSON) straight from the row store.
"""

import itertools
import os
import re
import shutil
import sys
import tempfile
import threading
import time
from array import array
from bisect import bisect_left, bisect_right
from collections.abc import Callable, Iterable, Sequence
from concurrent.futures import Future, ThreadPoolExecutor
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from . import coloring, navigation, objects, pdml, stats
from .cache import FrameIndex, LruCache, RowStore, sort_frames, sort_frames_by_key
from .cancellation import CancelledError, CancelToken
from .export import (
    CAPTURE_FORMATS,
    DISSECTION_FORMATS,
    EXPORT_KINDS,
    LIST_FORMATS,
    DissectionWriter,
    PacketListWriter,
    atomic_output,
    check_destination,
)
from .fields import FieldCatalog, parse_field_list
from .index_cache import IndexCache, folder_fingerprint, index_key, rules_key
from .objects import ExportedObject
from .protocol import (
    FilterError,
    IndexingError,
    InvalidParamsError,
    NotOpenError,
    RequestContext,
    RpcError,
    UnsupportedFormatError,
    param,
    str_list,
)
from .tshark import (
    EMPTY_CAPTURE,
    DissectionOptions,
    StreamResult,
    ToolError,
    ToolNotFoundError,
    Tshark,
    find_tool,
    run,
    stream_lines,
)

MAX_PAGE = 5000
EXPORT_CHUNK = 5000
# Longest display filter passed as one argv entry (Windows caps the whole command
# line at 32767 characters). Bigger marked-packet exports run in chunks + mergecap.
MAX_FILTER_ARG = 16_000
NEIGHBOR_CHUNK = 2000
# Quick detail: packets dissected before the one asked for (see _quick_detail).
QUICK_WINDOW = 300
MIN_QUICK_WINDOW = 2
MAX_QUICK_WINDOW = 5000
# FT_FRAMENUM fields by name, while the field catalogue is still loading.
_FRAMENUM_HINT = re.compile(
    r"\.(?:request_in|response_in|response_to|prev_request_in|next_request_in|reassembled_in"
    r"|segment|fragment|acks_frame|duplicate_ack_frame|retransmitted_in|retransmission_of)$"
)
# Most frames one request may name or return (multi-selection: Shift+click ranges,
# copy, export). 4 bytes each in the backend, ~8 in JSON.
MAX_SELECTION = 1_000_000
PROGRESS_INTERVAL_S = 0.2
# Streaming open: `open` returns once this many rows are indexed (or after
# FIRST_BATCH_S with at least one), and the pass goes on in the background.
FIRST_BATCH = 1000
FIRST_BATCH_S = 0.5
DEFAULT_CACHE_BYTES = 1 << 30


@dataclass(frozen=True, slots=True)
class Column:
    id: str
    title: str
    field: str
    legacy_field: str
    numeric: bool = False
    addresses: bool = False  # sort IPv4/IPv6/MAC numerically (cache.address_key)


BASE_COLUMNS: tuple[Column, ...] = (
    Column("number", "No.", "frame.number", "frame.number", numeric=True),
    Column("time", "Time", "frame.time_relative", "frame.time_relative", numeric=True),
    Column("source", "Source", "_ws.col.def_src", "_ws.col.Source", addresses=True),
    Column("destination", "Destination", "_ws.col.def_dst", "_ws.col.Destination", addresses=True),
    Column("protocol", "Protocol", "_ws.col.protocol", "_ws.col.Protocol"),
    Column("length", "Length", "frame.len", "frame.len", numeric=True),
    Column("info", "Info", "_ws.col.info", "_ws.col.Info"),
)
# With name resolution, Source/Destination can show names; the index pass then
# also stores the addresses (blank when the same as shown) for cell filters.
# These column fields exist only for columns in gui.column.format, which must
# then list every column field used (titles = the legacy field names).
UNRESOLVED_FIELDS = ("_ws.col.unres_src", "_ws.col.unres_dst")
_UNRESOLVED_FORMAT = (
    'gui.column.format:"Source","%s","Destination","%d","Protocol","%p","Info","%i",'
    '"unres_src","%us","unres_dst","%ud"'
)
_TIME_IDX = 1  # position of frame.time_relative in BASE_COLUMNS
_LEN_IDX = 5  # position of frame.len in BASE_COLUMNS
_TIME_FIELD = "frame.time_relative"
# Time column sort keys that differ from capture order: the time format's deltas.
# Internal sort "fields" (never valid field names, so no clash with real ones).
_DELTA_SORTS = {"delta_displayed": "@delta_displayed", "delta_captured": "@delta_captured"}
_ADDRESS_TYPES = frozenset({"FT_IPv4", "FT_IPv6", "FT_ETHER"})

_FIELD_NAME_RE = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_.\-]*$")
_INVALID_FIELDS_RE = re.compile(r"Some fields aren't valid:\s*(?P<names>(?:\s*\S+)+)")
_TRUNCATION_HINTS = ("cut short", "appears to be damaged", "corrupt", "truncated")

# Per-record overhead used to estimate progress from frame lengths. Only valid
# for uncompressed pcap/pcapng (recognised by magic number, whatever the file is
# called); other formats and compressed files get indeterminate progress.
_RECORD_OVERHEAD = {"pcap": 16, "pcapng": 32}
_PCAP_MAGICS = frozenset(
    bytes.fromhex(m)
    for m in ("d4c3b2a1", "a1b2c3d4", "4d3cb2a1", "a1b23c4d", "34cdb2a1", "a1b2cd34")
)
_PCAPNG_MAGIC = bytes.fromhex("0a0d0d0a")
_UNSUPPORTED_RE = re.compile(r"isn't a capture file in a format TShark understands")


def sniff_format(path: Path) -> str | None:
    """``"pcap"`` or ``"pcapng"`` for uncompressed files of those formats, else None."""
    try:
        with path.open("rb") as fh:
            head = fh.read(4)
    except OSError:
        return None
    if head in _PCAP_MAGICS:
        return "pcap"
    return "pcapng" if head == _PCAPNG_MAGIC else None


def _fields_args(fields: Sequence[str]) -> list[str]:
    args = [
        "-T", "fields",
        "-E", "separator=/t",
        "-E", "occurrence=a",
        "-E", "aggregator=,",
        "-E", "quote=n",
    ]  # fmt: skip
    for f in fields:
        args += ["-e", f]
    return args


@dataclass(slots=True)
class CaptureInfo:
    path: str
    frames: int = 0
    start_time: float | None = None
    end_time: float | None = None
    link_type: str | None = None
    file_type: str | None = None
    size: int = 0
    warnings: list[str] = field(default_factory=list)

    def to_json(self) -> dict[str, Any]:
        return {
            "path": self.path,
            "frames": self.frames,
            "startTime": self.start_time,
            "endTime": self.end_time,
            "linkType": self.link_type,
            "fileType": self.file_type,
            "size": self.size,
            "warnings": self.warnings,
        }


@dataclass(slots=True)
class _Store:
    """A row store and the requested field each of its columns serves."""

    rows: RowStore
    fields: tuple[str, ...]  # user-facing field names, parallel to rows.fields


@dataclass(slots=True)
class _Open:
    path: Path
    tshark: Tshark
    info: CaptureInfo
    base: _Store
    extra: list[_Store] = field(default_factory=list)
    columns: list[str] = field(default_factory=list)  # custom column fields
    # Fields tshark refused ("Some fields aren't valid"); never re-run tshark for them.
    rejected: set[str] = field(default_factory=set)
    # Saved-index cache and this capture's key in it (None: not cached).
    cache: IndexCache | None = None
    cache_key: str | None = None

    def frame_count(self) -> int:
        """Frames known so far: during a streaming open, the rows published
        already, even before the view (and ``info.frames``) caught up."""
        return max(self.info.frames, len(self.base.rows))


class _PassProgress:
    """Per-row bookkeeping of an index pass: progress (from frame lengths vs
    file size when the format allows), publishing rows as they come, and the
    first batch for a streaming open."""

    def __init__(
        self,
        ctx: RequestContext,
        store: _Store,
        on_rows: Callable[[_Store], None] | None,
        size: int,
        overhead: int | None,
    ) -> None:
        self.ctx = ctx
        self.store = store
        self.on_rows = on_rows
        self.size = size
        self.overhead = overhead
        self.bytes_seen = 0
        self.last_emit = 0.0
        self.started = time.monotonic()

    def row(self, number: int, rest: bytes) -> None:
        rows = self.store.rows
        if self.overhead:
            cells = rest.split(b"\t", _LEN_IDX + 1)
            if len(cells) > _LEN_IDX and cells[_LEN_IDX].isdigit():
                self.bytes_seen += int(cells[_LEN_IDX]) + self.overhead
        now = time.monotonic()
        if now - self.last_emit >= PROGRESS_INTERVAL_S:
            self.last_emit = now
            rows.publish()
            fraction = min(0.99, self.bytes_seen / self.size) if self.overhead else None
            self.ctx.progress({"phase": "index", "frames": number, "fraction": fraction})
        if self.on_rows is not None and (
            rows.appended >= FIRST_BATCH or now - self.started >= FIRST_BATCH_S
        ):
            on_rows, self.on_rows = self.on_rows, None
            rows.publish()
            on_rows(self.store)


@dataclass(slots=True)
class _InlineColoring:
    """Coloring rules evaluated by the index pass itself (``open {coloring}``):
    ``--color`` and ``frame.coloring_rule.name`` as a last field, so every row
    comes with its color. About 6% on the index pass instead of a second pass."""

    raw: list[Any]  # the rules as given (their digest names the saved colors)
    rules: list[coloring.ColorRule | str]
    errors: dict[int, str]  # malformed rules, then tshark's compile errors
    # Rule index + 1 per frame (0 = none), index 0 unused; grows with the rows.
    colors: array[int] = field(default_factory=lambda: array("B", [0]))
    colored: int = 0
    coloring_id: int = 0
    enabled: bool = True  # False if tshark rejected the field (the pass ran without)

    def summary(self) -> dict[str, Any]:
        return {
            "coloringId": self.coloring_id,
            "colored": self.colored,
            "errors": {str(i): m for i, m in sorted(self.errors.items())},
        }


@dataclass(slots=True)
class _Indexing:
    """A (streaming) index pass running in the background."""

    token: CancelToken
    report: Callable[[Any], None]
    first: threading.Event = field(default_factory=threading.Event)  # rows to show
    done: threading.Event = field(default_factory=threading.Event)
    store: _Store | None = None
    error: BaseException | None = None
    future: Future[None] | None = None
    # `open` returned while the pass was running: finishing it updates the capture.
    attached: bool = False
    inline: _InlineColoring | None = None


@dataclass(slots=True)
class _Filtering:
    """A streaming filter pass (``set_filter {stream: true}``) in the background.

    The pass appends matches to ``frames``; ``snapshot`` is the copy the view
    shows (taken every progress tick, so readers never see the array grow).
    While a streaming open is still indexing, the view shows only the matches
    among the rows published so far, even after the pass is done.
    """

    expr: str
    token: CancelToken = field(default_factory=CancelToken)
    frames: array[int] = field(default_factory=lambda: array("I"))
    snapshot: FrameIndex = field(default_factory=lambda: FrameIndex.of(()))
    version: int = 0  # bumped with every snapshot
    shown: tuple[int, int] = (-1, -1)  # (version, matches) the view shows
    fraction: float | None = None
    running: bool = True
    done: threading.Event = field(default_factory=threading.Event)
    future: Future[None] | None = None


@dataclass(slots=True)
class _View:
    filter_id: int
    expr: str
    matched: FrameIndex
    sort: tuple[str, bool] | None
    ordered: FrameIndex
    # Streaming filter: matches still arriving (or clipped to a streaming open's rows).
    live: _Filtering | None = None
    # The filter pass stopped early ("stopped", or tshark's error): matches so far.
    partial: str | None = None


class PcapService:
    def __init__(self, max_cached_frames: int = 5_000_000, detail_cache_size: int = 64) -> None:
        self._lock = threading.RLock()
        # Serialises expensive derived-data builds (sort orders, extra columns) so
        # concurrent page requests don't each redo the same tshark pass or sort.
        self._build_lock = threading.RLock()
        self._tshark: Tshark | None = None
        self._file: _Open | None = None
        self._view: _View | None = None
        self._work_dir: Path | None = None
        # Export Objects: (the capture they came from, the objects), and a lock
        # so concurrent requests extract once.
        self._objects: tuple[_Open, list[ExportedObject]] | None = None
        self._objects_lock = threading.Lock()
        self._filter_seq = 0
        self._next_filter_id = 0
        self._store_seq = 0
        self._filters: LruCache[str, FrameIndex] = LruCache(max_cached_frames, lambda v: v.cost)
        self._sorts: LruCache[tuple[str, str, bool], FrameIndex] = LruCache(
            max_cached_frames, lambda v: v.cost
        )
        self._sort_columns: LruCache[str, list[str]] = LruCache(2)
        self._details: LruCache[int, dict[str, Any]] = LruCache(detail_cache_size)
        # Quick (approximate) details by (frame, window); see _quick_detail.
        self._quick: LruCache[tuple[int, int], dict[str, Any]] = LruCache(16)
        self._quick_seq = itertools.count()
        self._catalog_warming = threading.Event()
        self._field_index: LruCache[tuple[str, ...], FieldCatalog] = LruCache(2)
        self._decode_as: LruCache[str, list[dict[str, str]]] = LruCache(32)
        # Coloring: rule index + 1 per frame (0 = no rule), from the latest set_coloring.
        self._colors: array[int] | None = None
        self._coloring_id = 0
        self._coloring_seq = 0
        # Marked frames (Wireshark's Ctrl+M): per session, not persisted.
        self._marks: set[int] = set()
        # Streaming open: the index pass still running after `open` returned.
        self._indexing: _Indexing | None = None
        self._tshark_versions: dict[Path, str] = {}
        # Backend -> client notifications ("index": progress/done/failed of a streaming open).
        self.notify: Callable[[str, dict[str, Any]], None] = lambda _method, _params: None
        self._pool = ThreadPoolExecutor(max_workers=4, thread_name_prefix="svc")

    # ------------------------------------------------------------------ lifecycle

    def initialize(self, params: dict[str, Any], _ctx: RequestContext) -> dict[str, Any]:
        """Locate tshark/capinfos. Must be called before ``open``."""
        tshark = Tshark.locate(params.get("tsharkPath") or None, params.get("capinfosPath") or None)
        version = tshark.version()
        with self._lock:
            self._tshark = tshark
        return {
            "tsharkPath": str(tshark.path),
            "capinfosPath": str(tshark.capinfos) if tshark.capinfos else None,
            "version": version,
        }

    def close(self, _params: dict[str, Any] | None = None, _ctx: Any = None) -> dict[str, Any]:
        with self._lock:
            self._close_file()
        return {"ok": True}

    def shutdown(self) -> None:
        self.close()
        EMPTY_CAPTURE.remove()
        self._pool.shutdown(wait=False, cancel_futures=True)

    def _close_file(self) -> None:
        live = self._view.live if self._view is not None else None
        self._view = None  # (so a stopped filter pass reports nothing)
        if live is not None and live.running:
            live.token.cancel()
            self._wait_unlocked(live.future)
        indexing, self._indexing = self._indexing, None
        if indexing is not None:
            indexing.token.cancel()
            self._wait_unlocked(indexing.future)
        if self._file is not None:
            self._file.base.rows.close()
            for s in self._file.extra:
                s.rows.close()
        self._file = None
        self._view = None
        self._objects = None
        self._colors = None
        self._marks = set()
        for cache in (self._filters, self._sorts, self._sort_columns, self._details, self._quick):
            cache.clear()
        if self._work_dir is not None:
            shutil.rmtree(self._work_dir, ignore_errors=True)
            self._work_dir = None

    def _wait_unlocked(self, future: Future[None] | None) -> None:
        """Wait for a cancelled background pass (it takes the lock to finish)."""
        if future is None:
            return
        self._lock.release()
        try:
            future.result(timeout=30)
        except Exception:  # noqa: S110 - it was cancelled; errors don't matter now
            pass
        finally:
            self._lock.acquire()

    def _require_tshark(self) -> Tshark:
        with self._lock:
            if self._tshark is None:
                self._tshark = Tshark.locate()
            return self._tshark

    def _require_file(self) -> _Open:
        with self._lock:
            if self._file is None:
                raise NotOpenError()
            return self._file

    def _require_view(self) -> tuple[_Open, _View]:
        with self._lock:
            if self._file is None or self._view is None:
                raise NotOpenError()
            view = self._view
            indexing = self._indexing is not None
            if indexing and not view.expr and view.sort is None:
                # Streaming: the unfiltered view grows with the index pass.
                n = len(self._file.base.rows)
                if len(view.matched) != n:
                    view.matched = view.ordered = FrameIndex.all(n)
                    self._file.info.frames = n
            live = view.live
            if live is not None:
                # Streaming filter: show the latest snapshot, limited to the rows
                # a streaming open has published so far.
                src = live.snapshot
                k = len(src)
                if indexing and k:
                    k = bisect_right(src.frames(), len(self._file.base.rows))
                if live.shown != (live.version, k):
                    live.shown = (live.version, k)
                    shown = src if k == len(src) else FrameIndex.of(src.frames()[:k])
                    view.matched = view.ordered = shown
                if not live.running and not indexing:
                    view.live = None  # final: sorting etc. work from now on
                    if view.partial is None:
                        self._filters.put(view.expr, view.matched)
            return self._file, view

    def _require_indexed(self) -> None:
        """Raise IndexingError while a streaming index pass is still running."""
        with self._lock:
            if self._indexing is not None and self._file is not None:
                raise IndexingError(len(self._file.base.rows))

    def _require_complete(self) -> None:
        """Raise IndexingError while the capture is indexed or the view's filter
        runs (for what needs the whole view: sorting, find, export in view order…)."""
        self._require_indexed()
        with self._lock:
            view = self._view
            if view is not None and view.live is not None and view.live.running:
                raise IndexingError(len(view.matched), filtering=True)

    def _install_view(self, view: _View) -> None:
        """Make ``view`` current (under the lock), stopping a streaming filter it replaces."""
        old = self._view
        if old is not None and old is not view and old.live is not None and old.live.running:
            old.live.token.cancel()
        self._view = view

    # ------------------------------------------------------------------ open

    def open(self, params: dict[str, Any], ctx: RequestContext) -> dict[str, Any]:
        """Index a capture file for the packet list.

        ``cache: {dir, maxBytes}`` reuses a saved index when nothing that
        changes it did (``fromCache: true``), and saves new ones. ``stream:
        true`` returns once the first rows are indexed (``indexing: true``);
        the pass goes on in the background and "index" notifications report
        its progress and end ("progress", then "done" with the final result,
        or "failed"). Until then the unfiltered list grows as rows arrive, and
        what needs every row (sorting, find…) raises IndexingError.

        ``coloring: {rules}`` (as for set_coloring) evaluates the coloring rules
        in the index pass, so rows come with their ``color``; the result (and
        "done") then carries ``coloring: {coloringId, colored, errors}``. From a
        saved index, the colors saved for these rules are used, if any (else no
        ``coloring``: run set_coloring).
        """
        path = _readable_capture(param(params, "path", str))
        options = DissectionOptions.from_params(
            str_list(params, "lua"),
            str_list(params, "decodeAs"),
            param(params, "prefs", dict, {}),
            _names_param(params),
        )
        base_fields = {c.field for c in BASE_COLUMNS}
        columns = [
            c for c in self._check_fields(str_list(params, "columns")) if c not in base_fields
        ]
        requested_columns = list(columns)  # _index_pass removes fields tshark rejects
        tshark = self._require_tshark().with_options(options)
        stream = bool(params.get("stream"))
        cache = _cache_from(params.get("cache"))
        inline = _inline_coloring(params.get("coloring"))

        with self._lock:
            self._close_file()
            self._work_dir = Path(tempfile.mkdtemp(prefix="pcapviewer-"))
            work_dir = self._work_dir

        info = CaptureInfo(path=str(path), size=path.stat().st_size)
        info.warnings += options.check_scripts()
        key = self._index_key(tshark, path, options, requested_columns, ctx) if cache else None
        if cache is not None and key is not None:
            hit = cache.load(key)
            if hit is not None:
                return self._open_cached(path, tshark, hit, work_dir, cache, key, inline)

        info_future = self._pool.submit(self._capinfos, tshark, path, ctx.token)
        indexing = _Indexing(token=CancelToken(), report=ctx.progress, inline=inline)
        ctx.token.on_cancel(indexing.token.cancel)
        indexing.future = self._pool.submit(
            self._run_index, tshark, path, work_dir, columns, info, info_future, indexing,
            cache, key,
        )  # fmt: skip
        wait_for = indexing.first if stream else indexing.done
        while not wait_for.wait(0.1):
            ctx.token.raise_if_cancelled()
        ctx.token.raise_if_cancelled()
        with self._lock:
            if indexing.error is not None:
                raise indexing.error
            assert indexing.store is not None
            complete = indexing.done.is_set()
            self._file = _Open(
                path,
                tshark,
                info,
                indexing.store,
                columns=columns,
                rejected={c for c in requested_columns if c not in columns},
                cache=cache,
                cache_key=key,
            )
            if not complete:
                info.frames = len(indexing.store.rows)
                indexing.attached = True
                indexing.report = self._index_progress
                self._indexing = indexing
            self._next_filter_id += 1
            everything = FrameIndex.all(info.frames)
            self._view = _View(self._next_filter_id, "", everything, None, everything)
            result = self._open_result(self._file, indexing=not complete)
            if inline is not None and inline.enabled:
                self._show_colors(inline, inline.colors)
                # (The pass keeps appending to inline.colors: published rows have theirs.)
                result["coloring"] = (
                    inline.summary() if complete else {"coloringId": inline.coloring_id}
                )
            return result

    def _show_colors(self, inline: _InlineColoring, colors: array[int]) -> None:
        """Make ``colors`` the list's coloring (under the lock)."""
        self._coloring_id += 1
        inline.coloring_id = self._coloring_id
        self._colors = colors

    def _open_result(self, f: _Open, *, indexing: bool = False) -> dict[str, Any]:
        result = f.info.to_json()
        result["columns"] = self._column_descriptors(f.columns)
        result["filterId"] = self._view.filter_id if self._view else 0
        result["indexing"] = indexing
        return result

    def _run_index(
        self,
        tshark: Tshark,
        path: Path,
        work_dir: Path,
        columns: list[str],
        info: CaptureInfo,
        info_future: Future[dict[str, Any]],
        indexing: _Indexing,
        cache: IndexCache | None,
        key: str | None,
    ) -> None:
        """The index pass (in the pool). Rows become visible as they come
        (``indexing.first`` once there are some); finishing it completes the
        capture's info, updates an attached (streaming) capture and saves the index."""
        # Not `progress=indexing.report`: open() swaps it for notifications when it returns.
        ctx = RequestContext(token=indexing.token, progress=lambda p: indexing.report(p))  # noqa: PLW0108

        def rows_ready(store: _Store) -> None:
            indexing.store = store
            indexing.first.set()

        try:
            base = self._index_pass(
                tshark, path, work_dir, columns, info, ctx, base=True, on_rows=rows_ready,
                inline=indexing.inline,
            )  # fmt: skip
            indexing.store = base
            meta = info_future.result()
            for name in ("start_time", "end_time", "link_type", "file_type"):
                if getattr(info, name) is None and meta.get(name) is not None:
                    setattr(info, name, meta[name])
            if info.start_time is None and len(base.rows):
                info.start_time = self._first_epoch(tshark, path, indexing.token)
        except BaseException as exc:  # handed to `open` or the client
            indexing.error = exc
        with self._lock:
            if indexing.error is None:
                assert indexing.store is not None
                info.frames = len(indexing.store.rows)
            indexing.done.set()
            indexing.first.set()
            attached = indexing.attached and self._indexing is indexing
            if attached:
                self._indexing = None
                done = self._finish_streaming(indexing)
        if attached:
            self.notify("index", done)
        if indexing.error is None and cache is not None and key is not None:
            store = indexing.store
            assert store is not None
            cache.save(
                key,
                store.rows.path,
                store.rows.offsets,
                {
                    "info": info.to_json(),
                    "fields": list(store.rows.fields),
                    "names": list(store.fields),
                    "columns": columns,
                },
            )
            inline = indexing.inline
            if inline is not None and inline.enabled:
                extra = {"colored": inline.colored, "errors": inline.summary()["errors"]}
                cache.save_colors(key, rules_key(inline.raw), inline.colors, extra)

    def _index_progress(self, progress: Any) -> None:
        """A streaming open's "index" progress notification. With a filter
        applied, ``view`` says how many of its matches are shown by now."""
        event = {"event": "progress", **progress}
        with self._lock:
            view = self._view_counts()
        if view is not None:
            event["view"] = view
        self.notify("index", event)

    def _view_counts(self) -> dict[str, Any] | None:
        """``{filterId, matchCount}`` of the current filtered view (under the lock)."""
        if self._file is None or self._view is None or not self._view.expr:
            return None
        _f, view = self._require_view()
        return {"filterId": view.filter_id, "matchCount": len(view.matched)}

    def _finish_streaming(self, indexing: _Indexing) -> dict[str, Any]:
        """The end of a streaming index pass: update the capture (under the lock)
        and return the "index" notification to send."""
        f = self._file
        if f is None:
            return {"event": "failed", "message": "the capture was closed"}
        if indexing.error is not None:
            if isinstance(indexing.error, CancelledError):
                return {"event": "failed", "message": "indexing was cancelled"}
            message = str(indexing.error) or type(indexing.error).__name__
            f.info.warnings.append(
                f"Indexing stopped after {len(f.base.rows):,} packets: {message}"
            )
            f.info.frames = len(f.base.rows)
            failed = {"event": "failed", "message": message, "info": self._open_result(f)}
            counts = self._view_counts()
            if counts is not None:
                failed["view"] = counts
            return failed
        view = self._view
        if view is not None and not view.expr and view.sort is None:
            view.matched = view.ordered = FrameIndex.all(f.info.frames)
        done: dict[str, Any] = {"event": "done", "info": self._open_result(f)}
        inline = indexing.inline
        if inline is not None and inline.enabled and inline.coloring_id == self._coloring_id:
            done["coloring"] = inline.summary()
        counts = self._view_counts()
        if counts is not None:
            done["view"] = counts
        return done

    def _open_cached(
        self,
        path: Path,
        tshark: Tshark,
        hit: Any,
        work_dir: Path,
        cache: IndexCache,
        key: str,
        inline: _InlineColoring | None = None,
    ) -> dict[str, Any]:
        """Open from a saved index: no tshark pass at all (and the colors saved
        for these coloring rules, if any)."""
        meta = hit.meta
        rows_path = work_dir / "rows-cached.tsv"
        try:
            os.link(hit.rows, rows_path)  # instant, and safe if the cache entry goes away
        except OSError:
            shutil.copyfile(hit.rows, rows_path)
        store = _Store(RowStore(rows_path, meta["fields"], hit.offsets), tuple(meta["names"]))
        saved = meta["info"]
        info = CaptureInfo(
            path=str(path),
            frames=len(store.rows),
            start_time=saved.get("startTime"),
            end_time=saved.get("endTime"),
            link_type=saved.get("linkType"),
            file_type=saved.get("fileType"),
            size=path.stat().st_size,
            warnings=list(saved.get("warnings", [])),
        )
        columns = list(meta.get("columns", []))
        with self._lock:
            self._file = _Open(
                path, tshark, info, store, columns=columns, cache=cache, cache_key=key
            )
            self._next_filter_id += 1
            everything = FrameIndex.all(info.frames)
            self._view = _View(self._next_filter_id, "", everything, None, everything)
            result = self._open_result(self._file)
            saved_colors = (
                cache.load_colors(key, rules_key(inline.raw), info.frames) if inline else None
            )
            if inline is not None and saved_colors is not None:
                colors, extra = saved_colors
                self._show_colors(inline, colors)
                inline.colored = int(extra.get("colored", 0))
                inline.errors.update({int(i): str(m) for i, m in extra.get("errors", {}).items()})
                result["coloring"] = inline.summary()
        result["fromCache"] = True
        return result

    def _index_key(
        self,
        tshark: Tshark,
        path: Path,
        options: DissectionOptions,
        columns: list[str],
        ctx: RequestContext,
    ) -> str | None:
        """The saved-index key of this capture with these settings (None if it
        can't be computed: then the index is neither loaded nor saved)."""
        try:
            version = self._tshark_versions.get(tshark.path)
            if version is None:
                version = tshark.version()
                self._tshark_versions[tshark.path] = version
            folders = _personal_folders(tshark.folders(ctx.token))
            return index_key(
                capture=path,
                tshark=tshark.path,
                tshark_version=version,
                lua_scripts=list(options.lua_scripts),
                decode_as=list(options.decode_as),
                prefs=dict(options.prefs),
                columns=columns,
                config=folder_fingerprint(folders),
                names=options.names,
            )
        except (OSError, ToolError) as exc:
            print(f"pcap-viewer: index cache off for this capture: {exc}", file=sys.stderr)
            return None

    def _column_descriptors(self, custom: Sequence[str]) -> list[dict[str, Any]]:
        cols: list[dict[str, Any]] = [
            {"id": c.id, "title": c.title, "field": c.field, "numeric": c.numeric}
            for c in BASE_COLUMNS
        ]
        cols += [{"id": f, "title": f, "field": f, "numeric": False} for f in custom]
        return cols

    @staticmethod
    def _check_fields(fields: Iterable[str]) -> list[str]:
        out: list[str] = []
        for raw in fields:
            name = raw.strip()
            if not name:
                continue
            if not _FIELD_NAME_RE.match(name):
                raise InvalidParamsError(f"invalid field name {name!r}")
            if name not in out:
                out.append(name)
        return out

    def _index_pass(
        self,
        tshark: Tshark,
        path: Path,
        work_dir: Path,
        custom: list[str],
        info: CaptureInfo,
        ctx: RequestContext,
        *,
        base: bool,
        on_rows: Callable[[_Store], None] | None = None,
        inline: _InlineColoring | None = None,
    ) -> _Store:
        """Run one ``-T fields`` pass, writing every frame's row to a RowStore.

        Retries without fields tshark rejects (unknown custom columns, or the
        column field names of older tshark versions). Rows are published as
        they come; ``on_rows`` gets the store once the first ones are readable
        (FIRST_BATCH rows, or FIRST_BATCH_S with at least one). With ``inline``
        (base pass only), the coloring rules are evaluated too: the last field
        is the matching rule, kept in ``inline.colors`` (not in the row store).
        """
        # (name the caller asked for, name actually passed to tshark)
        pairs = [(c.field, c.field) for c in BASE_COLUMNS] if base else []
        pairs += [(fld, fld) for fld in custom]
        unresolved = base and tshark.options.resolves_addresses
        if unresolved:
            pairs += [(fld, fld) for fld in UNRESOLVED_FIELDS]
        legacy = {c.field: c.legacy_field for c in BASE_COLUMNS}
        size = max(1, info.size)
        overhead = _RECORD_OVERHEAD.get(sniff_format(path) or "") if base else None
        if not base:
            inline = None
        env = self._coloring_env(tshark, work_dir, inline, ctx) if inline else None
        for _attempt in range(4):
            self._store_seq += 1
            store_path = work_dir / f"rows-{self._store_seq}.tsv"
            actual = [a for _, a in pairs]
            rows = RowStore(store_path, actual)
            result = StreamResult()
            # tshark blanks duplicated -e fields, so only prepend frame.number
            # when it is not already the first column.
            fields = actual if base else ["frame.number", *actual]
            color_args: list[str] = []
            if inline is not None:
                fields = [*fields, _COLOR_FIELD]
                color_args = ["--color"]
                inline.colors, inline.colored = array("B", [0]), 0
            column_args = ["-o", _UNRESOLVED_FORMAT] if unresolved else []
            argv = tshark.argv(*column_args, *color_args, *_fields_args(fields), capture=str(path))
            store = _Store(rows, tuple(name for name, _ in pairs))
            tracker = _PassProgress(ctx, store, on_rows, size, overhead)
            try:
                lines = stream_lines(argv, result, ctx.token, env=env)
                bad_lines = _read_rows(
                    lines, rows, tracker, base=base, inline=inline, unresolved=unresolved
                )
            finally:
                rows.finish()
            if result.lines == 0 and result.returncode not in (0, None):
                rows.close()
                store_path.unlink(missing_ok=True)
                rejected = _rejected_fields(result.stderr)
                if inline is not None and _COLOR_FIELD in rejected:
                    inline.enabled, inline, env = False, None, None  # index without colors
                    continue
                if unresolved and set(UNRESOLVED_FIELDS) & set(rejected):
                    unresolved = False  # cell filters then only work on addresses shown
                    pairs = [p for p in pairs if p[1] not in UNRESOLVED_FIELDS]
                    continue
                if rejected and _drop_rejected(pairs, rejected, legacy, custom, info.warnings):
                    continue
                raise _index_error(tshark, path, result)
            _finish_index_pass(info, result, bad_lines, len(rows), inline)
            ctx.progress({"phase": "index", "frames": len(rows), "fraction": 1.0})
            # Columns are exposed under the names the caller asked for.
            return store
        raise ToolError("tshark rejected the requested columns")

    @staticmethod
    def _coloring_env(
        tshark: Tshark, work_dir: Path, inline: _InlineColoring, ctx: RequestContext
    ) -> dict[str, str]:
        """Environment for a pass that evaluates ``inline``'s rules: tshark reads
        them only from its personal config folder (see coloring.py)."""
        color_dir = work_dir / "colorfilters"
        color_dir.mkdir(exist_ok=True)
        personal = coloring.personal_config_dir(tshark.folders(ctx.token))
        coloring.prepare_config_dir(color_dir, inline.rules, personal)
        return {**os.environ, "WIRESHARK_CONFIG_DIR": str(color_dir)}

    def _capinfos(self, tshark: Tshark, path: Path, token: CancelToken) -> dict[str, Any]:
        if tshark.capinfos is None:
            return {}
        try:
            res = run(
                [str(tshark.capinfos), "-T", "-M", "-a", "-e", "-E", "-S", "-t", str(path)], token
            )
        except OSError, CancelledError:
            return {}
        return parse_capinfos(res.stdout.decode("utf-8", "replace"))

    @staticmethod
    def _first_epoch(tshark: Tshark, path: Path, token: CancelToken) -> float | None:
        res = run(
            tshark.argv("-c", "1", "-T", "fields", "-e", "frame.time_epoch", capture=str(path)),
            token,
        )
        try:
            return float(res.stdout.decode().strip())
        except ValueError:
            return None

    def capture_info(self, _params: dict[str, Any], _ctx: RequestContext) -> dict[str, Any]:
        f = self._require_file()
        result = f.info.to_json()
        result["columns"] = self._column_descriptors(f.columns)
        return result

    # ------------------------------------------------------------------ filters

    def validate_filter(self, params: dict[str, Any], ctx: RequestContext) -> dict[str, Any]:
        expr = param(params, "expr", str, "")
        tshark = self._file.tshark if self._file else self._require_tshark()
        error = tshark.validate_filter(expr, ctx.token)
        return {"valid": error is None, "error": error} if error else {"valid": True}

    def set_filter(self, params: dict[str, Any], ctx: RequestContext) -> dict[str, Any]:
        """Apply a display filter to the list (``""``: every packet).

        ``stream: true`` returns once the first matches are in (FIRST_BATCH, or
        after FIRST_BATCH_S) with ``filtering: true`` while the pass goes on;
        "filter" notifications (``progress``, then ``done``, ``stopped`` or
        ``failed``, each with ``filterId`` and ``matchCount``) report it, and
        ``stop_filter`` ends it early, keeping the matches so far (``partial``).
        A streaming filter also works while a streaming open is still indexing:
        the list then shows the matches among the rows indexed so far.
        Finished results are cached, also in the saved index.
        """
        if str(params.get("expr") or "").strip() and not params.get("stream"):
            self._require_indexed()
        return self._set_filter(params, ctx)

    def _set_filter(self, params: dict[str, Any], ctx: RequestContext) -> dict[str, Any]:
        expr = param(params, "expr", str, "").strip()
        stream = bool(params.get("stream"))
        f = self._require_file()
        with self._lock:
            self._filter_seq += 1
            seq = self._filter_seq
            current = self._view
            indexing = self._indexing is not None
        if current is not None and current.expr == expr and current.partial is None:
            return self._filter_result(current)

        matched = self._filters.get(expr) if expr else FrameIndex.all(f.info.frames)
        if matched is None and not indexing and f.cache is not None and f.cache_key is not None:
            saved = f.cache.load_filter(f.cache_key, expr, f.info.frames)
            if saved is not None:
                matched = FrameIndex(saved, len(saved))
                self._filters.put(expr, matched)
        if matched is None:
            error = f.tshark.validate_filter(expr, ctx.token)
            if error:
                raise FilterError(error, {"expr": expr})
            if stream:
                return self._start_filter(f, expr, seq, current, ctx)
            matched = self._run_filter(f, expr, ctx)
            self._filters.put(expr, matched)
            self._save_filter(f, expr, matched)

        with self._lock:
            if seq != self._filter_seq:
                raise CancelledError("superseded by a newer filter")
            sort = current.sort if current else None
            self._next_filter_id += 1
            view = _View(self._next_filter_id, expr, matched, sort, matched)
        if sort is not None:
            view.ordered = self._sorted(f, view, sort, ctx)
        with self._lock:
            if seq != self._filter_seq:
                raise CancelledError("superseded by a newer filter")
            self._install_view(view)
        return self._filter_result(view)

    def _start_filter(
        self, f: _Open, expr: str, seq: int, current: _View | None, ctx: RequestContext
    ) -> dict[str, Any]:
        """Show a new view whose matches arrive from a background filter pass."""
        live = _Filtering(expr)
        with self._lock:
            if seq != self._filter_seq:
                raise CancelledError("superseded by a newer filter")
            self._next_filter_id += 1
            empty = FrameIndex.of(())
            # Capture order while matches arrive; a sort applies once the pass is done.
            view = _View(self._next_filter_id, expr, empty, None, empty, live=live)
            self._install_view(view)
            live.future = self._pool.submit(self._filter_pass, f, view, live)
        deadline = time.monotonic() + FIRST_BATCH_S
        while not live.done.wait(0.05):
            if ctx.token.cancelled:
                live.token.cancel()
                with self._lock:
                    if self._view is view:
                        self._view = current  # never shown: back to the previous view
                raise CancelledError("filter cancelled")
            if time.monotonic() >= deadline or len(live.frames) >= FIRST_BATCH:
                break
        with self._lock:
            if live.running:
                self._snapshot(live)
        return self._filter_result(view)

    @staticmethod
    def _snapshot(live: _Filtering) -> None:
        """Publish the matches so far to the view (under the lock)."""
        frames = live.frames[:]  # a copy: the pass keeps appending to its array
        live.snapshot = FrameIndex(frames, len(frames))
        live.version += 1

    def _filter_pass(self, f: _Open, view: _View, live: _Filtering) -> None:
        """A streaming filter's tshark pass (in the pool), then the "filter" notification."""

        def tick(p: Any) -> None:
            with self._lock:
                self._snapshot(live)
                live.fraction = None if self._indexing is not None else p.get("fraction")
                if self._view is not view:
                    return
                _f, shown = self._require_view()
                event = {
                    "event": "progress",
                    "filterId": view.filter_id,
                    "matchCount": len(shown.matched),
                    "fraction": live.fraction,
                }
            self.notify("filter", event)

        ctx = RequestContext(token=live.token, progress=tick)
        matched: FrameIndex | None = None
        error: str | None = None
        try:
            matched = self._run_filter(f, live.expr, ctx, live.frames)
        except CancelledError:
            pass
        except Exception as exc:  # reported to the client as "failed"
            error = str(exc) or type(exc).__name__
        with self._lock:
            live.running = False
            if matched is None:
                self._snapshot(live)
            else:
                live.snapshot = matched
                live.version += 1
            live.done.set()
            # Matches beyond a streaming open's rows so far can't be reused as they are.
            complete = matched is not None and self._indexing is None and self._file is f
            if complete and matched is not None:
                self._filters.put(live.expr, matched)
            event: dict[str, Any] | None = None
            if self._view is view:
                if matched is None:
                    view.partial = error or "stopped"
                _f, shown = self._require_view()
                event = {
                    "event": "done" if matched is not None else "failed" if error else "stopped",
                    "filterId": view.filter_id,
                    "matchCount": len(shown.matched),
                    "total": f.info.frames,
                }
                if error:
                    event["message"] = error
        if complete and matched is not None:
            self._save_filter(f, live.expr, matched)
        if event is not None:
            self.notify("filter", event)

    def stop_filter(self, params: dict[str, Any], _ctx: RequestContext) -> dict[str, Any]:
        """Stop the streaming filter of view ``filterId``; its matches so far stay
        (a "filter" notification with event "stopped" follows)."""
        filter_id = param(params, "filterId", int)
        with self._lock:
            view = self._view
            live = view.live if view is not None else None
            if view is None or view.filter_id != filter_id or live is None or not live.running:
                return {"stopped": False}
            live.token.cancel()
        return {"stopped": True}

    @staticmethod
    def _save_filter(f: _Open, expr: str, matched: FrameIndex) -> None:
        if expr and f.cache is not None and f.cache_key is not None:
            frames = matched.frames()
            if isinstance(frames, array):
                f.cache.save_filter(f.cache_key, expr, frames)

    def _filter_result(self, view: _View) -> dict[str, Any]:
        f, _current = self._require_view()  # brings a streaming view up to date
        result: dict[str, Any] = {
            "expr": view.expr,
            "matchCount": len(view.matched),
            "total": f.info.frames,
            "filterId": view.filter_id,
        }
        live = view.live
        if live is not None and live.running:
            result["filtering"] = True
            result["fraction"] = live.fraction
        if view.partial:
            result["partial"] = view.partial
        return result

    def _run_filter(
        self, f: _Open, expr: str, ctx: RequestContext, frames: array[int] | None = None
    ) -> FrameIndex:
        """Run filter ``expr`` over the capture; matches are appended to ``frames``
        (a new array by default) as they come."""
        if frames is None:
            frames = array("I")
        result = StreamResult()
        argv = f.tshark.argv("-Y", expr, "-T", "fields", "-e", "frame.number", capture=str(f.path))
        total = max(1, f.info.frames)
        last_emit = 0.0
        for line in stream_lines(argv, result, ctx.token):
            if ctx.token.cancelled:  # (lines tshark wrote already would still come)
                raise CancelledError("filter stopped")
            try:
                n = int(line)
            except ValueError:
                continue
            frames.append(n)
            now = time.monotonic()
            if now - last_emit >= PROGRESS_INTERVAL_S:
                last_emit = now
                ctx.progress(
                    {"phase": "filter", "matched": len(frames), "fraction": min(0.99, n / total)}
                )
        if result.returncode not in (0, None) and not frames and result.stderr:
            if any(h in result.stderr for h in _TRUNCATION_HINTS):
                return FrameIndex(frames, len(frames))
            raise FilterError(result.stderr.removeprefix("tshark: "), {"expr": expr})
        return FrameIndex(frames, len(frames))

    # ------------------------------------------------------------------ list

    def list_packets(self, params: dict[str, Any], ctx: RequestContext) -> dict[str, Any]:
        """Return rows ``[offset, offset + limit)`` of the current (filtered, sorted) view.

        With ``frames`` (at most MAX_PAGE frame numbers) instead, the rows of
        those frames that are displayed, in view order (e.g. to copy a
        multi-selection); with ``inView: false`` too, the rows of all of them
        (in range) in the given order, displayed or not (e.g. to explain them).
        ``columns`` is the full list of custom column fields wanted after the
        seven base columns (default: the ones given to ``open``). Fields not
        indexed yet are extracted with one extra tshark pass, then cached.
        """
        offset = param(params, "offset", int, 0)
        limit = param(params, "limit", int, 200)
        if offset < 0 or limit < 0:
            raise InvalidParamsError("offset and limit must be non-negative")
        limit = min(limit, MAX_PAGE)
        f, view = self._require_view()
        base_fields = {c.field for c in BASE_COLUMNS}
        if "columns" in params:
            extra_fields = [
                c for c in self._check_fields(str_list(params, "columns")) if c not in base_fields
            ]
        else:
            extra_fields = list(f.columns)
        with self._lock:
            indexing = self._indexing is not None
        if not indexing:
            self._ensure_columns(f, extra_fields, ctx)
        # (Streaming: columns not indexed yet stay blank until the pass is done.)
        view_ordered = self._apply_sort(f, view, params, ctx)

        if "frames" in params and params.get("inView") is False:
            n_frames = f.frame_count()
            asked = _frame_list(params, "frames", MAX_PAGE)
            frames = [n for n in dict.fromkeys(asked) if 1 <= n <= n_frames]
        elif "frames" in params:
            wanted = set(_frame_list(params, "frames", MAX_PAGE))
            frames = [n for n in view_ordered.frames() if n in wanted] if wanted else []
        else:
            frames = view_ordered.slice(offset, limit)
        rejected = [fld for fld in extra_fields if fld in f.rejected]
        n_base = len(BASE_COLUMNS)
        base_rows = f.base.rows.get_many(frames)
        extra_cols = [self._column_cells(f, fld, frames) for fld in extra_fields]
        rows: list[dict[str, Any]] = [
            {"number": n, "cells": base_rows[i][:n_base] + [col[i] for col in extra_cols]}
            for i, n in enumerate(frames)
        ]
        _add_addresses(f.base.fields, base_rows, rows)
        if "timeFormat" in params:
            fmt = param(params, "timeFormat", str)
            ref = params.get("timeRef")
            if indexing and fmt in navigation.TIME_FORMATS:
                # The other formats need a frame.time_epoch pass: relative until indexed.
                fmt, ref = "relative", None
            times = self._display_times(
                f,
                view.matched,
                frames,
                [r["cells"][1] for r in rows],
                fmt,
                ref,
                ctx,
            )
            for row, text in zip(rows, times, strict=True):
                row["cells"][1] = text
        with self._lock:
            marks = self._marks
            colors, coloring_id = self._colors, self._coloring_id
        for row in rows:
            if row["number"] in marks:
                row["marked"] = True
        if colors is not None:
            for row in rows:
                n = row["number"]
                if 0 < n < len(colors) and colors[n]:
                    row["color"] = colors[n] - 1
        return {
            "offset": offset,
            "rows": rows,
            "total": len(view_ordered),
            "filterId": view.filter_id,
            # Row "color" values index the rules of this set_coloring call (0 = none).
            "coloringId": coloring_id if colors is not None else 0,
            "columns": [c.field for c in BASE_COLUMNS] + extra_fields,
            # Unknown to tshark: their cells are blank; the UI should drop them.
            "rejectedColumns": rejected,
        }

    def _apply_sort(
        self, f: _Open, view: _View, params: dict[str, Any], ctx: RequestContext
    ) -> FrameIndex:
        """The view's order after applying ``sort`` (and ``timeFormat``, which picks
        what the Time column sorts by) from ``params``; the new order becomes the
        view's. Every request that uses row indexes takes them, so an index
        request can't overtake the page request that changes the sort."""
        sort = _parse_sort(params.get("sort"))
        if sort and sort[0] == _TIME_FIELD and params.get("timeFormat") in _DELTA_SORTS:
            # "Since previous packet" formats sort by that delta, not by capture time.
            sort = (_DELTA_SORTS[params["timeFormat"]], sort[1])
        if sort == view.sort or view.live is not None:
            return view.ordered  # (a streaming filter's matches stay in capture order)
        if sort is not None:
            self._require_complete()
        ordered = self._sorted(f, view, sort, ctx) if sort else view.matched
        with self._lock:
            if self._view is view:
                view.sort = sort
                view.ordered = ordered
        return ordered

    def find_frame(self, params: dict[str, Any], ctx: RequestContext) -> dict[str, Any]:
        """Row index of a frame in the current view (for "go to packet").

        ``sort``/``timeFormat`` as for list_packets (omitted: the current order)."""
        number = param(params, "number", int)
        f, view = self._require_view()
        ordered = self._apply_sort(f, view, params, ctx) if "sort" in params else view.ordered
        return {"index": ordered.position_of(number), "filterId": view.filter_id}

    def view_frames(self, params: dict[str, Any], ctx: RequestContext) -> dict[str, Any]:
        """Frame numbers of rows ``[offset, offset + limit)`` of the current view
        (a Shift+click range; ``limit`` at most MAX_SELECTION), or, with
        ``frames``, those of them that are displayed, in view order.
        ``sort``/``timeFormat`` as for list_packets (omitted: the current order)."""
        f, view = self._require_view()
        ordered = self._apply_sort(f, view, params, ctx) if "sort" in params else view.ordered
        if "frames" in params:
            wanted = set(_frame_list(params, "frames"))
            frames = [n for n in ordered.frames() if n in wanted] if wanted else []
            return {"frames": frames, "filterId": view.filter_id}
        offset = param(params, "offset", int, 0)
        limit = param(params, "limit", int)
        if offset < 0 or not 0 <= limit <= MAX_SELECTION:
            raise InvalidParamsError(f"offset must be >= 0 and limit 0..{MAX_SELECTION}")
        return {"frames": ordered.slice(offset, limit), "filterId": view.filter_id}

    def _locate(self, f: _Open, fld: str) -> tuple[RowStore, int] | None:
        for store in (f.base, *f.extra):
            if fld in store.fields:
                return store.rows, store.fields.index(fld)
        return None

    def _ensure_columns(self, f: _Open, fields: Sequence[str], ctx: RequestContext) -> None:
        """Extract any not-yet-indexed fields (one tshark pass for all of them).

        Fields tshark rejects are remembered in ``f.rejected`` instead of failing
        the request, so one bad custom column can't break the packet list.
        """
        if all(fld in f.rejected or self._locate(f, fld) is not None for fld in fields):
            return
        self._require_indexed()  # a column pass while the index pass still runs: later
        with self._build_lock:
            self._build_columns(f, fields, ctx)

    def _build_columns(self, f: _Open, fields: Sequence[str], ctx: RequestContext) -> None:
        missing = [fld for fld in fields if fld not in f.rejected and self._locate(f, fld) is None]
        if not missing:
            return
        assert self._work_dir is not None
        requested = list(missing)
        store = self._index_pass(f.tshark, f.path, self._work_dir, missing, f.info, ctx, base=False)
        with self._lock:
            f.extra.append(store)
            f.rejected.update(m for m in requested if m not in store.fields)

    def _column_cells(self, f: _Open, fld: str, frames: Sequence[int]) -> list[str]:
        loc = self._locate(f, fld)
        if loc is None:
            return [""] * len(frames)
        rows, idx = loc
        return [r[idx] for r in rows.get_many(frames)]

    def _sorted(
        self, f: _Open, view: _View, sort: tuple[str, bool] | None, ctx: RequestContext
    ) -> FrameIndex:
        if sort is None:
            return view.matched
        key = (view.expr, *sort)
        cached = self._sorts.get(key)
        if cached is not None:
            return cached
        with self._build_lock:
            return self._build_sort(f, view, sort, ctx)

    def _build_sort(
        self, f: _Open, view: _View, sort: tuple[str, bool], ctx: RequestContext
    ) -> FrameIndex:
        fld, desc = sort
        key = (view.expr, fld, desc)
        cached = self._sorts.get(key)
        if cached is not None:
            return cached
        if fld in _DELTA_SORTS.values():
            ctx.progress({"phase": "sort", "fraction": None})
            deltas = self._time_deltas(f, view.matched, fld == _DELTA_SORTS["delta_displayed"], ctx)
            ordered = sort_frames_by_key(view.matched.frames(), deltas, desc)
            self._sorts.put(key, ordered)
            return ordered
        self._ensure_columns(f, [fld], ctx)
        if fld in f.rejected:
            raise InvalidParamsError(f"cannot sort by unknown field {fld!r}")
        ctx.progress({"phase": "sort", "fraction": None})
        values = self._sort_columns.get(fld)
        if values is None:
            loc = self._locate(f, fld)
            assert loc is not None
            rows, idx = loc
            values = rows.column(idx)
            self._sort_columns.put(fld, values)
        ctx.token.raise_if_cancelled()
        base = next((c for c in BASE_COLUMNS if c.field == fld), None)
        if base is not None:
            numeric, addresses = base.numeric or None, base.addresses
        else:
            numeric, addresses = None, self._is_address_field(fld, ctx)
        ordered = sort_frames(
            view.matched.frames(), values, desc, numeric=numeric, addresses=addresses
        )
        self._sorts.put(key, ordered)
        return ordered

    def _is_address_field(self, fld: str, ctx: RequestContext) -> bool:
        """Custom columns of IPv4/IPv6/MAC fields sort numerically, like Source/Destination."""
        try:
            entry = self._catalog(ctx).lookup(fld)
        except CancelledError:
            raise
        except RpcError, ToolError, OSError:
            return False
        return entry is not None and entry.get("type") in _ADDRESS_TYPES

    def _time_deltas(
        self, f: _Open, matched: FrameIndex, displayed: bool, ctx: RequestContext
    ) -> list[int | None]:
        """Per frame of ``matched``: ns since the previous displayed (``matched``)
        or captured packet, the values the delta time formats show (0 for the first)."""
        fld = "frame.time_epoch"
        self._ensure_columns(f, [fld], ctx)
        loc = self._locate(f, fld)
        assert loc is not None
        rows, idx = loc
        epoch = [navigation.parse_ns(v) for v in rows.column(idx)]
        ctx.token.raise_if_cancelled()
        out: list[int | None] = []
        prev: int | None = None
        for n in matched.frames():
            e = epoch[n - 1] if n <= len(epoch) else None
            p = prev if displayed else (n - 1 if n > 1 else None)
            pe = epoch[p - 1] if p is not None and p <= len(epoch) else None
            if e is None:
                out.append(None)
            else:
                out.append(e - pe if pe is not None else (0 if p is None else None))
            prev = n
        return out

    # ------------------------------------------------------------------ time formats

    def _display_times(
        self,
        f: _Open,
        matched: FrameIndex,
        frames: list[int],
        relative: list[str],
        fmt: str,
        ref: Any,
        ctx: RequestContext,
    ) -> list[str]:
        """Time column text for one page in ``fmt`` (see navigation.TIME_FORMATS).

        Everything but plain "seconds since beginning" needs frame.time_epoch,
        extracted once into the row store. "Since previous displayed" is since the
        previous packet of the current filter in capture order (``matched``), like
        Wireshark's frame.time_delta_displayed but for our filter: a property of
        the packet, whatever the sort order, so the Time column can sort by it.
        """
        if fmt not in navigation.TIME_FORMATS:
            raise InvalidParamsError(
                f"timeFormat must be one of {', '.join(navigation.TIME_FORMATS)}"
            )
        if ref is not None and (
            isinstance(ref, bool) or not isinstance(ref, int) or not 1 <= ref <= f.info.frames
        ):
            raise InvalidParamsError(f"timeRef must be a frame number 1..{f.info.frames}")
        if fmt == "relative" and ref is None:
            return [
                navigation.format_seconds(ns) if (ns := navigation.parse_ns(v)) is not None else v
                for v in relative
            ]
        fld = "frame.time_epoch"
        self._ensure_columns(f, [fld], ctx)
        need = set(frames)
        prev_displayed: dict[int, int] = {}
        if fmt == "delta_displayed":
            seq = matched.frames()
            for n in frames:
                i = bisect_left(seq, n)
                if 0 < i <= len(seq):
                    prev_displayed[n] = seq[i - 1]
            need |= set(prev_displayed.values())
        if fmt == "delta_captured":
            need |= {n - 1 for n in frames if n > 1}
        if ref is not None:
            need.add(ref)
        wanted = sorted(need)
        epoch = {
            n: navigation.parse_ns(c)
            for n, c in zip(wanted, self._column_cells(f, fld, wanted), strict=True)
        }
        ref_ns = epoch.get(ref) if ref is not None else None
        zero = navigation.format_seconds(0)
        out: list[str] = []
        for n in frames:
            e = epoch.get(n)
            if n == ref:
                out.append("*REF*")
            elif e is None:
                out.append("")
            elif fmt == "relative":
                out.append(navigation.format_seconds(e - ref_ns) if ref_ns is not None else "")
            elif fmt == "delta_displayed":
                prev = prev_displayed.get(n)
                p = epoch.get(prev) if prev is not None else None
                out.append(navigation.format_seconds(e - p) if p is not None else zero)
            elif fmt == "delta_captured":
                p = epoch.get(n - 1)
                out.append(navigation.format_seconds(e - p) if p is not None else zero)
            elif fmt == "epoch":
                out.append(navigation.format_seconds(e))
            else:
                out.append(navigation.format_absolute(e, utc=fmt == "utc"))
        return out

    # ------------------------------------------------------------------ find / navigate / mark

    def find_packet(self, params: dict[str, Any], ctx: RequestContext) -> dict[str, Any]:
        """Next (or previous) frame of the current view that matches a search.

        ``mode``: ``filter`` (a display filter), ``string`` (text in the packet
        bytes; ``caseSensitive``), ``hex`` (bytes, e.g. ``47:45:54``) or
        ``marked``. The search starts after ``from`` (a frame number; omitted:
        from the top or bottom) in view order (current filter and sort) and
        wraps around. The search filter runs once and is cached like any filter.
        """
        self._require_complete()
        mode = param(params, "mode", str)
        direction = param(params, "direction", str, "next")
        if mode not in navigation.FIND_MODES or direction not in ("next", "previous"):
            raise InvalidParamsError("invalid find mode or direction")
        f, view = self._require_view()
        n_frames = f.info.frames
        hits = bytearray(n_frames + 1)
        expr = ""
        if mode == "marked":
            with self._lock:
                for n in self._marks:
                    if 0 < n <= n_frames:
                        hits[n] = 1
        else:
            try:
                expr = navigation.find_expression(
                    mode, param(params, "value", str, ""), bool(params.get("caseSensitive"))
                )
            except ValueError as exc:
                raise InvalidParamsError(str(exc)) from exc
            matched = self._filters.get(expr)
            if matched is None:
                error = f.tshark.validate_filter(expr, ctx.token)
                if error:
                    raise FilterError(error, {"expr": expr})
                matched = self._run_filter(f, expr, ctx)
                self._filters.put(expr, matched)
            for n in matched.frames():
                hits[n] = 1
        ordered = self._apply_sort(f, view, params, ctx) if "sort" in params else view.ordered
        seq = ordered.frames()
        total = len(ordered)
        start = params.get("from")
        pos = ordered.position_of(start) if isinstance(start, int) else None
        step = 1 if direction == "next" else -1
        result: dict[str, Any] = {"frame": None, "index": None, "filterId": view.filter_id}
        if expr:
            result["expr"] = expr
        for k in range(total):
            if pos is None:
                i = k if step == 1 else total - 1 - k
            else:
                i = (pos + step * (k + 1)) % total
            if hits[seq[i]]:
                wrapped = pos is not None and (i <= pos if step == 1 else i >= pos)
                result.update({"frame": seq[i], "index": i, "wrapped": wrapped})
                break
            if k % 65536 == 65535:
                ctx.token.raise_if_cancelled()
        return result

    def neighbor_frame(self, params: dict[str, Any], ctx: RequestContext) -> dict[str, Any]:
        """Next/previous frame of the current view in the same conversation.

        The conversation is the tcp.stream or udp.stream (extracted once into the
        row store), else the Source/Destination address pair. No wrap-around.
        """
        self._require_complete()
        frame = param(params, "frame", int)
        direction = param(params, "direction", str, "next")
        if direction not in ("next", "previous"):
            raise InvalidParamsError("direction must be next or previous")
        f, view = self._require_view()
        ordered = self._apply_sort(f, view, params, ctx) if "sort" in params else view.ordered
        pos = ordered.position_of(frame)
        if pos is None:
            raise InvalidParamsError(f"packet {frame} is not displayed")
        self._ensure_columns(f, ["tcp.stream", "udp.stream"], ctx)
        key = self._conversation_keys(f, [frame])[0]
        result: dict[str, Any] = {"frame": None, "index": None, "filterId": view.filter_id}
        if key is None:
            return result
        seq = ordered.frames()
        step = 1 if direction == "next" else -1
        i = pos + step
        while 0 <= i < len(seq):
            stop = min(len(seq), i + NEIGHBOR_CHUNK) if step == 1 else max(-1, i - NEIGHBOR_CHUNK)
            positions = list(range(i, stop, step))
            keys = self._conversation_keys(f, [seq[p] for p in positions])
            for p, k in zip(positions, keys, strict=True):
                if k == key:
                    result.update({"frame": seq[p], "index": p})
                    return result
            ctx.token.raise_if_cancelled()
            i = stop
        return result

    def _conversation_keys(self, f: _Open, frames: list[int]) -> list[tuple[str, ...] | None]:
        tcp = self._column_cells(f, "tcp.stream", frames)
        udp = self._column_cells(f, "udp.stream", frames)
        base = f.base.rows.get_many(frames)
        keys: list[tuple[str, ...] | None] = []
        for t, u, cells in zip(tcp, udp, base, strict=True):
            if t:
                keys.append(("tcp", t.split(",")[0]))
            elif u:
                keys.append(("udp", u.split(",")[0]))
            elif cells[2] and cells[3]:
                keys.append(("addr", *sorted((cells[2], cells[3]))))
            else:
                keys.append(None)
        return keys

    def mark_packets(self, params: dict[str, Any], _ctx: RequestContext) -> dict[str, Any]:
        """Mark (``mark: true``) or unmark (``false``) ``frames``. Omitted: toggle,
        like Wireshark's Ctrl+M on a multi-selection: mark them all unless all
        of them are already marked, then unmark them."""
        f = self._require_file()
        frames = [n for n in _frame_list(params, "frames") if 1 <= n <= f.frame_count()]
        mark = params.get("mark")
        with self._lock:
            on = bool(mark) if mark is not None else not all(n in self._marks for n in frames)
            for n in frames:
                if on:
                    self._marks.add(n)
                else:
                    self._marks.discard(n)
            return {
                "count": len(self._marks),
                "marked": [n for n in frames if n in self._marks],
                "unmarked": [n for n in frames if n not in self._marks],
            }

    def unmark_all(self, _params: dict[str, Any], _ctx: RequestContext) -> dict[str, Any]:
        self._require_file()
        with self._lock:
            self._marks = set()
        return {"count": 0}

    def field_types(self, params: dict[str, Any], ctx: RequestContext) -> dict[str, Any]:
        """Type and display name of each field in ``names`` (unknown ones are left out),
        e.g. to render FT_FRAMENUM fields as links to the frame they reference."""
        names = str_list(params, "names")[:2000]
        catalog = self._catalog(ctx)
        types: dict[str, dict[str, str]] = {}
        for name in names:
            entry = catalog.lookup(name)
            if entry is not None:
                types[name] = {"type": entry.get("type", "protocol"), "desc": entry.get("desc", "")}
        return {"types": types}

    # ------------------------------------------------------------------ detail

    def packet_detail(self, params: dict[str, Any], ctx: RequestContext) -> dict[str, Any]:
        """Detail tree and byte sources of frame ``number``.

        ``mode``: ``exact`` (default) dissects the capture up to the frame
        (``-c N``), so its cost grows with N. ``quick`` dissects only the
        ``window`` packets up to it (cut out with editcap): fast anywhere in
        the file, but approximate (``approximate: true``, ``window: [first,
        last]``), since state from earlier packets (reassembly, TCP analysis,
        conversations) is missing. A quick request answers with the exact
        detail when that is cached or the window starts at frame 1, and with
        ``{"unavailable": reason}`` without editcap.
        """
        number = param(params, "number", int)
        mode = param(params, "mode", str, "exact")
        if mode not in ("exact", "quick"):
            raise InvalidParamsError("mode must be exact or quick")
        f = self._require_file()
        if not 1 <= number <= f.frame_count():
            raise InvalidParamsError(f"frame {number} out of range 1..{f.frame_count()}")
        cached = self._details.get(number)
        if cached is not None:
            return cached
        if mode == "quick":
            window = param(params, "window", int, QUICK_WINDOW)
            if not MIN_QUICK_WINDOW <= window <= MAX_QUICK_WINDOW:
                raise InvalidParamsError(
                    f"window must be {MIN_QUICK_WINDOW}..{MAX_QUICK_WINDOW} packets"
                )
            if number > window:
                return self._quick_detail(f, number, window, ctx)
        detail = {"number": number, **self._dissect(f.tshark, f.path, number, ctx)}
        self._details.put(number, detail)
        return detail

    def _dissect(
        self, tshark: Tshark, capture: Path, number: int, ctx: RequestContext
    ) -> dict[str, Any]:
        """PDML tree and ``-x`` byte sources of frame ``number`` of ``capture``."""
        select = ["-c", str(number), "-Y", f"frame.number=={number}"]
        pdml_argv = tshark.argv(*select, "-T", "pdml", capture=str(capture))
        hex_argv = tshark.argv(*select, "-x", capture=str(capture))
        hex_future = self._pool.submit(run, hex_argv, ctx.token)
        pdml_res = run(pdml_argv, ctx.token)
        hex_res = hex_future.result()
        if not pdml_res.stdout.strip():
            raise tshark.error(
                pdml_res.stderr,
                pdml_res.returncode,
                f"tshark returned no detail for frame {number}",
            )
        sources = pdml.parse_hexdump(hex_res.stdout.decode("utf-8", "replace"))
        tree = pdml.parse_pdml(pdml_res.stdout, source_count=max(1, len(sources)))
        return {
            "tree": tree,
            "sources": [s.to_json() for s in sources],
            "warnings": _stderr_warnings(pdml_res.stderr),
        }

    def _quick_detail(
        self, f: _Open, number: int, window: int, ctx: RequestContext
    ) -> dict[str, Any]:
        """Dissect only packets ``number - window + 1 .. number``: editcap copies
        them into a small pcapng (it reads records without dissecting them),
        and the tree is renumbered to the capture's frame numbers."""
        key = (number, window)
        cached = self._quick.get(key)
        if cached is not None:
            return cached
        try:
            editcap = find_tool("editcap", sibling_of=f.tshark.path)
        except ToolNotFoundError:
            return {"number": number, "unavailable": "editcap (part of Wireshark) was not found"}
        assert self._work_dir is not None
        first = number - window + 1
        part = self._work_dir / f"quick-{number}-{next(self._quick_seq)}.pcapng"
        try:
            res = run(
                [str(editcap), "-F", "pcapng", "-r", str(f.path), str(part), f"{first}-{number}"],
                ctx.token,
            )
            if res.returncode != 0 or not part.exists():
                raise ToolError(
                    res.stderr or f"editcap exited with code {res.returncode}",
                    res.stderr,
                    res.returncode,
                )
            detail = self._dissect(f.tshark, part, window, ctx)
        finally:
            part.unlink(missing_ok=True)
        pdml.renumber_tree(
            detail["tree"],
            offset=first - 1,
            window=window,
            is_framenum=self._framenum_check(ctx),
            time_relative=f.base.rows.get(number)[_TIME_IDX] or None,
        )
        detail = {"number": number, **detail, "approximate": True, "window": [first, number]}
        self._quick.put(key, detail)
        return detail

    def _framenum_check(self, ctx: RequestContext) -> Callable[[str], bool]:
        """Whether a field is FT_FRAMENUM: from the field catalogue when it is
        loaded (the webview warms it after open), else known names, while the
        catalogue loads in the background (a quick view must not wait for it)."""
        tshark = self._file.tshark if self._file else self._require_tshark()
        catalog = self._field_index.get(tshark.options.lua_scripts)
        if catalog is None:
            if not self._catalog_warming.is_set():
                self._catalog_warming.set()
                self._pool.submit(self._warm_catalog)
            return lambda name: bool(_FRAMENUM_HINT.search(name))

        def check(name: str) -> bool:
            entry = catalog.lookup(name)
            return entry is not None and entry.get("type") == "FT_FRAMENUM"

        return check

    def _warm_catalog(self) -> None:
        try:
            self._catalog(RequestContext())
        except (RpcError, ToolError, OSError) as exc:  # a real request reports it
            print(f"pcap-viewer: field catalogue not loaded: {exc}", file=sys.stderr)
        finally:
            self._catalog_warming.clear()

    # ------------------------------------------------------------------ follow stream

    def follow_stream(self, params: dict[str, Any], ctx: RequestContext) -> dict[str, Any]:
        """Reassembled payload of one TCP/UDP/TLS/HTTP stream (``-z follow,<proto>,raw``).

        Give ``stream`` (the ``tcp.stream``/``udp.stream`` number) or ``frame``
        (a packet in the stream). Returns ``segments`` of ``{dir, hex}`` where
        ``dir`` 0 is the side that sent first (node 0) and 1 the other side.
        Output beyond ``maxBytes`` of payload is cut off (``truncated``).
        """
        proto = param(params, "proto", str).lower()
        if proto not in stats.FOLLOW_PROTOCOLS:
            raise InvalidParamsError(f"proto must be one of {', '.join(stats.FOLLOW_PROTOCOLS)}")
        f = self._require_file()
        max_bytes = max(1024, min(param(params, "maxBytes", int, 16 << 20), 256 << 20))
        if params.get("stream") is not None:
            stream = param(params, "stream", int)
            if stream < 0:
                raise InvalidParamsError("stream must be >= 0")
        else:
            stream = self._stream_of(f, proto, param(params, "frame", int), ctx)

        # -n: node addresses stay addresses, whatever the list's name resolution.
        argv = f.tshark.argv("-q", "-n", "-z", f"follow,{proto},raw,{stream}", capture=str(f.path))
        result = StreamResult()
        lines: list[str] = []
        size = 0
        truncated = False
        ctx.progress({"phase": "follow", "fraction": None})
        for raw in stream_lines(argv, result, ctx.token):
            line = raw.decode("utf-8", "replace")
            size += len(line) // 2
            if size > max_bytes:
                truncated = True
                break  # closing the generator kills tshark
            lines.append(line)
        if not lines and result.returncode not in (0, None):
            raise f.tshark.error(result.stderr, result.returncode, "tshark follow failed")
        followed = stats.parse_follow_raw("\n".join(lines))
        followed.update({"proto": proto, "stream": stream, "truncated": truncated})
        if not followed["segments"] and proto == "tls":
            followed["hint"] = (
                "No decrypted TLS data. Provide session keys via the "
                '"tls.keylog_file" preference (pcapViewer.prefs) to follow TLS.'
            )
        return followed

    def _stream_of(self, f: _Open, proto: str, frame: int, ctx: RequestContext) -> int:
        if not 1 <= frame <= f.frame_count():
            raise InvalidParamsError(f"frame {frame} out of range 1..{f.frame_count()}")
        fld = "udp.stream" if proto == "udp" else "tcp.stream"
        self._ensure_columns(f, [fld], ctx)  # one extra pass, then cached
        value = self._column_cells(f, fld, [frame])[0].split(",")[0]
        if not value.isdigit():
            label = "UDP" if proto == "udp" else "TCP"
            raise InvalidParamsError(f"packet {frame} is not part of a {label} stream")
        return int(value)

    # ------------------------------------------------------------------ statistics

    def stats(self, params: dict[str, Any], ctx: RequestContext) -> dict[str, Any]:
        """Statistics tables from tshark's ``-z`` reports.

        ``kind``: ``conversations`` / ``endpoints`` (with ``type`` eth, ip, ipv6,
        tcp, udp), ``phs`` (protocol hierarchy), ``io`` (with optional
        ``interval`` in seconds), ``expert`` or ``properties`` (capinfos).
        ``filter`` limits the statistics to packets matching a display filter.
        """
        kind = param(params, "kind", str)
        f = self._require_file()
        flt = param(params, "filter", str, "").strip()
        if flt and kind != "properties":
            error = f.tshark.validate_filter(flt, ctx.token)
            if error:
                raise FilterError(error, {"expr": flt})
        suffix = f",{flt}" if flt else ""
        ctx.progress({"phase": "stats", "fraction": None})
        match kind:
            case "conversations" | "endpoints":
                typ = param(params, "type", str, "tcp")
                if typ not in stats.CONV_TYPES:
                    raise InvalidParamsError(f"type must be one of {', '.join(stats.CONV_TYPES)}")
                tap = "conv" if kind == "conversations" else "endpoints"
                text = self._tap(f, f"{tap},{typ}{suffix}", ctx)
                parse = (
                    stats.parse_conversations if kind == "conversations" else stats.parse_endpoints
                )
                table = parse(text, typ)
                table.extra["type"] = typ
            case "phs":
                table = stats.parse_protocol_hierarchy(self._tap(f, f"io,phs{suffix}", ctx))
            case "io":
                duration = (
                    f.info.end_time - f.info.start_time
                    if f.info.end_time is not None and f.info.start_time is not None
                    else None
                )
                interval = param(params, "interval", float, 0.0) or stats.io_interval(duration)
                if not 0.000001 <= interval <= 86400:
                    raise InvalidParamsError("interval must be between 1 µs and 1 day")
                text = self._tap(f, f"io,stat,{interval:g}{suffix}", ctx)
                table = stats.parse_io_stat(text, interval)
            case "expert":
                fields_args = ["-T", "fields", "-e", "frame.number", "-e", "_ws.expert"]
                fields_args += [
                    "-E",
                    "aggregator=\x1e",
                    "-Y",
                    f"_ws.expert && ({flt})" if flt else "_ws.expert",
                ]
                fields_future = self._pool.submit(
                    run, f.tshark.argv(*fields_args, capture=str(f.path)), ctx.token
                )
                # "comment" is the lowest severity, i.e. everything.
                summary = self._tap(f, f"expert,comment{suffix}", ctx)
                fields_text = fields_future.result().stdout.decode("utf-8", "replace")
                table = stats.parse_expert(summary, fields_text)
            case "properties":
                if f.tshark.capinfos is None:
                    raise ToolError("capinfos (part of Wireshark) was not found")
                res = run([str(f.tshark.capinfos), str(f.path)], ctx.token)
                table = stats.parse_capinfos_properties(res.stdout.decode("utf-8", "replace"))
            case _:
                raise InvalidParamsError(f"unknown statistics kind {kind!r}")
        result = table.to_json()
        result["filter"] = flt
        return result

    def _tap(self, f: _Open, spec: str, ctx: RequestContext) -> str:
        # -n (after the name resolution options): report rows become address filters.
        res = run(f.tshark.argv("-q", "-n", "-z", spec, capture=str(f.path)), ctx.token)
        text = res.stdout.decode("utf-8", "replace")
        if res.returncode != 0 and not text.strip():
            raise f.tshark.error(res.stderr, res.returncode, f"tshark -z {spec} failed")
        return text

    # ------------------------------------------------------------------ fields

    # ------------------------------------------------------------------ coloring

    def set_coloring(self, params: dict[str, Any], ctx: RequestContext) -> dict[str, Any]:
        """Evaluate coloring rules (first match wins) for every frame in one pass.

        ``rules``: ``[{filter, foreground?, background?}]`` in priority order; an
        empty list turns coloring off. Returns ``coloringId`` (echoed by
        ``list_packets``) and per-rule ``errors`` (index → message) for rules
        that were skipped because they don't compile or are malformed.
        """
        raw = params.get("rules") or []
        if not isinstance(raw, list):
            raise InvalidParamsError("parameter 'rules' must be a list")
        f = self._require_file()
        self._require_indexed()
        with self._lock:
            self._coloring_seq += 1
            seq = self._coloring_seq
        rules, errors = _parse_rules(raw)
        valid = sum(isinstance(r, coloring.ColorRule) for r in rules)
        colors: array[int] | None = None
        colored = 0
        rules_id = rules_key(raw)
        saved = (
            f.cache.load_colors(f.cache_key, rules_id, f.info.frames)
            if valid and f.cache is not None and f.cache_key is not None
            else None
        )
        if saved is not None:
            colors, extra = saved
            colored = int(extra.get("colored", 0))
            errors.update({int(i): str(m) for i, m in extra.get("errors", {}).items()})
        elif valid:
            colors, colored, compile_errors = self._coloring_pass(f, rules, ctx)
            errors.update(compile_errors)
            if f.cache is not None and f.cache_key is not None:
                extra = {"colored": colored, "errors": {str(i): m for i, m in errors.items()}}
                f.cache.save_colors(f.cache_key, rules_id, colors, extra)
        with self._lock:
            if seq != self._coloring_seq:
                raise CancelledError("superseded by newer coloring rules")
            if self._file is not f:
                raise NotOpenError()
            self._coloring_id += 1
            self._colors = colors
            coloring_id = self._coloring_id
        return {
            "coloringId": coloring_id,
            "colored": colored,
            "errors": {str(i): msg for i, msg in sorted(errors.items())},
        }

    def _coloring_pass(
        self, f: _Open, rules: list[coloring.ColorRule | str], ctx: RequestContext
    ) -> tuple[array[int], int, dict[int, str]]:
        """One ``--color`` pass: (rule index + 1 per frame, frames colored, compile errors)."""
        colors = array("B", bytes(f.info.frames + 1))
        colored = 0
        result = StreamResult()
        argv = f.tshark.argv(
            "--color", "-T", "fields", "-e", "frame.number", "-e", "frame.coloring_rule.name",
            capture=str(f.path),
        )  # fmt: skip
        personal = coloring.personal_config_dir(f.tshark.folders(ctx.token))
        total = max(1, f.info.frames)
        last_emit = 0.0
        with tempfile.TemporaryDirectory(prefix="pcapviewer-colors-") as tmp:
            coloring.prepare_config_dir(Path(tmp), rules, personal)
            env = {**os.environ, "WIRESHARK_CONFIG_DIR": tmp}
            for line in stream_lines(argv, result, ctx.token, env=env):
                number, _, rule = line.partition(b"\t")
                try:
                    n, idx = int(number), int(rule)
                except ValueError:
                    continue
                if 0 < n < len(colors) and 0 <= idx < len(rules):
                    colors[n] = idx + 1
                    colored += 1
                now = time.monotonic()
                if now - last_emit >= PROGRESS_INTERVAL_S:
                    last_emit = now
                    ctx.progress({"phase": "color", "fraction": min(0.99, n / total)})
        if result.returncode not in (0, None) and result.lines == 0:
            raise f.tshark.error(result.stderr, result.returncode, "tshark coloring pass failed")
        return colors, colored, coloring.parse_compile_errors(result.stderr)

    # ------------------------------------------------------------------ export

    def export(self, params: dict[str, Any], ctx: RequestContext) -> dict[str, Any]:
        """Write an export file at ``dest`` (absolute path, never the open capture).

        ``kind``:

        * ``pcapng`` / ``pcap``: packets matching ``filter`` (default: the current
          display filter; ``""`` for all packets), written by tshark. Or the
          marked packets (``marked: true``) or the packets in ``frames`` (a
          multi-selection).
        * ``csv`` / ``json``: the packet list of the current view, in its current
          order, with the base columns plus ``columns`` (custom fields; titles in
          the parallel ``titles`` list); only the rows of ``frames`` if given.
        * ``bytes``: the raw bytes of frame ``number`` (data ``source`` index,
          default 0: the frame itself).
        * ``dissections``: tshark's full packet details, ``format`` ``text``
          (``-V``), ``pdml`` or ``json``, with the hex bytes too if ``bytes``;
          packets chosen as for pcapng (filter, ``marked`` or ``frames``).

        The file only appears once complete; cancelling leaves nothing behind.
        """
        kind = param(params, "kind", str)
        if kind not in EXPORT_KINDS:
            raise InvalidParamsError(f"kind must be one of {', '.join(EXPORT_KINDS)}")
        f = self._require_file()
        dest = check_destination(param(params, "dest", str), f.path)
        if kind in CAPTURE_FORMATS:
            result = self._export_capture(f, kind, dest, params, ctx)
        elif kind in LIST_FORMATS:
            result = self._export_list(f, kind, dest, params, ctx)
        elif kind == "dissections":
            result = self._export_dissections(f, dest, params, ctx)
        else:
            result = self._export_bytes(dest, params, ctx)
        result.update({"ok": True, "path": str(dest), "size": dest.stat().st_size})
        return result

    def _export_capture(
        self, f: _Open, fmt: str, dest: Path, params: dict[str, Any], ctx: RequestContext
    ) -> dict[str, Any]:
        if params.get("marked"):
            with self._lock:
                marks = sorted(self._marks)
            if not marks:
                raise InvalidParamsError("No packets are marked")
            return self._export_frames(f, fmt, dest, marks, "marked packets", ctx)
        if "frames" in params:
            n_frames = f.frame_count()
            frames = sorted({n for n in _frame_list(params, "frames") if 1 <= n <= n_frames})
            if not frames:
                raise InvalidParamsError("No packets are selected")
            return self._export_frames(f, fmt, dest, frames, "selected packets", ctx)
        if "filter" in params:
            flt = param(params, "filter", str, "").strip()
        else:
            flt = self._require_view()[1].expr
        packets = 0
        with atomic_output(dest) as tmp:
            if flt:
                error = f.tshark.validate_filter(flt, ctx.token)
                if error:
                    raise FilterError(error, {"expr": flt})
                # -P prints each written packet's number: that is our progress.
                argv = f.tshark.argv(
                    "-Y", flt, "-F", fmt, "-w", str(tmp),
                    "-P", "-T", "fields", "-e", "frame.number",
                    capture=str(f.path),
                )  # fmt: skip
            else:
                # Every packet: nothing to dissect, tshark just copies records.
                argv = f.tshark.argv("-F", fmt, "-w", str(tmp), capture=str(f.path), dissect=False)
            result = StreamResult()
            total = max(1, f.info.frames)
            last_emit = 0.0
            ctx.progress({"phase": "export", "fraction": None})
            for line in stream_lines(argv, result, ctx.token):
                try:
                    n = int(line)
                except ValueError:
                    continue
                packets += 1
                now = time.monotonic()
                if now - last_emit >= PROGRESS_INTERVAL_S:
                    last_emit = now
                    ctx.progress({"phase": "export", "fraction": min(0.99, n / total)})
            truncated = any(h in result.stderr for h in _TRUNCATION_HINTS)
            if result.returncode not in (0, None) and not (truncated and tmp.exists()):
                raise f.tshark.error(
                    result.stderr, result.returncode, f"tshark exited with code {result.returncode}"
                )
            if not tmp.exists():
                raise f.tshark.error(
                    result.stderr, result.returncode, "tshark wrote no output file"
                )
        return {
            "packets": packets if flt else f.info.frames,
            "filter": flt,
            "warnings": _stderr_warnings(result.stderr),
        }

    def _export_frames(
        self, f: _Open, fmt: str, dest: Path, frames: list[int], label: str, ctx: RequestContext
    ) -> dict[str, Any]:
        """Some frames (marked or selected) to a capture: ``frame.number in {...}``
        (ranges compressed).

        A filter longer than MAX_FILTER_ARG would overflow the command line
        (Windows caps it at 32767 characters), so big frame sets are written in
        chunks and joined in frame order with ``mergecap -a``.
        """
        filters = navigation.frame_set_filters(frames, MAX_FILTER_ARG)
        if len(filters) == 1:
            result = self._export_capture(f, fmt, dest, {"filter": filters[0]}, ctx)
            result["filter"] = label
            return result
        try:
            mergecap = find_tool("mergecap", sibling_of=f.tshark.path)
        except ToolNotFoundError as exc:
            raise ToolError(
                f"{len(frames):,} {label} need mergecap (part of Wireshark), "
                "which was not found; export fewer packets or install mergecap"
            ) from exc
        assert self._work_dir is not None
        parts: list[Path] = []
        packets = 0
        warnings: list[str] = []
        try:
            for i, flt in enumerate(filters):
                ctx.token.raise_if_cancelled()
                part = self._work_dir / f"frames-{i}.{fmt}"
                parts.append(part)
                res = self._export_capture(f, fmt, part, {"filter": flt}, ctx)
                packets += res["packets"]
                warnings += res["warnings"]
                ctx.progress({"phase": "export", "fraction": min(0.99, (i + 1) / len(filters))})
            with atomic_output(dest) as tmp:
                merged = run(
                    [str(mergecap), "-a", "-F", fmt, "-w", str(tmp), *map(str, parts)], ctx.token
                )
                if merged.returncode != 0 or not tmp.exists():
                    raise ToolError(
                        merged.stderr or "mergecap failed", merged.stderr, merged.returncode
                    )
        finally:
            for part in parts:
                part.unlink(missing_ok=True)
        return {"packets": packets, "filter": label, "warnings": warnings}

    def _export_list(
        self, f: _Open, fmt: str, dest: Path, params: dict[str, Any], ctx: RequestContext
    ) -> dict[str, Any]:
        self._require_complete()
        _f, view = self._require_view()
        base_fields = {c.field for c in BASE_COLUMNS}
        requested = str_list(params, "columns") if "columns" in params else list(f.columns)
        titles = str_list(params, "titles")
        title_of = {
            fld: (titles[i] if i < len(titles) and titles[i].strip() else fld)
            for i, fld in enumerate(requested)
        }
        custom = [c for c in self._check_fields(requested) if c not in base_fields]
        self._ensure_columns(f, custom, ctx)
        custom = [c for c in custom if c not in f.rejected]
        headers = [c.title for c in BASE_COLUMNS] + [title_of.get(c, c) for c in custom]
        keys = [c.id for c in BASE_COLUMNS] + custom
        numeric = [c.numeric for c in BASE_COLUMNS] + [False] * len(custom)
        ordered = view.ordered
        if "frames" in params:
            wanted = set(_frame_list(params, "frames"))
            ordered = FrameIndex.of(n for n in ordered.frames() if n in wanted)
        total = len(ordered)
        n_base = len(BASE_COLUMNS)
        with atomic_output(dest) as tmp, tmp.open("w", encoding="utf-8", newline="") as fh:
            writer = PacketListWriter(fh, fmt, headers, keys, numeric)
            for offset in range(0, total, EXPORT_CHUNK):
                ctx.token.raise_if_cancelled()
                frames = ordered.slice(offset, EXPORT_CHUNK)
                base_rows = f.base.rows.get_many(frames)
                extra = [self._column_cells(f, fld, frames) for fld in custom]
                writer.write(
                    base_rows[i][:n_base] + [col[i] for col in extra] for i in range(len(frames))
                )
                ctx.progress(
                    {"phase": "export", "fraction": min(0.99, (offset + len(frames)) / total)}
                )
            writer.close()
        label = "selected packets" if "frames" in params else view.expr
        return {"packets": total, "filter": label, "columns": keys}

    def _export_scope(
        self, f: _Open, params: dict[str, Any]
    ) -> tuple[list[str], str, int | None, bool]:
        """Which packets an export takes, as display filters (one pass each;
        ``""`` = every packet): (filters, label, expected packets if known,
        whether the filter came from the user and needs validating)."""
        if params.get("marked"):
            with self._lock:
                frames = sorted(self._marks)
            if not frames:
                raise InvalidParamsError("No packets are marked")
            label = "marked packets"
        elif "frames" in params:
            n_frames = f.frame_count()
            frames = sorted({n for n in _frame_list(params, "frames") if 1 <= n <= n_frames})
            if not frames:
                raise InvalidParamsError("No packets are selected")
            label = "selected packets"
        else:
            _f, view = self._require_view()
            flt = param(params, "filter", str, "").strip() if "filter" in params else view.expr
            if not flt:
                return [""], "", f.info.frames, False
            known = flt == view.expr and view.live is None and view.partial is None
            return [flt], flt, len(view.matched) if known else None, True
        return navigation.frame_set_filters(frames, MAX_FILTER_ARG), label, len(frames), False

    def _export_dissections(
        self, f: _Open, dest: Path, params: dict[str, Any], ctx: RequestContext
    ) -> dict[str, Any]:
        """Full dissections (Wireshark's "Export Packet Dissections"), streamed
        from tshark to the file; big frame sets are filtered in chunks and joined."""
        fmt = param(params, "format", str, "text")
        if fmt not in DISSECTION_FORMATS:
            raise InvalidParamsError(f"format must be one of {', '.join(DISSECTION_FORMATS)}")
        filters, label, expected, user_filter = self._export_scope(f, params)
        if user_filter:
            error = f.tshark.validate_filter(filters[0], ctx.token)
            if error:
                raise FilterError(error, {"expr": filters[0]})
        options = [*DISSECTION_FORMATS[fmt], *(["-x"] if params.get("bytes") else [])]
        packets = 0
        warnings: list[str] = []
        last_emit = 0.0
        ctx.progress({"phase": "export", "fraction": None})
        with atomic_output(dest) as tmp, tmp.open("wb") as out:
            writer = DissectionWriter(fmt, out)
            for flt in filters:
                writer.next_pass()
                argv = f.tshark.argv(*(["-Y", flt] if flt else []), *options, capture=str(f.path))
                result = StreamResult()
                for line in stream_lines(argv, result, ctx.token):
                    if not writer.line(line):
                        continue
                    packets += 1
                    now = time.monotonic()
                    if expected and now - last_emit >= PROGRESS_INTERVAL_S:
                        last_emit = now
                        fraction = min(0.99, packets / expected)
                        ctx.progress({"phase": "export", "fraction": fraction})
                truncated = any(h in result.stderr for h in _TRUNCATION_HINTS)
                if result.returncode not in (0, None) and not (truncated and result.lines):
                    raise f.tshark.error(
                        result.stderr, result.returncode, "tshark could not dissect the packets"
                    )
                warnings += _stderr_warnings(result.stderr)
            writer.close()
        return {"packets": packets, "filter": label, "format": fmt, "warnings": warnings}

    def _export_bytes(
        self, dest: Path, params: dict[str, Any], ctx: RequestContext
    ) -> dict[str, Any]:
        number = param(params, "number", int)
        source = param(params, "source", int, 0)
        sources = self.packet_detail({"number": number}, ctx)["sources"]
        if not 0 <= source < len(sources):
            raise InvalidParamsError(f"frame {number} has no data source {source}")
        data = bytes.fromhex(sources[source]["hex"])
        with atomic_output(dest) as tmp:
            tmp.write_bytes(data)
        return {"number": number, "source": sources[source]["name"], "bytes": len(data)}

    # ------------------------------------------------------------------ merging

    def merge(self, params: dict[str, Any], ctx: RequestContext) -> dict[str, Any]:
        """Merge capture files into ``dest`` with mergecap: by timestamp, or one
        after another in the given order with ``append`` (a rotated capture's
        files). ``format``: ``pcapng`` (default) or ``pcap``. Needs no open
        capture. The file only appears once complete."""
        inputs = [Path(p).expanduser() for p in str_list(params, "inputs")]
        if len(inputs) < 2:
            raise InvalidParamsError("choose at least two capture files to merge")
        for path in inputs:
            if not path.is_file():
                raise InvalidParamsError(f"capture file not found: {path}")
        fmt = param(params, "format", str, "pcapng")
        if fmt not in CAPTURE_FORMATS:
            raise InvalidParamsError(f"format must be one of {', '.join(CAPTURE_FORMATS)}")
        dest = check_destination(param(params, "dest", str), inputs[0])
        for path in inputs[1:]:
            check_destination(str(dest), path)  # never over one of the inputs
        tshark = self._require_tshark()
        try:
            mergecap = find_tool("mergecap", sibling_of=tshark.path)
        except ToolNotFoundError as exc:
            raise ToolError("merging captures needs mergecap (part of Wireshark)") from exc
        ctx.progress({"phase": "merge", "fraction": None})
        with atomic_output(dest) as tmp:
            argv = [str(mergecap), *(["-a"] if params.get("append") else []), "-F", fmt]
            res = run([*argv, "-w", str(tmp), *map(str, inputs)], ctx.token)
            if res.returncode != 0 or not tmp.exists():
                raise ToolError(res.stderr.strip() or "mergecap failed", res.stderr, res.returncode)
        return {"ok": True, "path": str(dest), "size": dest.stat().st_size, "inputs": len(inputs)}

    # ------------------------------------------------------------------ objects

    def export_objects(self, params: dict[str, Any], ctx: RequestContext) -> dict[str, Any]:
        """Files carried by HTTP, SMB, TFTP, IMF, DICOM and FTP-DATA (see
        objects.py): ``objects`` with ``id``, ``protocol``, ``name``, ``size``,
        and when known the ``frame`` that carried it, ``host`` and ``contentType``.
        One tshark pass (two passes over the file) the first time, then cached;
        works while a streaming open is still indexing."""
        f = self._require_file()
        with self._objects_lock:
            if self._objects is None or self._objects[0] is not f:
                self._objects = (f, self._extract_objects(f, ctx))
            found = self._objects[1]
        return {"objects": [o.to_json(i) for i, o in enumerate(found)]}

    def _extract_objects(self, f: _Open, ctx: RequestContext) -> list[ExportedObject]:
        with self._lock:
            if self._work_dir is None:
                raise NotOpenError()
            folder = self._work_dir / "objects"
        shutil.rmtree(folder, ignore_errors=True)  # (a cancelled earlier run)
        folder.mkdir()
        wanted = list(objects.FIELDS)
        size = max(1, f.info.size)
        overhead = _RECORD_OVERHEAD.get(sniff_format(f.path) or "")
        for _attempt in range(len(wanted)):
            eo = [a for p in objects.PROTOCOLS for a in ("--export-objects", f"{p},{folder / p}")]
            argv = f.tshark.argv(
                "-2", *eo, *_fields_args(wanted), "-E", f"aggregator={objects.AGGREGATOR}",
                capture=str(f.path),
            )  # fmt: skip
            linker = objects.Linker()
            result = StreamResult()
            seen, last = 0, 0.0
            # The first pass prints nothing; the second prints a line per packet.
            ctx.progress({"phase": "objects", "fraction": None})
            for line in stream_lines(argv, result, ctx.token):
                values = dict(
                    zip(wanted, line.decode("utf-8", "replace").split("\t"), strict=False)
                )
                linker.add(values)
                if overhead is not None and values.get("frame.len", "").isdigit():
                    seen += int(values["frame.len"]) + overhead
                    now = time.monotonic()
                    if now - last > 0.2:
                        last = now
                        ctx.progress({"phase": "objects", "fraction": min(1.0, seen / size)})
            if result.returncode not in (0, None) and result.lines == 0:
                rejected = [r for r in _rejected_fields(result.stderr) if r in wanted[2:]]
                if rejected:  # (an older tshark without one of the linking fields)
                    wanted = [w for w in wanted if w not in rejected]
                    shutil.rmtree(folder, ignore_errors=True)
                    folder.mkdir()
                    continue
                raise f.tshark.error(result.stderr, result.returncode, "extracting objects failed")
            return objects.collect(folder, linker)
        raise ToolError("tshark rejected the fields that link objects to packets")

    def save_objects(self, params: dict[str, Any], ctx: RequestContext) -> dict[str, Any]:
        """Save exported objects (``ids`` from export_objects): one object to the
        file ``dest``, or any number into the folder ``dir`` under their own
        names (made safe; ``name (1).ext`` instead of overwriting). Each file
        only appears once complete."""
        f = self._require_file()
        with self._objects_lock:
            found = self._objects[1] if self._objects and self._objects[0] is f else None
        if found is None:
            raise InvalidParamsError("list the objects first (export_objects)")
        ids = params.get("ids")
        if not isinstance(ids, list) or not ids or not all(isinstance(i, int) for i in ids):
            raise InvalidParamsError("ids must be a non-empty list of object ids")
        if any(not 0 <= i < len(found) for i in ids):
            raise InvalidParamsError("unknown object id")
        chosen = [found[i] for i in dict.fromkeys(ids)]
        if "dest" in params:
            if len(chosen) != 1:
                raise InvalidParamsError("dest takes one object; use dir for several")
            targets = [check_destination(param(params, "dest", str), f.path)]
        else:
            folder = Path(param(params, "dir", str)).expanduser()
            if not folder.is_absolute() or not folder.is_dir():
                raise InvalidParamsError(f"not an existing folder: {folder}")
            taken: set[str] = set()
            targets = [
                check_destination(
                    str(objects.unique_path(folder, objects.safe_name(o.name), taken)), f.path
                )
                for o in chosen
            ]
        for i, (obj, dest) in enumerate(zip(chosen, targets, strict=True)):
            ctx.token.raise_if_cancelled()
            ctx.progress({"phase": "save", "fraction": i / len(chosen)})
            with atomic_output(dest) as tmp:
                shutil.copyfile(obj.path, tmp)
        return {"saved": [str(t) for t in targets]}

    # ------------------------------------------------------------------ dissectors

    def check_dissectors(self, params: dict[str, Any], ctx: RequestContext) -> dict[str, Any]:
        """Load Lua scripts against an empty capture and report their errors.

        Fast (no packets are read), so the extension runs it before re-indexing
        on "Reload Dissectors". ``lua`` defaults to the open file's scripts.
        Returns ``errors`` (tshark's Lua messages, ``script`` when identifiable)
        and ``warnings`` (missing files, Lua disabled for root).
        """
        base = self._file.tshark if self._file else self._require_tshark()
        if "lua" in params:
            options = DissectionOptions.from_params(
                str_list(params, "lua"), base.options.decode_as, dict(base.options.prefs)
            )
        else:
            options = base.options
        tshark = base.with_options(options)
        warnings = options.check_scripts()
        errors: list[dict[str, str]] = []
        if options.lua_scripts:
            res = run(tshark.argv(capture=str(EMPTY_CAPTURE.get())), ctx.token)
            for message in _stderr_warnings(res.stderr):
                if message.startswith("Lua:"):  # missing files are in `warnings` already
                    script = script_in_lua_message(options.lua_scripts, message)
                    errors.append({"message": message, **({"script": script} if script else {})})
        return {"scripts": list(options.lua_scripts), "errors": errors, "warnings": warnings}

    def decode_as_options(self, params: dict[str, Any], ctx: RequestContext) -> dict[str, Any]:
        """Valid "Decode As" choices, straight from tshark's own lists.

        Without ``layer``: the layer types (``tcp.port``, ``udp.port``, …).
        With ``layer``: the protocols that layer can be decoded as.
        """
        tshark = self._file.tshark if self._file else self._require_tshark()
        layer = param(params, "layer", str, "").strip()
        if layer and not _FIELD_NAME_RE.match(layer):
            raise InvalidParamsError(f"invalid layer type {layer!r}")
        key = f"decode-as:{layer}"
        cached = self._decode_as.get(key)
        if cached is None:
            # tshark lists the valid choices when given an invalid rule.
            probe = f"{layer}==0,no-such-protocol" if layer else "no-such-layer"
            res = run([str(tshark.path), "-d", probe, "-r", str(EMPTY_CAPTURE.get())], ctx.token)
            if layer and "Unknown layer type" in res.stderr:
                # tshark answered with the layer list, not protocols
                raise InvalidParamsError(f"unknown layer type {layer!r}")
            cached = parse_decode_as_choices(res.stderr)
            self._decode_as.put(key, cached)
        return {"layer": layer or None, "choices": cached}

    def field_index(self, params: dict[str, Any], ctx: RequestContext) -> dict[str, Any]:
        """Field/protocol names from ``tshark -G fields`` for autocomplete.

        Case-insensitive ``prefix`` search; ``limit`` caps each list (the
        catalogue has ~250k entries). Lua dissector fields are included because
        the catalogue is built with the file's ``-X lua_script`` options. Call
        with ``limit: 0`` to warm the cache without transferring anything.
        """
        prefix = param(params, "prefix", str, "")
        limit = max(0, min(param(params, "limit", int, 200), 100_000))
        catalog = self._catalog(ctx)
        return catalog.search(prefix, limit)

    def _catalog(self, ctx: RequestContext) -> FieldCatalog:
        tshark = self._file.tshark if self._file else self._require_tshark()
        key = tshark.options.lua_scripts
        catalog = self._field_index.get(key)
        if catalog is None:
            with self._build_lock:
                catalog = self._field_index.get(key)
                if catalog is None:
                    catalog = FieldCatalog.parse(tshark.field_list(ctx.token))
                    self._field_index.put(key, catalog)
        return catalog


# ---------------------------------------------------------------------- helpers


def _index_error(tshark: Tshark, path: Path, result: StreamResult) -> Exception:
    """The error for an index pass that produced nothing."""
    if _UNSUPPORTED_RE.search(result.stderr):
        return UnsupportedFormatError(
            f"{path.name} is not a capture file that tshark can read",
            {"path": str(path), "stderr": result.stderr},
        )
    return tshark.error(
        result.stderr, result.returncode, f"tshark exited with code {result.returncode}"
    )


def _cache_from(raw: Any) -> IndexCache | None:
    """``{dir, maxBytes?}`` -> the saved-index cache (None: caching off)."""
    if not isinstance(raw, dict) or not isinstance(raw.get("dir"), str) or not raw["dir"]:
        return None
    max_bytes = raw.get("maxBytes", DEFAULT_CACHE_BYTES)
    if isinstance(max_bytes, bool) or not isinstance(max_bytes, int) or max_bytes < 0:
        raise InvalidParamsError("cache.maxBytes must be a non-negative integer")
    return IndexCache(Path(raw["dir"]).expanduser(), max_bytes)


def _personal_folders(folders_output: str) -> list[Path]:
    """tshark's personal configuration and plugin folders (``tshark -G folders``):
    their contents change dissection, so they are part of the saved-index key."""
    wanted = {"Personal configuration", "Personal Plugins", "Personal Lua Plugins"}
    out: list[Path] = []
    for line in folders_output.split("\n"):
        name, sep, value = line.partition(":")
        if sep and name.strip() in wanted and value.strip():
            out.append(Path(value.strip()))
    return out


def _frame_list(params: dict[str, Any], key: str, limit: int = MAX_SELECTION) -> list[int]:
    frames = params.get(key)
    if not isinstance(frames, list) or not all(
        isinstance(n, int) and not isinstance(n, bool) for n in frames
    ):
        raise InvalidParamsError(f"parameter {key!r} must be a list of frame numbers")
    if len(frames) > limit:
        raise InvalidParamsError(f"parameter {key!r} holds more than {limit:,} frames")
    return frames


def _parse_sort(raw: Any) -> tuple[str, bool] | None:
    if raw is None:
        return None
    if not isinstance(raw, dict) or not isinstance(raw.get("field"), str):
        raise InvalidParamsError("sort must be {field: string, desc?: boolean}")
    fld = raw["field"]
    if not _FIELD_NAME_RE.match(fld):
        raise InvalidParamsError(f"invalid sort field {fld!r}")
    return fld, bool(raw.get("desc", False))


def _drop_rejected(
    pairs: list[tuple[str, str]],
    rejected: Sequence[str],
    legacy: dict[str, str],
    custom: list[str],
    warnings: list[str],
) -> bool:
    """Swap in legacy column names / drop unknown custom fields. True if anything changed."""
    changed = False
    for bad in rejected:
        for i, (name, actual) in enumerate(pairs):
            if actual != bad:
                continue
            if legacy.get(name, name) != actual:
                pairs[i] = (name, legacy[name])
            elif name in custom:
                del pairs[i]
                custom.remove(name)
                warnings.append(f"Unknown field removed from columns: {name}")
            else:
                continue
            changed = True
            break
    return changed


def _finish_index_pass(
    info: CaptureInfo,
    result: StreamResult,
    bad_lines: int,
    frames: int,
    inline: _InlineColoring | None,
) -> None:
    """Warnings and coloring results of a finished index pass."""
    if bad_lines:
        info.warnings.append(f"{bad_lines} unparseable line(s) in tshark output skipped")
    if result.stderr:
        info.warnings += _stderr_warnings(result.stderr)
    if inline is not None:
        inline.errors.update(coloring.parse_compile_errors(result.stderr))
        while len(inline.colors) <= frames:  # one byte per frame, like set_coloring
            inline.colors.append(0)


def _names_param(params: dict[str, Any]) -> dict[str, Any] | None:
    """The optional ``names`` switches (pcapViewer.nameResolution.*)."""
    names = params.get("names")
    if names is not None and not isinstance(names, dict):
        raise InvalidParamsError("parameter 'names' must be dict")
    return names


def _rejected_fields(stderr: str) -> list[str]:
    m = _INVALID_FIELDS_RE.search(stderr)
    return m["names"].split() if m else []


# Lua names a chunk by its path, shortened to "...<tail>" when long.
_LUA_CHUNK_RE = re.compile(r"(?P<dots>\.\.\.)?(?P<path>[^\s:]*(?::[\\/][^\s:]*)?\.lua):\d+:")


def script_in_lua_message(scripts: Sequence[str], message: str) -> str | None:
    """Which configured script a Lua error message is about, if identifiable."""
    for script in scripts:
        if script in message:
            return script
    for m in _LUA_CHUNK_RE.finditer(message):
        tail = m["path"]
        hits = [
            s for s in scripts if s.endswith(tail) or (not m["dots"] and s.endswith(f"/{tail}"))
        ]
        if len(hits) == 1:
            return hits[0]
    return None


_CHOICE_RE = re.compile(r"^\t(?P<name>\S+) \((?P<desc>.*)\)$")


def parse_decode_as_choices(stderr: str) -> list[dict[str, str]]:
    """Parse the "Valid layer types are:" / "Valid protocols for layer type … are:"
    lists tshark prints for an invalid ``-d`` rule (one ``\tname (description)`` per line).
    """
    out: list[dict[str, str]] = []
    for line in stderr.split("\n"):
        m = _CHOICE_RE.match(line.rstrip("\r"))
        if m:
            out.append({"name": m["name"], "desc": m["desc"]})
    return out


def _stderr_warnings(stderr: str) -> list[str]:
    """Group tshark stderr into user-facing warnings (Lua errors, truncation...).
    Coloring rules that don't compile are reported per rule instead."""
    out: list[str] = []
    for block in re.split(r"\n(?=tshark: )", stderr.strip()):
        text = block.strip()
        if text and "in colorfilters file" not in text:
            out.append(text.removeprefix("tshark: "))
    return out


def _readable_capture(raw: str) -> Path:
    """The capture's path, once we could read from it ourselves (a sandboxed
    tshark's permission errors are explained separately)."""
    path = Path(raw).expanduser()
    if not path.is_file():
        raise InvalidParamsError(f"capture file not found: {path}")
    try:
        with path.open("rb") as fh:
            fh.read(1)
    except PermissionError as exc:
        raise InvalidParamsError(
            f"cannot read {path}: permission denied (check the file's permissions)"
        ) from exc
    return path


_COLOR_FIELD = "frame.coloring_rule.name"


def _parse_rules(raw: list[Any]) -> tuple[list[coloring.ColorRule | str], dict[int, str]]:
    """Coloring rules (at most MAX_RULES) and the reasons some can't be used."""
    rules = [coloring.parse_rule(r) for r in raw[: coloring.MAX_RULES]]
    errors = {i: r for i, r in enumerate(rules) if isinstance(r, str)}
    errors.update({i: "too many coloring rules" for i in range(coloring.MAX_RULES, len(raw))})
    return rules, errors


def _inline_coloring(raw: Any) -> _InlineColoring | None:
    """``open``'s ``coloring: {rules}`` (None without valid rules)."""
    if raw is None:
        return None
    if not isinstance(raw, dict) or not isinstance(raw.get("rules"), list):
        raise InvalidParamsError("parameter 'coloring' must be {rules: [...]}")
    rules, errors = _parse_rules(raw["rules"])
    if not any(isinstance(r, coloring.ColorRule) for r in rules):
        return None
    return _InlineColoring(raw["rules"], rules, errors)


def _read_rows(
    lines: Iterable[bytes],
    rows: RowStore,
    tracker: _PassProgress,
    *,
    base: bool,
    inline: _InlineColoring | None,
    unresolved: bool = False,
) -> int:
    """Store an index pass's rows (and colors); returns the unparseable lines.

    With ``unresolved``, the row ends with the UNRESOLVED_FIELDS, which are
    blanked when they equal the Source/Destination shown (the usual case)."""
    bad_lines = 0
    for line in lines:
        parts = line.split(b"\t", 1)
        try:
            number = int(parts[0])
        except ValueError:
            bad_lines += 1
            continue
        row = line
        if inline is not None:
            row, _sep, rule = line.rpartition(b"\t")
            _add_color(inline, number, rule)  # before the row is published
        if unresolved:
            row = _blank_same_addresses(row)
        rest = row if base else (parts[1] if len(parts) > 1 else b"")
        rows.append(number, rest)
        tracker.row(number, rest)
    return bad_lines


def _add_addresses(
    fields: Sequence[str], base_rows: Sequence[list[str]], rows: list[dict[str, Any]]
) -> None:
    """Give rows whose Source/Destination show names their ``addresses``
    ([source, destination], for cell filters)."""
    if UNRESOLVED_FIELDS[0] not in fields:
        return
    at = fields.index(UNRESOLVED_FIELDS[0])
    for base_row, row in zip(base_rows, rows, strict=True):
        src, dst = [*base_row[at : at + 2], "", ""][:2]
        if src or dst:
            cells = row["cells"]
            row["addresses"] = [src or cells[2], dst or cells[3]]


def _blank_same_addresses(row: bytes) -> bytes:
    """Blank the trailing unresolved addresses that equal Source/Destination."""
    head, src, dst = row.rsplit(b"\t", 2) if row.count(b"\t") >= 2 else (row, b"", b"")
    cells = head.split(b"\t", 4)
    if len(cells) < 4 or (src != cells[2] and dst != cells[3]):
        return row
    return b"\t".join((head, b"" if src == cells[2] else src, b"" if dst == cells[3] else dst))


def _add_color(inline: _InlineColoring, number: int, rule: bytes) -> None:
    """Record frame ``number``'s matching rule (tshark names rules by index)."""
    colors = inline.colors
    while len(colors) < number:  # (frames are dense; pad like the row store would)
        colors.append(0)
    idx = int(rule) if rule.isdigit() else -1
    if 0 <= idx < len(inline.rules):
        colors.append(idx + 1)
        inline.colored += 1
    else:
        colors.append(0)


def parse_capinfos(text: str) -> dict[str, Any]:
    """Parse ``capinfos -T -M -a -e -E -S -t`` table output (header row + value row)."""
    lines = [ln for ln in text.splitlines() if ln.strip()]
    if len(lines) < 2:
        return {}
    header = lines[0].split("\t")
    values = lines[1].split("\t")
    extra = len(values) - len(header)
    if extra > 0:  # the file name (first column) contained tabs
        values = ["\t".join(values[: extra + 1]), *values[extra + 1 :]]
    row = dict(zip(header, values, strict=False))

    def num(key: str) -> float | None:
        try:
            return float(row.get(key, ""))
        except ValueError:
            return None

    return {
        "start_time": num("Start time"),
        "end_time": num("End time"),
        "link_type": row.get("File encapsulation") or None,
        "file_type": row.get("File type") or None,
    }


def rpc_methods(service: PcapService) -> dict[str, Callable[[dict[str, Any], RequestContext], Any]]:
    return {
        "initialize": service.initialize,
        "open": service.open,
        "capture_info": service.capture_info,
        "validate_filter": service.validate_filter,
        "set_filter": service.set_filter,
        "stop_filter": service.stop_filter,
        "list_packets": service.list_packets,
        "find_frame": service.find_frame,
        "view_frames": service.view_frames,
        "packet_detail": service.packet_detail,
        "field_index": service.field_index,
        "follow_stream": service.follow_stream,
        "stats": service.stats,
        "check_dissectors": service.check_dissectors,
        "decode_as_options": service.decode_as_options,
        "set_coloring": service.set_coloring,
        "find_packet": service.find_packet,
        "neighbor_frame": service.neighbor_frame,
        "mark_packets": service.mark_packets,
        "unmark_all": service.unmark_all,
        "field_types": service.field_types,
        "export": service.export,
        "merge": service.merge,
        "export_objects": service.export_objects,
        "save_objects": service.save_objects,
        "close": service.close,
    }


__all__ = [
    "BASE_COLUMNS",
    "PcapService",
    "RpcError",
    "parse_capinfos",
    "parse_field_list",
    "rpc_methods",
]
