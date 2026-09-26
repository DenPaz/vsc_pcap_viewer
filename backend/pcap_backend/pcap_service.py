"""Capture-file service: indexing, filtering, paging, sorting and packet detail.

One ``PcapService`` serves one capture file (the extension starts one backend
process per open editor). All heavy lifting is delegated to tshark:

* ``open`` runs a single ``-T fields`` pass and stores the packet-list columns
  on disk (:class:`~pcap_backend.cache.RowStore`).
* ``set_filter`` runs ``-Y <expr> -T fields -e frame.number`` once and keeps the
  matching frame numbers; scrolling never re-runs tshark.
* ``packet_detail`` runs ``-T pdml`` and ``-x`` for one frame, reading only up
  to that frame (``-c N``) so dissection state from earlier packets (TCP
  reassembly etc.) is still correct.
* ``set_coloring`` runs one ``--color`` pass and keeps a one-byte rule index
  per frame; ``list_packets`` rows then carry their ``color``.
* ``export`` writes filtered captures with tshark (``-Y … -w``) and the packet
  list (CSV/JSON) straight from the row store.
"""

import os
import re
import shutil
import tempfile
import threading
import time
from array import array
from collections.abc import Callable, Iterable, Sequence
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from . import coloring, navigation, pdml, stats
from .cache import FrameIndex, LruCache, RowStore, sort_frames
from .cancellation import CancelledError, CancelToken
from .export import (
    CAPTURE_FORMATS,
    EXPORT_KINDS,
    LIST_FORMATS,
    PacketListWriter,
    atomic_output,
    check_destination,
)
from .fields import FieldCatalog, parse_field_list
from .protocol import (
    FilterError,
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
PROGRESS_INTERVAL_S = 0.2


@dataclass(frozen=True, slots=True)
class Column:
    id: str
    title: str
    field: str
    legacy_field: str
    numeric: bool = False


BASE_COLUMNS: tuple[Column, ...] = (
    Column("number", "No.", "frame.number", "frame.number", numeric=True),
    Column("time", "Time", "frame.time_relative", "frame.time_relative", numeric=True),
    Column("source", "Source", "_ws.col.def_src", "_ws.col.Source"),
    Column("destination", "Destination", "_ws.col.def_dst", "_ws.col.Destination"),
    Column("protocol", "Protocol", "_ws.col.protocol", "_ws.col.Protocol"),
    Column("length", "Length", "frame.len", "frame.len", numeric=True),
    Column("info", "Info", "_ws.col.info", "_ws.col.Info"),
)
_LEN_IDX = 5  # position of frame.len in BASE_COLUMNS

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


@dataclass(slots=True)
class _View:
    filter_id: int
    expr: str
    matched: FrameIndex
    sort: tuple[str, bool] | None
    ordered: FrameIndex


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
        self._filter_seq = 0
        self._next_filter_id = 0
        self._store_seq = 0
        self._filters: LruCache[str, FrameIndex] = LruCache(max_cached_frames, lambda v: v.cost)
        self._sorts: LruCache[tuple[str, str, bool], FrameIndex] = LruCache(
            max_cached_frames, lambda v: v.cost
        )
        self._sort_columns: LruCache[str, list[str]] = LruCache(2)
        self._details: LruCache[int, dict[str, Any]] = LruCache(detail_cache_size)
        self._field_index: LruCache[tuple[str, ...], FieldCatalog] = LruCache(2)
        self._decode_as: LruCache[str, list[dict[str, str]]] = LruCache(32)
        # Coloring: rule index + 1 per frame (0 = no rule), from the latest set_coloring.
        self._colors: array[int] | None = None
        self._coloring_id = 0
        self._coloring_seq = 0
        # Marked frames (Wireshark's Ctrl+M): per session, not persisted.
        self._marks: set[int] = set()
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
        if self._file is not None:
            self._file.base.rows.close()
            for s in self._file.extra:
                s.rows.close()
        self._file = None
        self._view = None
        self._colors = None
        self._marks = set()
        for cache in (self._filters, self._sorts, self._sort_columns, self._details):
            cache.clear()
        if self._work_dir is not None:
            shutil.rmtree(self._work_dir, ignore_errors=True)
            self._work_dir = None

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
            return self._file, self._view

    # ------------------------------------------------------------------ open

    def open(self, params: dict[str, Any], ctx: RequestContext) -> dict[str, Any]:
        path = Path(param(params, "path", str)).expanduser()
        if not path.is_file():
            raise InvalidParamsError(f"capture file not found: {path}")
        try:
            with path.open("rb") as fh:
                fh.read(1)
        except PermissionError as exc:
            raise InvalidParamsError(
                f"cannot read {path}: permission denied (check the file's permissions)"
            ) from exc
        options = DissectionOptions.from_params(
            str_list(params, "lua"),
            str_list(params, "decodeAs"),
            param(params, "prefs", dict, {}),
        )
        base_fields = {c.field for c in BASE_COLUMNS}
        columns = [
            c for c in self._check_fields(str_list(params, "columns")) if c not in base_fields
        ]
        requested_columns = list(columns)  # _index_pass removes fields tshark rejects
        tshark = self._require_tshark().with_options(options)

        with self._lock:
            self._close_file()
            self._work_dir = Path(tempfile.mkdtemp(prefix="pcapviewer-"))
            work_dir = self._work_dir

        info = CaptureInfo(path=str(path), size=path.stat().st_size)
        info.warnings += options.check_scripts()
        info_future = self._pool.submit(self._capinfos, tshark, path, ctx.token)

        base = self._index_pass(tshark, path, work_dir, columns, info, ctx, base=True)
        info.frames = len(base.rows)

        meta = info_future.result()
        for key in ("start_time", "end_time", "link_type", "file_type"):
            if getattr(info, key) is None and meta.get(key) is not None:
                setattr(info, key, meta[key])
        if info.start_time is None and info.frames:
            info.start_time = self._first_epoch(tshark, path, ctx.token)

        with self._lock:
            self._file = _Open(
                path,
                tshark,
                info,
                base,
                columns=columns,
                rejected={c for c in requested_columns if c not in columns},
            )
            self._next_filter_id += 1
            everything = FrameIndex.all(info.frames)
            self._view = _View(self._next_filter_id, "", everything, None, everything)
        result = info.to_json()
        result["columns"] = self._column_descriptors(columns)
        result["filterId"] = self._view.filter_id
        return result

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
    ) -> _Store:
        """Run one ``-T fields`` pass, writing every frame's row to a RowStore.

        Retries without fields tshark rejects (unknown custom columns, or the
        column field names of older tshark versions).
        """
        # (name the caller asked for, name actually passed to tshark)
        pairs = [(c.field, c.field) for c in BASE_COLUMNS] if base else []
        pairs += [(fld, fld) for fld in custom]
        legacy = {c.field: c.legacy_field for c in BASE_COLUMNS}
        size = max(1, info.size)
        overhead = _RECORD_OVERHEAD.get(sniff_format(path) or "") if base else None
        for _attempt in range(3):
            self._store_seq += 1
            store_path = work_dir / f"rows-{self._store_seq}.tsv"
            actual = [a for _, a in pairs]
            rows = RowStore(store_path, actual)
            result = StreamResult()
            # tshark blanks duplicated -e fields, so only prepend frame.number
            # when it is not already the first column.
            fields = actual if base else ["frame.number", *actual]
            argv = tshark.argv(*_fields_args(fields), capture=str(path))
            last_emit = 0.0
            bytes_seen = 0
            bad_lines = 0
            try:
                for line in stream_lines(argv, result, ctx.token):
                    parts = line.split(b"\t", 1)
                    try:
                        number = int(parts[0])
                    except ValueError:
                        bad_lines += 1
                        continue
                    rest = line if base else (parts[1] if len(parts) > 1 else b"")
                    rows.append(number, rest)
                    if overhead:
                        cells = rest.split(b"\t", _LEN_IDX + 1)
                        if len(cells) > _LEN_IDX and cells[_LEN_IDX].isdigit():
                            bytes_seen += int(cells[_LEN_IDX]) + overhead
                    now = time.monotonic()
                    if now - last_emit >= PROGRESS_INTERVAL_S:
                        last_emit = now
                        fraction = min(0.99, bytes_seen / size) if overhead else None
                        ctx.progress({"phase": "index", "frames": number, "fraction": fraction})
            finally:
                rows.finish()
            if result.lines == 0 and result.returncode not in (0, None):
                rows.close()
                store_path.unlink(missing_ok=True)
                rejected = _rejected_fields(result.stderr)
                if rejected and _drop_rejected(pairs, rejected, legacy, custom, info.warnings):
                    continue
                raise _index_error(tshark, path, result)
            if bad_lines:
                info.warnings.append(f"{bad_lines} unparseable line(s) in tshark output skipped")
            if result.stderr:
                info.warnings += _stderr_warnings(result.stderr)
            ctx.progress({"phase": "index", "frames": len(rows), "fraction": 1.0})
            # Expose columns under the names the caller asked for.
            return _Store(rows, tuple(name for name, _ in pairs))
        raise ToolError("tshark rejected the requested columns")

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
        expr = param(params, "expr", str, "").strip()
        f = self._require_file()
        with self._lock:
            self._filter_seq += 1
            seq = self._filter_seq
            current = self._view
        if current is not None and current.expr == expr:
            return self._filter_result(current)

        matched = self._filters.get(expr) if expr else FrameIndex.all(f.info.frames)
        if matched is None:
            error = f.tshark.validate_filter(expr, ctx.token)
            if error:
                raise FilterError(error, {"expr": expr})
            matched = self._run_filter(f, expr, ctx)
            self._filters.put(expr, matched)

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
            self._view = view
        return self._filter_result(view)

    def _filter_result(self, view: _View) -> dict[str, Any]:
        f = self._require_file()
        return {
            "expr": view.expr,
            "matchCount": len(view.matched),
            "total": f.info.frames,
            "filterId": view.filter_id,
        }

    def _run_filter(self, f: _Open, expr: str, ctx: RequestContext) -> FrameIndex:
        frames = array("I")
        result = StreamResult()
        argv = f.tshark.argv("-Y", expr, "-T", "fields", "-e", "frame.number", capture=str(f.path))
        total = max(1, f.info.frames)
        last_emit = 0.0
        for line in stream_lines(argv, result, ctx.token):
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

        ``columns`` is the full list of custom column fields wanted after the
        seven base columns (default: the ones given to ``open``). Fields not
        indexed yet are extracted with one extra tshark pass, then cached.
        """
        offset = param(params, "offset", int, 0)
        limit = param(params, "limit", int, 200)
        if offset < 0 or limit < 0:
            raise InvalidParamsError("offset and limit must be non-negative")
        limit = min(limit, MAX_PAGE)
        sort = _parse_sort(params.get("sort"))
        f, view = self._require_view()
        base_fields = {c.field for c in BASE_COLUMNS}
        if "columns" in params:
            extra_fields = [
                c for c in self._check_fields(str_list(params, "columns")) if c not in base_fields
            ]
        else:
            extra_fields = list(f.columns)
        self._ensure_columns(f, extra_fields, ctx)
        if sort != view.sort:
            ordered = self._sorted(f, view, sort, ctx) if sort else view.matched
            with self._lock:
                if self._view is view:
                    view.sort = sort
                    view.ordered = ordered
            view_ordered = ordered
        else:
            view_ordered = view.ordered

        frames = view_ordered.slice(offset, limit)
        rejected = [fld for fld in extra_fields if fld in f.rejected]
        n_base = len(BASE_COLUMNS)
        base_rows = f.base.rows.get_many(frames)
        extra_cols = [self._column_cells(f, fld, frames) for fld in extra_fields]
        rows: list[dict[str, Any]] = [
            {"number": n, "cells": base_rows[i][:n_base] + [col[i] for col in extra_cols]}
            for i, n in enumerate(frames)
        ]
        if "timeFormat" in params:
            times = self._display_times(
                f,
                view_ordered,
                offset,
                frames,
                [r["cells"][1] for r in rows],
                param(params, "timeFormat", str),
                params.get("timeRef"),
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

    def find_frame(self, params: dict[str, Any], _ctx: RequestContext) -> dict[str, Any]:
        """Row index of a frame in the current view (for "go to packet")."""
        number = param(params, "number", int)
        _f, view = self._require_view()
        return {"index": view.ordered.position_of(number), "filterId": view.filter_id}

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
        numeric = next((c.numeric for c in BASE_COLUMNS if c.field == fld), None)
        ordered = sort_frames(view.matched.frames(), values, desc, numeric=numeric or None)
        self._sorts.put(key, ordered)
        return ordered

    # ------------------------------------------------------------------ time formats

    def _display_times(
        self,
        f: _Open,
        ordered: FrameIndex,
        offset: int,
        frames: list[int],
        relative: list[str],
        fmt: str,
        ref: Any,
        ctx: RequestContext,
    ) -> list[str]:
        """Time column text for one page in ``fmt`` (see navigation.TIME_FORMATS).

        Everything but plain "seconds since beginning" needs frame.time_epoch,
        extracted once into the row store. "Since previous displayed" follows the
        current filter and sort order: the previous row of the view, not
        tshark's frame.time_delta_displayed from the unfiltered pass.
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
        prev_row: int | None = None
        if fmt == "delta_displayed" and offset > 0 and frames:
            prev_row = ordered.slice(offset - 1, 1)[0]
            need.add(prev_row)
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
                p = epoch.get(prev_row) if prev_row is not None else None
                out.append(navigation.format_seconds(e - p) if p is not None else zero)
            elif fmt == "delta_captured":
                p = epoch.get(n - 1)
                out.append(navigation.format_seconds(e - p) if p is not None else zero)
            elif fmt == "epoch":
                out.append(navigation.format_seconds(e))
            else:
                out.append(navigation.format_absolute(e, utc=fmt == "utc"))
            prev_row = n
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
        ordered = view.ordered
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
        frame = param(params, "frame", int)
        direction = param(params, "direction", str, "next")
        if direction not in ("next", "previous"):
            raise InvalidParamsError("direction must be next or previous")
        f, view = self._require_view()
        pos = view.ordered.position_of(frame)
        if pos is None:
            raise InvalidParamsError(f"packet {frame} is not displayed")
        self._ensure_columns(f, ["tcp.stream", "udp.stream"], ctx)
        key = self._conversation_keys(f, [frame])[0]
        result: dict[str, Any] = {"frame": None, "index": None, "filterId": view.filter_id}
        if key is None:
            return result
        seq = view.ordered.frames()
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
        """Mark (``mark: true``), unmark (``false``) or toggle (omitted) ``frames``."""
        frames = params.get("frames")
        if not isinstance(frames, list) or not all(
            isinstance(n, int) and not isinstance(n, bool) for n in frames
        ):
            raise InvalidParamsError("parameter 'frames' must be a list of frame numbers")
        f = self._require_file()
        mark = params.get("mark")
        with self._lock:
            for n in frames:
                if not 1 <= n <= f.info.frames:
                    continue
                on = (n not in self._marks) if mark is None else bool(mark)
                if on:
                    self._marks.add(n)
                else:
                    self._marks.discard(n)
            return {
                "count": len(self._marks),
                "marked": [n for n in frames if n in self._marks],
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
        number = param(params, "number", int)
        f = self._require_file()
        if not 1 <= number <= f.info.frames:
            raise InvalidParamsError(f"frame {number} out of range 1..{f.info.frames}")
        cached = self._details.get(number)
        if cached is not None:
            return cached
        select = ["-c", str(number), "-Y", f"frame.number=={number}"]
        pdml_argv = f.tshark.argv(*select, "-T", "pdml", capture=str(f.path))
        hex_argv = f.tshark.argv(*select, "-x", capture=str(f.path))
        hex_future = self._pool.submit(run, hex_argv, ctx.token)
        pdml_res = run(pdml_argv, ctx.token)
        hex_res = hex_future.result()
        if not pdml_res.stdout.strip():
            raise f.tshark.error(
                pdml_res.stderr,
                pdml_res.returncode,
                f"tshark returned no detail for frame {number}",
            )
        sources = pdml.parse_hexdump(hex_res.stdout.decode("utf-8", "replace"))
        tree = pdml.parse_pdml(pdml_res.stdout, source_count=max(1, len(sources)))
        warnings = _stderr_warnings(pdml_res.stderr)
        detail = {
            "number": number,
            "tree": tree,
            "sources": [s.to_json() for s in sources],
            "warnings": warnings,
        }
        self._details.put(number, detail)
        return detail

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

        argv = f.tshark.argv("-q", "-z", f"follow,{proto},raw,{stream}", capture=str(f.path))
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
        if not 1 <= frame <= f.info.frames:
            raise InvalidParamsError(f"frame {frame} out of range 1..{f.info.frames}")
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
        res = run(f.tshark.argv("-q", "-z", spec, capture=str(f.path)), ctx.token)
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
        with self._lock:
            self._coloring_seq += 1
            seq = self._coloring_seq
        rules = [coloring.parse_rule(r) for r in raw[: coloring.MAX_RULES]]
        errors = {i: r for i, r in enumerate(rules) if isinstance(r, str)}
        errors.update({i: "too many coloring rules" for i in range(coloring.MAX_RULES, len(raw))})
        valid = sum(isinstance(r, coloring.ColorRule) for r in rules)
        colors: array[int] | None = None
        colored = 0
        if valid:
            colors = array("B", bytes(f.info.frames + 1))
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
                raise f.tshark.error(
                    result.stderr, result.returncode, "tshark coloring pass failed"
                )
            errors.update(coloring.parse_compile_errors(result.stderr))
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

    # ------------------------------------------------------------------ export

    def export(self, params: dict[str, Any], ctx: RequestContext) -> dict[str, Any]:
        """Write an export file at ``dest`` (absolute path, never the open capture).

        ``kind``:

        * ``pcapng`` / ``pcap``: packets matching ``filter`` (default: the current
          display filter; ``""`` for all packets), written by tshark.
        * ``csv`` / ``json``: the packet list of the current view, in its current
          order, with the base columns plus ``columns`` (custom fields; titles in
          the parallel ``titles`` list).
        * ``bytes``: the raw bytes of frame ``number`` (data ``source`` index,
          default 0: the frame itself).

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
        else:
            result = self._export_bytes(dest, params, ctx)
        result.update({"ok": True, "path": str(dest), "size": dest.stat().st_size})
        return result

    def _export_capture(
        self, f: _Open, fmt: str, dest: Path, params: dict[str, Any], ctx: RequestContext
    ) -> dict[str, Any]:
        if params.get("marked"):
            return self._export_marked(f, fmt, dest, ctx)
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

    def _export_marked(self, f: _Open, fmt: str, dest: Path, ctx: RequestContext) -> dict[str, Any]:
        """Marked frames to a capture: ``frame.number in {...}`` (ranges compressed).

        A filter longer than MAX_FILTER_ARG would overflow the command line
        (Windows caps it at 32767 characters), so big mark sets are written in
        chunks and joined in frame order with ``mergecap -a``.
        """
        with self._lock:
            marks = sorted(self._marks)
        if not marks:
            raise InvalidParamsError("No packets are marked")
        filters = navigation.frame_set_filters(marks, MAX_FILTER_ARG)
        if len(filters) == 1:
            result = self._export_capture(f, fmt, dest, {"filter": filters[0]}, ctx)
            result["filter"] = "marked packets"
            return result
        try:
            mergecap = find_tool("mergecap", sibling_of=f.tshark.path)
        except ToolNotFoundError as exc:
            raise ToolError(
                f"{len(marks):,} marked packets need mergecap (part of Wireshark), "
                "which was not found; mark fewer packets or install mergecap"
            ) from exc
        assert self._work_dir is not None
        parts: list[Path] = []
        packets = 0
        warnings: list[str] = []
        try:
            for i, flt in enumerate(filters):
                ctx.token.raise_if_cancelled()
                part = self._work_dir / f"marked-{i}.{fmt}"
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
        return {"packets": packets, "filter": "marked packets", "warnings": warnings}

    def _export_list(
        self, f: _Open, fmt: str, dest: Path, params: dict[str, Any], ctx: RequestContext
    ) -> dict[str, Any]:
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
        return {"packets": total, "filter": view.expr, "columns": keys}

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
    """Group tshark stderr into user-facing warnings (Lua errors, truncation...)."""
    out: list[str] = []
    for block in re.split(r"\n(?=tshark: )", stderr.strip()):
        text = block.strip()
        if text:
            out.append(text.removeprefix("tshark: "))
    return out


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
        "list_packets": service.list_packets,
        "find_frame": service.find_frame,
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
