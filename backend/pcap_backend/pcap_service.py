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
"""

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

from . import pdml, stats
from .cache import FrameIndex, LruCache, RowStore, sort_frames
from .cancellation import CancelledError, CancelToken
from .fields import FieldCatalog, parse_field_list
from .protocol import (
    FilterError,
    InvalidParamsError,
    NotOpenError,
    RequestContext,
    RpcError,
    param,
    str_list,
)
from .tshark import (
    EMPTY_CAPTURE,
    DissectionOptions,
    StreamResult,
    ToolError,
    Tshark,
    run,
    stream_lines,
)

MAX_PAGE = 5000
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

# Per-record overhead used to estimate progress from frame lengths.
_RECORD_OVERHEAD = {"pcap": 16, "pcapng": 32}


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
        overhead = _RECORD_OVERHEAD["pcapng" if path.suffix.lower() == ".pcapng" else "pcap"]
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
                    if base:
                        cells = rest.split(b"\t", _LEN_IDX + 1)
                        if len(cells) > _LEN_IDX and cells[_LEN_IDX].isdigit():
                            bytes_seen += int(cells[_LEN_IDX]) + overhead
                    now = time.monotonic()
                    if now - last_emit >= PROGRESS_INTERVAL_S:
                        last_emit = now
                        fraction = min(0.99, bytes_seen / size) if base else None
                        ctx.progress({"phase": "index", "frames": number, "fraction": fraction})
            finally:
                rows.finish()
            if result.lines == 0 and result.returncode not in (0, None):
                rows.close()
                store_path.unlink(missing_ok=True)
                rejected = _rejected_fields(result.stderr)
                if rejected and _drop_rejected(pairs, rejected, legacy, custom, info.warnings):
                    continue
                raise ToolError(
                    result.stderr or f"tshark exited with code {result.returncode}",
                    result.stderr,
                    result.returncode,
                )
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
        rows = [
            {"number": n, "cells": base_rows[i][:n_base] + [col[i] for col in extra_cols]}
            for i, n in enumerate(frames)
        ]
        return {
            "offset": offset,
            "rows": rows,
            "total": len(view_ordered),
            "filterId": view.filter_id,
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
            raise ToolError(
                pdml_res.stderr or f"tshark returned no detail for frame {number}",
                pdml_res.stderr,
                pdml_res.returncode,
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
            raise ToolError(
                result.stderr or "tshark follow failed", result.stderr, result.returncode
            )
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
            raise ToolError(res.stderr or f"tshark -z {spec} failed", res.stderr, res.returncode)
        return text

    # ------------------------------------------------------------------ fields

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
