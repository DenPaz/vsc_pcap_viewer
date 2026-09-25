"""Caches that let the packet list page through huge captures without re-running tshark.

* :class:`RowStore` keeps tshark's ``-T fields`` output on disk and an in-memory
  array of line offsets, so any frame's row is one ``seek`` + ``readline`` away.
  Memory cost is 8 bytes per frame (8 MB per million packets).
* :class:`FrameIndex` is the ordered list of frame numbers visible under the
  current filter/sort (4 bytes per entry), sliced for ``list_packets``.
* :class:`LruCache` bounds everything else (per-filter indexes, sort orders,
  packet details) by an explicit cost budget.
"""

from __future__ import annotations

import threading
from array import array
from collections import OrderedDict
from collections.abc import Callable, Iterable, Sequence
from pathlib import Path
from typing import BinaryIO, Generic, TypeVar

K = TypeVar("K")
V = TypeVar("V")


class RowStore:
    """Append-only on-disk table of tab-separated tshark field rows, keyed by frame number.

    Frame numbers from a capture file are dense (1..N), so the offset of frame
    ``n`` lives at index ``n - 1``.
    """

    def __init__(self, path: Path, fields: Sequence[str]) -> None:
        self.path = path
        self.fields: tuple[str, ...] = tuple(fields)
        self._offsets = array("Q")
        self._writer = path.open("wb")
        self._pos = 0
        self._reader: BinaryIO | None = None
        self._lock = threading.Lock()

    def append(self, frame_number: int, line: bytes) -> None:
        """Append the row for ``frame_number`` (``line`` without trailing newline)."""
        expected = len(self._offsets) + 1
        if frame_number != expected:
            # Should not happen for file reads; pad so indexing stays positional.
            if frame_number < expected:
                raise ValueError(f"frame {frame_number} out of order (expected {expected})")
            tabs = b"\t" * (len(self.fields) - 1)
            for n in range(expected, frame_number):
                self._write(str(n).encode() + tabs)
        self._write(line)

    def _write(self, line: bytes) -> None:
        self._offsets.append(self._pos)
        self._writer.write(line)
        self._writer.write(b"\n")
        self._pos += len(line) + 1

    def finish(self) -> None:
        self._writer.close()

    def __len__(self) -> int:
        return len(self._offsets)

    def get(self, frame_number: int) -> list[str]:
        return self.get_many([frame_number])[0]

    def get_many(self, frame_numbers: Iterable[int]) -> list[list[str]]:
        rows: list[list[str]] = []
        width = len(self.fields)
        with self._lock:
            fh = self._open_reader()
            for n in frame_numbers:
                if not 1 <= n <= len(self._offsets):
                    rows.append([""] * width)
                    continue
                fh.seek(self._offsets[n - 1])
                cells = fh.readline().rstrip(b"\n").decode("utf-8", "replace").split("\t")
                if len(cells) < width:
                    cells += [""] * (width - len(cells))
                rows.append(cells[:width])
        return rows

    def column(self, field: str) -> list[str]:
        """Read one column for every frame (used for sorting)."""
        idx = self.fields.index(field)
        out: list[str] = []
        with self.path.open("rb") as fh:
            for raw in fh:
                cells = raw.rstrip(b"\n").split(b"\t")
                out.append(cells[idx].decode("utf-8", "replace") if idx < len(cells) else "")
        return out

    def _open_reader(self) -> BinaryIO:
        if self._reader is None:
            self._reader = self.path.open("rb")
        return self._reader

    def close(self) -> None:
        with self._lock:
            if not self._writer.closed:
                self._writer.close()
            if self._reader is not None:
                self._reader.close()
                self._reader = None


class FrameIndex:
    """Ordered frame numbers visible in the list (after filter and sort).

    ``FrameIndex.all(n)`` represents the unfiltered, unsorted view without
    materialising an array.
    """

    __slots__ = ("_frames", "_total")

    def __init__(self, frames: array[int] | None, total: int) -> None:
        self._frames = frames
        self._total = total if frames is None else len(frames)

    @classmethod
    def all(cls, total: int) -> FrameIndex:
        return cls(None, total)

    @classmethod
    def of(cls, frames: Iterable[int]) -> FrameIndex:
        arr = array("I", frames)
        return cls(arr, len(arr))

    @property
    def is_identity(self) -> bool:
        return self._frames is None

    def __len__(self) -> int:
        return self._total

    def slice(self, offset: int, limit: int) -> list[int]:
        start = max(0, offset)
        stop = min(self._total, start + max(0, limit))
        if start >= stop:
            return []
        if self._frames is None:
            return list(range(start + 1, stop + 1))
        return self._frames[start:stop].tolist()

    def frames(self) -> Sequence[int]:
        return range(1, self._total + 1) if self._frames is None else self._frames

    def position_of(self, frame_number: int) -> int | None:
        """Index of ``frame_number`` in this view, or ``None`` if it is not visible."""
        if self._frames is None:
            return frame_number - 1 if 1 <= frame_number <= self._total else None
        try:
            return self._frames.index(frame_number)
        except ValueError:
            return None

    @property
    def cost(self) -> int:
        return 0 if self._frames is None else len(self._frames)


def sort_frames(
    frames: Sequence[int],
    column_values: Sequence[str],
    descending: bool,
    numeric: bool | None = None,
) -> FrameIndex:
    """Sort ``frames`` by ``column_values[frame - 1]``, tie-breaking on frame number.

    When ``numeric`` is ``None`` the column is treated as numeric if every
    non-empty value parses as a float. Empty values sort last in ascending order.
    """
    values = [column_values[f - 1] if 0 < f <= len(column_values) else "" for f in frames]
    if numeric is None:
        numeric = all(_is_number(v) for v in values if v)
    key: Callable[[int], tuple[object, ...]]
    if numeric:
        nums = [float(v) if v else float("inf") for v in values]
        key = lambda i: (nums[i], frames[i])  # noqa: E731
    else:
        lowered = [v.casefold() for v in values]
        key = lambda i: (lowered[i] == "", lowered[i], frames[i])  # noqa: E731
    order = sorted(range(len(frames)), key=key, reverse=descending)
    return FrameIndex.of(frames[i] for i in order)


def _is_number(v: str) -> bool:
    try:
        float(v)
    except ValueError:
        return False
    return True


class LruCache(Generic[K, V]):
    """Thread-safe LRU cache bounded by a total ``cost`` budget."""

    def __init__(self, budget: int, cost: Callable[[V], int] = lambda _v: 1) -> None:
        self.budget = budget
        self._cost = cost
        self._items: OrderedDict[K, tuple[V, int]] = OrderedDict()
        self._total = 0
        self._lock = threading.Lock()

    def get(self, key: K) -> V | None:
        with self._lock:
            item = self._items.get(key)
            if item is None:
                return None
            self._items.move_to_end(key)
            return item[0]

    def put(self, key: K, value: V) -> None:
        c = self._cost(value)
        with self._lock:
            old = self._items.pop(key, None)
            if old is not None:
                self._total -= old[1]
            if c > self.budget:
                return  # too large to cache at all
            self._items[key] = (value, c)
            self._total += c
            while self._total > self.budget and self._items:
                _, (_, oc) = self._items.popitem(last=False)
                self._total -= oc

    def clear(self) -> None:
        with self._lock:
            self._items.clear()
            self._total = 0

    def __len__(self) -> int:
        with self._lock:
            return len(self._items)

    @property
    def total_cost(self) -> int:
        with self._lock:
            return self._total
