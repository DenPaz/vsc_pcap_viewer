from pathlib import Path

import pytest

from pcap_backend.cache import FrameIndex, LruCache, RowStore, sort_frames


def _store(tmp_path: Path, rows: list[str]) -> RowStore:
    store = RowStore(tmp_path / "rows.tsv", ["a", "b", "c"])
    for i, row in enumerate(rows, start=1):
        store.append(i, row.encode())
    store.finish()
    return store


def test_row_store_random_access(tmp_path: Path) -> None:
    store = _store(tmp_path, ["1\tx\ty", "2\tü\t", "3\t\tz"])
    assert len(store) == 3
    assert store.get(2) == ["2", "ü", ""]
    assert store.get_many([3, 1]) == [["3", "", "z"], ["1", "x", "y"]]
    # Out-of-range frames yield blank rows rather than raising.
    assert store.get(99) == ["", "", ""]
    store.close()


def test_row_store_pads_missing_frames(tmp_path: Path) -> None:
    store = RowStore(tmp_path / "rows.tsv", ["n", "v"])
    store.append(1, b"1\ta")
    store.append(3, b"3\tc")
    store.finish()
    assert len(store) == 3
    assert store.get(2) == ["2", ""]
    assert store.get(3) == ["3", "c"]
    with pytest.raises(ValueError, match="out of order"):
        store.append(2, b"2\tb")
    store.close()


def test_row_store_short_rows_are_padded(tmp_path: Path) -> None:
    store = _store(tmp_path, ["1"])
    assert store.get(1) == ["1", "", ""]
    assert store.column(2) == [""]
    store.close()


def test_frame_index_identity_slices() -> None:
    idx = FrameIndex.all(10)
    assert idx.is_identity
    assert len(idx) == 10
    assert idx.slice(0, 3) == [1, 2, 3]
    assert idx.slice(8, 5) == [9, 10]
    assert idx.slice(10, 5) == []
    assert idx.slice(-5, 2) == [1, 2]
    assert idx.position_of(4) == 3
    assert idx.position_of(11) is None
    assert idx.cost == 0


def test_frame_index_filtered() -> None:
    idx = FrameIndex.of([2, 5, 9])
    assert len(idx) == 3
    assert idx.slice(1, 10) == [5, 9]
    assert idx.position_of(9) == 2
    assert idx.position_of(3) is None
    assert idx.cost == 3


def test_sort_frames_numeric_and_text() -> None:
    values = ["10", "9", "", "100"]  # values for frames 1..4
    asc = sort_frames([1, 2, 3, 4], values, descending=False)
    assert asc.slice(0, 4) == [2, 1, 4, 3]  # empty sorts last
    desc = sort_frames([1, 2, 3, 4], values, descending=True)
    assert desc.slice(0, 4) == [4, 1, 2, 3]  # empty still last
    ties = sort_frames([1, 2, 3], ["5", "5", "1"], descending=True)
    assert ties.slice(0, 3) == [1, 2, 3]  # ties keep ascending frame order
    text = sort_frames([1, 2, 3], ["b", "A", "a"], descending=False)
    assert text.slice(0, 3) == [2, 3, 1]  # case-insensitive, ties by frame number


def test_sort_frames_forced_text() -> None:
    ordered = sort_frames([1, 2], ["10", "9"], descending=False, numeric=False)
    assert ordered.slice(0, 2) == [1, 2]


def test_lru_cache_budget() -> None:
    cache: LruCache[str, list[int]] = LruCache(5, cost=len)
    cache.put("a", [1, 2])
    cache.put("b", [1, 2])
    assert cache.get("a") == [1, 2]  # "a" becomes most recently used
    cache.put("c", [1, 2])  # evicts "b"
    assert cache.get("b") is None
    assert cache.get("a") is not None
    assert cache.total_cost == 4
    cache.put("huge", list(range(10)))  # larger than budget: not cached
    assert cache.get("huge") is None
    cache.clear()
    assert len(cache) == 0
