"""Saved indexes (reopening skips the index pass) and streaming open."""

import json
import os
import threading
import time
from array import array
from pathlib import Path
from typing import Any

import pytest

from pcap_backend import tshark as ts
from pcap_backend.index_cache import CACHE_FORMAT, IndexCache, index_key, rules_key
from pcap_backend.pcap_service import PcapService
from pcap_backend.protocol import IndexingError, RequestContext

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures"


def _key(capture: Path, **over: Any) -> str:
    args: dict[str, Any] = {
        "capture": capture,
        "tshark": Path("/usr/bin/tshark"),
        "tshark_version": "TShark 4.2.2",
        "lua_scripts": [],
        "decode_as": [],
        "prefs": {},
        "columns": [],
        "config": [],
    }
    return index_key(**{**args, **over})


# ---------------------------------------------------------------------- cache module


def test_index_key_changes_with_everything_that_changes_the_index(tmp_path: Path) -> None:
    capture = tmp_path / "c.pcap"
    capture.write_bytes(b"x" * 100)
    lua = tmp_path / "d.lua"
    lua.write_text("-- v1")
    base = _key(capture, lua_scripts=[str(lua)])
    assert base == _key(capture, lua_scripts=[str(lua)]), "stable"
    for over in (
        {"tshark_version": "TShark 4.6.4"},
        {"decode_as": ["udp.port==9999,dns"]},
        {"prefs": {"tcp.analyze_sequence_numbers": False}},
        {"columns": ["tcp.stream"]},
        {"config": [["/home/u/.config/wireshark/preferences", 10, 1]]},
        {"lua_scripts": []},
    ):
        assert _key(capture, **{"lua_scripts": [str(lua)], **over}) != base, over
    lua.write_text("-- v2")  # same path, new content
    assert _key(capture, lua_scripts=[str(lua)]) != base
    lua.write_text("-- v1")
    st = capture.stat()
    os.utime(capture, ns=(st.st_atime_ns, st.st_mtime_ns + 1_000_000))
    assert _key(capture, lua_scripts=[str(lua)]) != base, "modified capture"
    # A preference naming a file (the TLS key log) depends on the file's contents.
    keylog = tmp_path / "keys.log"
    keylog.write_text("CLIENT_RANDOM aa bb\n")
    with_keys = _key(capture, prefs={"tls.keylog_file": str(keylog)})
    assert with_keys == _key(capture, prefs={"tls.keylog_file": str(keylog)})
    keylog.write_text("CLIENT_RANDOM aa bb\nCLIENT_RANDOM cc dd\n")  # the browser added keys
    assert _key(capture, prefs={"tls.keylog_file": str(keylog)}) != with_keys


def test_save_load_prune_and_clear(tmp_path: Path) -> None:
    cache = IndexCache(tmp_path / "cache", max_bytes=10_000)
    rows = tmp_path / "rows.tsv"
    rows.write_bytes(b"1\ta\n2\tb\n")
    offsets = array("Q", [0, 4])
    assert cache.load("a" * 64) is None
    assert cache.save("a" * 64, rows, offsets, {"info": {"frames": 2}}, complete=True)
    hit = cache.load("a" * 64)
    assert hit is not None and hit.offsets.tolist() == [0, 4] and hit.meta["info"] == {"frames": 2}
    assert hit.rows.read_bytes() == rows.read_bytes()
    assert hit.meta["format"] == CACHE_FORMAT and hit.meta["rows"] == 2
    assert hit.complete and hit.meta["complete"] is True and hit.meta["frames"] == 2

    colors = array("B", [0, 1, 2])
    cache.save_colors("a" * 64, "r1", colors, {"colored": 2, "errors": {"3": "bad"}})
    assert cache.load_colors("a" * 64, "r1", frames=2) == (
        colors,
        {"colored": 2, "errors": {"3": "bad"}},
    )
    assert cache.load_colors("a" * 64, "r1", frames=5) is None, "frame count must match"
    assert cache.load_colors("a" * 64, "other", frames=2) is None
    for i in range(6):  # only the most recent colorings are kept
        cache.save_colors("a" * 64, f"x{i}", colors, {})
        time.sleep(0.01)
    assert len(list((tmp_path / "cache" / ("a" * 64)).glob("colors-*.bin"))) == 4

    # Least recently used entries go first once the total exceeds max_bytes.
    big = tmp_path / "big.tsv"
    big.write_bytes(b"z" * 6000)
    cache.save("b" * 64, big, array("Q", [0]), {}, complete=True)
    time.sleep(0.01)
    assert cache.load("a" * 64) is not None  # touch: now the most recent
    cache.save("c" * 64, big, array("Q", [0]), {}, complete=True)  # over the limit: b goes
    assert cache.load("b" * 64) is None
    assert cache.load("a" * 64) is not None and cache.load("c" * 64) is not None
    removed, freed = cache.clear()
    assert removed == 2 and freed > 6000 and cache.entries() == []


def test_an_incomplete_entry_is_never_a_finished_index(tmp_path: Path) -> None:
    cache = IndexCache(tmp_path, max_bytes=1 << 20)
    key = "p" * 64
    rows = tmp_path / "rows.tsv"
    rows.write_bytes(b"1\ta\n2\tb\n")
    assert cache.save(key, rows, array("Q", [0, 4]), {"fields": ["x"]}, complete=False)
    hit = cache.load(key)
    assert hit is not None and not hit.complete
    assert (hit.meta["complete"], hit.meta["frames"]) == (False, 2)
    # Colors and filter results belong to finished indexes only.
    cache.save_colors(key, "r", array("B", [0, 1, 1]), {"colored": 2})
    cache.save_filter(key, "udp", array("I", [1]))
    assert not list((tmp_path / key).glob("colors-*")) and not list(
        (tmp_path / key).glob("filter-*")
    )
    assert cache.load_colors(key, "r", 2) is None and cache.load_filter(key, "udp", 2) is None
    # Planted by hand (or left by an older version): still never used.
    (tmp_path / key / "filter-x.bin").write_bytes(array("I", [1]).tobytes())
    assert cache.load_filter(key, "x", 2) is None
    # Once complete, the entry is replaced as a whole.
    assert cache.save(key, rows, array("Q", [0, 4]), {}, complete=True)
    assert cache.load(key).complete  # type: ignore[union-attr]
    assert not (tmp_path / key / "filter-x.bin").exists()
    cache.discard(key)
    assert cache.load(key) is None
    # An entry of the old format (which could hold a closed pass) is ignored.
    assert cache.save(key, rows, array("Q", [0, 4]), {}, complete=True)
    meta = tmp_path / key / "meta.json"
    old = json.loads(meta.read_text())
    meta.write_text(json.dumps({**old, "format": 1}))
    assert cache.load(key) is None
    meta.write_text(json.dumps({k: v for k, v in old.items() if k != "complete"}))
    assert cache.load(key) is None


def test_broken_entries_are_ignored(tmp_path: Path) -> None:
    cache = IndexCache(tmp_path, max_bytes=1 << 20)
    rows = tmp_path / "rows.tsv"
    rows.write_bytes(b"1\n")
    cache.save("d" * 64, rows, array("Q", [0]), {}, complete=True)
    (tmp_path / ("d" * 64) / "offsets.bin").write_bytes(b"\0" * 16)  # 2 offsets, meta says 1
    assert cache.load("d" * 64) is None
    (tmp_path / ("e" * 64)).mkdir()
    (tmp_path / ("e" * 64) / "meta.json").write_text("{not json")
    assert cache.load("e" * 64) is None
    with pytest.raises(ValueError, match="bad cache key"):
        cache.load("../escape")


# ---------------------------------------------------------------------- service: saved index


def _all_rows(svc: PcapService, ctx: RequestContext) -> list[Any]:
    return [r["cells"] for r in svc.list_packets({"offset": 0, "limit": 100}, ctx)["rows"]]


@pytest.mark.tshark
def test_reopen_uses_the_saved_index(
    service: PcapService, ctx: RequestContext, tmp_path: Path
) -> None:
    capture = tmp_path / "http.pcap"
    capture.write_bytes((FIXTURES / "http.pcap").read_bytes())
    cache = {"dir": str(tmp_path / "cache")}
    first = service.open({"path": str(capture), "cache": cache, "columns": ["tcp.stream"]}, ctx)
    rows = _all_rows(service, ctx)
    for _ in range(50):  # the index is saved in the background
        if list((tmp_path / "cache").glob("*/meta.json")):
            break
        time.sleep(0.05)
    again = service.open({"path": str(capture), "cache": cache, "columns": ["tcp.stream"]}, ctx)
    assert again.pop("fromCache") is True and "fromCache" not in first
    assert {k: v for k, v in again.items() if k != "filterId"} == {
        k: v for k, v in first.items() if k != "filterId"
    }
    assert _all_rows(service, ctx) == rows
    assert service.set_filter({"expr": "http"}, ctx)["matchCount"] == 2
    assert service.packet_detail({"number": 4}, ctx)["tree"][0]["label"].startswith("Frame 4:")

    # Anything that changes the index means a new pass.
    for params in (
        {"columns": ["tcp.stream", "ip.ttl"]},
        {"columns": ["tcp.stream"], "prefs": {"tcp.analyze_sequence_numbers": False}},
    ):
        res = service.open({"path": str(capture), "cache": cache, **params}, ctx)
        assert "fromCache" not in res, params
    st = capture.stat()
    os.utime(capture, ns=(st.st_atime_ns, st.st_mtime_ns + 1_000_000))
    res = service.open({"path": str(capture), "cache": cache, "columns": ["tcp.stream"]}, ctx)
    assert "fromCache" not in res, "the capture changed"
    # Without a cache dir nothing is saved or loaded.
    assert "fromCache" not in service.open({"path": str(capture)}, ctx)


@pytest.mark.tshark
def test_coloring_is_saved_with_the_index(
    service: PcapService, ctx: RequestContext, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    cache = {"dir": str(tmp_path / "cache")}
    rules = [
        {"filter": "http", "background": "#e4ffc7"},
        {"filter": "tcp", "background": "#e7e6ff"},
    ]
    service.open({"path": str(FIXTURES / "http.pcap"), "cache": cache}, ctx)
    time.sleep(0.5)  # background save of the index
    colored = service.set_coloring({"rules": rules}, ctx)
    colors = [r.get("color") for r in service.list_packets({"limit": 20}, ctx)["rows"]]
    assert colored["colored"] == 11

    def no_pass(*_args: Any) -> Any:
        raise AssertionError("the saved coloring should be used")

    monkeypatch.setattr(PcapService, "_coloring_pass", no_pass)
    service.open({"path": str(FIXTURES / "http.pcap"), "cache": cache}, ctx)
    again = service.set_coloring({"rules": rules}, ctx)
    assert (again["colored"], again["errors"]) == (colored["colored"], colored["errors"])
    assert [r.get("color") for r in service.list_packets({"limit": 20}, ctx)["rows"]] == colors
    assert rules_key(rules) != rules_key(rules[:1])


# ---------------------------------------------------------------------- service: streaming open


@pytest.mark.tshark
def test_streaming_open(
    service: PcapService, ctx: RequestContext, slow_index: threading.Event
) -> None:
    events: list[dict[str, Any]] = []
    service.notify = lambda method, params: events.append({"method": method, **params})
    res = service.open({"path": str(FIXTURES / "http.pcap"), "stream": True}, ctx)
    assert res["indexing"] is True and 3 <= res["frames"] < 11
    page = service.list_packets({"offset": 0, "limit": 50}, ctx)
    assert 3 <= page["total"] < 11 and [r["number"] for r in page["rows"]] == list(
        range(1, page["total"] + 1)
    )
    assert service.packet_detail({"number": 2}, ctx)["number"] == 2, "detail doesn't wait"
    # A row published after the last page fetch can still be opened and marked.
    time.sleep(0.25)
    newest = len(service._file.base.rows) if service._file else 0
    assert service.packet_detail({"number": newest}, ctx)["number"] == newest
    assert service.mark_packets({"frames": [newest]}, ctx)["marked"] == [newest]
    for call in (
        lambda: service.set_filter({"expr": "tcp"}, ctx),
        lambda: service.list_packets({"sort": {"field": "frame.len"}}, ctx),
        lambda: service.find_packet({"mode": "filter", "value": "tcp"}, ctx),
        lambda: (
            service.list_packets({"columns": ["ip.ttl"]}, ctx)
            and service.follow_stream({"proto": "tcp", "frame": 1}, ctx)
        ),
    ):
        with pytest.raises(IndexingError, match="still being indexed"):
            call()
    assert service.set_filter({"expr": ""}, ctx)["matchCount"] >= 3, "clearing is fine"
    # Non-relative times need a frame.time_epoch pass: relative until indexed.
    assert (
        service.list_packets({"limit": 1, "timeFormat": "utc"}, ctx)["rows"][0]["cells"][1]
        == "0.000000"
    )
    slow_index.set()
    for _ in range(100):
        if any(e.get("event") == "done" for e in events):
            break
        time.sleep(0.05)
    done = next(e for e in events if e.get("event") == "done")
    assert (
        done["method"] == "index"
        and done["info"]["frames"] == 11
        and done["info"]["indexing"] is False
    )
    assert service.list_packets({"limit": 50}, ctx)["total"] == 11
    assert service.set_filter({"expr": "http"}, ctx)["matchCount"] == 2
    assert service.list_packets({"limit": 1, "timeFormat": "utc"}, ctx)["rows"][0]["cells"][
        1
    ].startswith("2023-")


@pytest.mark.tshark
def test_streaming_open_finishing_fast_is_a_normal_open(
    service: PcapService, ctx: RequestContext
) -> None:
    res = service.open({"path": str(FIXTURES / "http.pcap"), "stream": True}, ctx)
    assert res["frames"] == 11 and res["indexing"] is False  # done before the first batch


@pytest.mark.tshark
def test_closing_a_streaming_capture_stops_the_pass(
    service: PcapService, ctx: RequestContext, slow_index: threading.Event
) -> None:
    events: list[dict[str, Any]] = []
    service.notify = lambda _method, params: events.append(params)
    assert service.open({"path": str(FIXTURES / "http.pcap"), "stream": True}, ctx)["indexing"]
    service.close()
    assert len(ts.PROCESSES) == 0
    assert not any(e.get("event") == "done" for e in events)
    # Opening another file while one streams replaces it cleanly.
    assert service.open({"path": str(FIXTURES / "dns.pcap"), "stream": True}, ctx)["indexing"]
    slow_index.set()
    res = service.open({"path": str(FIXTURES / "http.pcap")}, ctx)
    assert res["frames"] == 11 and res["indexing"] is False
