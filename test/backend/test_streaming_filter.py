"""Streaming filters: set_filter {stream: true}, "filter" notifications, stop_filter,
filtering while a streaming open indexes, and filter results in the saved index."""

import threading
import time
from array import array
from pathlib import Path
from typing import Any

import pytest

from pcap_backend import pcap_service
from pcap_backend import tshark as ts
from pcap_backend.cancellation import CancelledError
from pcap_backend.index_cache import MAX_FILTERS, IndexCache
from pcap_backend.pcap_service import PcapService
from pcap_backend.protocol import IndexingError, RequestContext

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures"
MIXED = str(FIXTURES / "mixed.pcapng")  # 26 packets: udp 4-9 and 21-26, tcp 10-20
UDP = [4, 5, 6, 7, 8, 9, 21, 22, 23, 24, 25, 26]


def _recorder(service: PcapService) -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []
    service.notify = lambda method, params: events.append({"method": method, **params})
    return events


def _wait_event(
    events: list[dict[str, Any]], method: str, event: str, *, has_view: bool = False, **match: Any
) -> Any:
    """The first ``method`` notification with this ``event`` (and ``match``ing
    fields; with ``has_view``, one carrying ``view``), waiting up to 10 s."""
    for _ in range(200):
        for e in list(events):
            if (
                e["method"] == method
                and e.get("event") == event
                and (not has_view or "view" in e)
                and all(e.get(k) == v for k, v in match.items())
            ):
                return e
        time.sleep(0.05)
    raise AssertionError(f"no {method} {event} event: {events}")


def _numbers(service: PcapService, ctx: RequestContext, **params: Any) -> list[int]:
    page = service.list_packets({"offset": 0, "limit": 100, **params}, ctx)
    return [r["number"] for r in page["rows"]]


def _wait_idle() -> None:
    for _ in range(100):
        if not ts.PROCESSES:
            return
        time.sleep(0.05)
    raise AssertionError("tshark is still running")


def test_saved_filter_results(tmp_path: Path) -> None:
    cache = IndexCache(tmp_path, max_bytes=1 << 20)
    key = "f" * 64
    cache.save_filter(key, "udp", array("I", [1]))  # no entry for this capture yet
    assert cache.load_filter(key, "udp", 3) is None
    rows = tmp_path / "rows.tsv"
    rows.write_bytes(b"1\n2\n3\n")
    cache.save(key, rows, array("Q", [0, 2, 4]), {})
    cache.save_filter(key, "udp", array("I", [1, 3]))
    assert cache.load_filter(key, "udp", 3) == array("I", [1, 3])
    assert cache.load_filter(key, "udp", 2) is None, "matches beyond the capture"
    assert cache.load_filter(key, "tcp", 3) is None
    cache.save_filter(key, "tcp", array("I"))
    assert cache.load_filter(key, "tcp", 3) == array("I"), "no matches is a result too"
    for i in range(MAX_FILTERS + 2):
        time.sleep(0.01)  # distinct mtimes: the most recent ones stay
        cache.save_filter(key, f"frame.number == {i}", array("I", [1]))
    assert len(list((tmp_path / key).glob("filter-*.bin"))) == MAX_FILTERS
    assert cache.load_filter(key, f"frame.number == {MAX_FILTERS + 1}", 3) is not None
    assert cache.load_filter(key, "udp", 3) is None, "the oldest went first"
    (tmp_path / key / next((tmp_path / key).glob("filter-*.bin")).name).write_bytes(b"\1\2\3")
    assert sum(cache.load_filter(key, f"frame.number == {i}", 3) is None for i in range(12)) >= 3


@pytest.mark.tshark
def test_streaming_filter(
    service: PcapService,
    ctx: RequestContext,
    slow_filter: threading.Event,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    events = _recorder(service)
    service.open({"path": MIXED}, ctx)
    res = service.set_filter({"expr": "udp", "stream": True}, ctx)
    assert res["filtering"] is True and 2 <= res["matchCount"] < len(UDP)
    # Matches so far, in capture order even when a sort is asked for.
    by_len = {"sort": {"field": "frame.len", "desc": True}}
    shown = _numbers(service, ctx, **by_len)
    assert shown == UDP[: len(shown)] and len(shown) >= 2
    assert service.find_frame({"number": 4}, ctx)["index"] == 0
    for call in (
        lambda: service.find_packet({"mode": "filter", "value": "dns"}, ctx),
        lambda: service.neighbor_frame({"frame": 4}, ctx),
    ):
        with pytest.raises(IndexingError, match="filter is still running"):
            call()
    time.sleep(0.5)
    progress = [e for e in events if e.get("event") == "progress"]
    assert progress and all(e["filterId"] == res["filterId"] for e in progress)
    assert progress[-1]["matchCount"] >= res["matchCount"]
    slow_filter.set()
    done = _wait_event(events, "filter", "done", filterId=res["filterId"])
    assert (done["matchCount"], done["total"]) == (len(UDP), 26)
    # Once done, the sort applies and the view is complete.
    lengths = [
        int(r["cells"][5]) for r in service.list_packets({"limit": 100, **by_len}, ctx)["rows"]
    ]
    assert len(lengths) == len(UDP) and lengths == sorted(lengths, reverse=True)
    assert service.find_packet({"mode": "filter", "value": "dns"}, ctx)["frame"] is not None

    # The result is cached: applying it again runs no filter pass.
    def no_pass(*_args: Any) -> Any:
        raise AssertionError("the cached result should be used")

    service.set_filter({"expr": ""}, ctx)
    monkeypatch.setattr(PcapService, "_run_filter", no_pass)
    again = service.set_filter({"expr": "udp", "stream": True}, ctx)
    assert again["matchCount"] == len(UDP) and "filtering" not in again


@pytest.mark.tshark
def test_stopping_a_streaming_filter_keeps_its_matches(
    service: PcapService, ctx: RequestContext, slow_filter: threading.Event
) -> None:
    events = _recorder(service)
    service.open({"path": MIXED}, ctx)
    res = service.set_filter({"expr": "udp", "stream": True}, ctx)
    assert service.stop_filter({"filterId": res["filterId"] + 1}, ctx) == {"stopped": False}
    assert service.stop_filter({"filterId": res["filterId"]}, ctx) == {"stopped": True}
    stopped = _wait_event(events, "filter", "stopped", filterId=res["filterId"])
    assert 2 <= stopped["matchCount"] < len(UDP)
    assert _numbers(service, ctx) == UDP[: stopped["matchCount"]]
    _wait_idle()
    # A partial result is neither cached nor kept: applying the filter again reruns it.
    slow_filter.set()
    again = service.set_filter({"expr": "udp"}, ctx)
    assert again["matchCount"] == len(UDP) and "partial" not in again
    assert service.stop_filter({"filterId": again["filterId"]}, ctx) == {"stopped": False}


@pytest.mark.tshark
def test_a_new_filter_replaces_a_streaming_one(
    service: PcapService, ctx: RequestContext, slow_filter: threading.Event
) -> None:
    events = _recorder(service)
    service.open({"path": MIXED}, ctx)
    first = service.set_filter({"expr": "udp", "stream": True}, ctx)
    second = service.set_filter({"expr": "tcp", "stream": True}, ctx)
    assert second["filterId"] != first["filterId"]
    slow_filter.set()
    done = _wait_event(events, "filter", "done", filterId=second["filterId"])
    assert done["matchCount"] == 11
    _wait_idle()
    assert not [
        e for e in events if e["filterId"] == first["filterId"] and e["event"] != "progress"
    ]
    assert _numbers(service, ctx) == list(range(10, 21))


@pytest.mark.tshark
@pytest.mark.usefixtures("slow_filter")
def test_cancelling_the_request_keeps_the_previous_view(
    service: PcapService, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(pcap_service, "FIRST_BATCH", 100)  # wait for the whole pass
    service.open({"path": MIXED}, RequestContext())
    ctx = RequestContext()
    threading.Timer(0.3, ctx.token.cancel).start()
    with pytest.raises(CancelledError):
        service.set_filter({"expr": "udp", "stream": True}, ctx)
    ok = RequestContext()
    assert service.list_packets({"limit": 1}, ok)["total"] == 26
    _wait_idle()


@pytest.mark.tshark
@pytest.mark.usefixtures("slow_filter")
def test_closing_stops_a_streaming_filter(service: PcapService, ctx: RequestContext) -> None:
    events = _recorder(service)
    service.open({"path": MIXED}, ctx)
    assert service.set_filter({"expr": "udp", "stream": True}, ctx)["filtering"]
    service.close()
    assert len(ts.PROCESSES) == 0
    assert not [e for e in events if e.get("event") in ("done", "stopped")]


@pytest.mark.tshark
def test_streaming_filter_while_indexing(
    service: PcapService, ctx: RequestContext, slow_index: threading.Event
) -> None:
    events = _recorder(service)
    assert service.open({"path": MIXED, "stream": True}, ctx)["indexing"]
    with pytest.raises(IndexingError, match="still being indexed"):
        service.set_filter({"expr": "udp"}, ctx)  # only a streaming filter can start now
    res = service.set_filter({"expr": "udp", "stream": True}, ctx)
    done = _wait_event(events, "filter", "done", filterId=res["filterId"])
    # Only matches among the packets indexed so far are shown.
    indexed = len(service._file.base.rows) if service._file else 0
    assert indexed < 26 and done["matchCount"] < len(UDP)
    shown = _numbers(service, ctx)
    assert shown == UDP[: len(shown)] and all(n <= len(service._file.base.rows) for n in shown)  # type: ignore[union-attr]
    with pytest.raises(IndexingError):
        service.list_packets({"sort": {"field": "frame.len"}}, ctx) and service.find_packet(
            {"mode": "filter", "value": "dns"}, ctx
        )
    # Index progress (every PROGRESS_INTERVAL_S) says how many matches are shown by now.
    progress = _wait_event(events, "index", "progress", has_view=True)
    assert progress["view"]["filterId"] == res["filterId"]
    slow_index.set()
    index_done = _wait_event(events, "index", "done")
    assert index_done["view"] == {"filterId": res["filterId"], "matchCount": len(UDP)}
    assert _numbers(service, ctx) == UDP
    assert service.set_filter({"expr": ""}, ctx)["matchCount"] == 26
    assert service.set_filter({"expr": "udp"}, ctx)["matchCount"] == len(UDP)


@pytest.mark.tshark
def test_filter_results_are_saved_with_the_index(
    service: PcapService, ctx: RequestContext, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    cache = {"dir": str(tmp_path / "cache")}
    service.open({"path": MIXED, "cache": cache}, ctx)
    for _ in range(100):  # the index is saved in the background
        if list((tmp_path / "cache").glob("*/meta.json")):
            break
        time.sleep(0.05)
    assert service.set_filter({"expr": "udp"}, ctx)["matchCount"] == len(UDP)
    assert service.set_filter({"expr": "dns", "stream": True}, ctx)["matchCount"] == 6
    for _ in range(100):
        if len(list((tmp_path / "cache").glob("*/filter-*.bin"))) == 2:
            break
        time.sleep(0.05)
    assert len(list((tmp_path / "cache").glob("*/filter-*.bin"))) == 2

    def no_pass(*_args: Any) -> Any:
        raise AssertionError("the saved result should be used")

    monkeypatch.setattr(PcapService, "_run_filter", no_pass)
    assert service.open({"path": MIXED, "cache": cache}, ctx)["fromCache"] is True
    assert service.set_filter({"expr": "udp", "stream": True}, ctx)["matchCount"] == len(UDP)
    assert service.set_filter({"expr": "dns"}, ctx)["matchCount"] == 6
    assert _numbers(service, ctx) == UDP[:6]
