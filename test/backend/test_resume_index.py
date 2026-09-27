"""Closing a streaming open mid-index keeps an incomplete saved index, and the
next open resumes from it (rows at once, then a catch-up re-read of the capture)."""

import json
import threading
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

from pcap_backend import pcap_service
from pcap_backend import tshark as ts
from pcap_backend.index_cache import IndexCache
from pcap_backend.pcap_service import PcapService
from pcap_backend.protocol import IndexingError, RequestContext

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures"
CAPTURE = FIXTURES / "http.pcap"  # 11 packets

pytestmark = pytest.mark.tshark


@pytest.fixture
def held(slow_index: threading.Event, monkeypatch: pytest.MonkeyPatch) -> threading.Event:
    """slow_index (first rows after 3 packets, the pass held after 8 until
    released or cancelled), with every row published at once so tests can
    count them."""
    monkeypatch.setattr(pcap_service, "PROGRESS_INTERVAL_S", 0.0)
    return slow_index


def _wait(cond: Callable[[], Any], timeout: float = 20.0) -> Any:
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        value = cond()
        if value:
            return value
        time.sleep(0.02)
    raise AssertionError("timed out")


def _entry(cache_dir: Path) -> dict[str, Any] | None:
    metas = list(cache_dir.glob("*/meta.json"))
    return json.loads(metas[0].read_text()) if metas else None


def _rows(svc: PcapService, ctx: RequestContext) -> list[Any]:
    page = svc.list_packets({"offset": 0, "limit": 100}, ctx)
    return [(r["number"], r["cells"]) for r in page["rows"]]


def _published(svc: PcapService) -> int:
    f = svc._file
    return len(f.base.rows) if f is not None else 0


@pytest.fixture(scope="module")
def fresh_rows() -> list[Any]:
    """The rows of a normal full index of the capture (no cache; module-scoped,
    so it runs before slow_index slows index passes down)."""
    svc, ctx = PcapService(), RequestContext()
    try:
        svc.open({"path": str(CAPTURE), "columns": ["tcp.stream"]}, ctx)
        return _rows(svc, ctx)
    finally:
        svc.shutdown()


def _open(svc: PcapService, ctx: RequestContext, cache_dir: Path, **extra: Any) -> dict[str, Any]:
    params = {
        "path": str(CAPTURE),
        "stream": True,
        "columns": ["tcp.stream"],
        "cache": {"dir": str(cache_dir)},
        **extra,
    }
    return svc.open(params, ctx)


def _close_mid_index(
    svc: PcapService, ctx: RequestContext, cache_dir: Path, at_least: int = 5, **extra: Any
) -> int:
    """Open, wait for ``at_least`` rows, close: returns the rows published."""
    res = _open(svc, ctx, cache_dir, **extra)
    assert res["indexing"] is True
    _wait(lambda: _published(svc) >= at_least)
    svc.close()
    entry = _entry(cache_dir)
    assert entry is not None, "an incomplete entry was saved"
    return int(entry["frames"])


def test_tshark_killed_at_shutdown_never_makes_a_complete_index(
    service: PcapService, ctx: RequestContext, tmp_path: Path, held: threading.Event
) -> None:
    """The bug: at shutdown the server kills every child (PROCESSES.kill_all)
    before the index pass's own token is cancelled; tshark's output then just
    ends, and the rows so far were saved as a finished index."""
    cache_dir = tmp_path / "cache"
    events: list[dict[str, Any]] = []
    service.notify = lambda _m, p: events.append(p)
    _open(service, ctx, cache_dir)
    _wait(lambda: _published(service) >= 5)
    ts.PROCESSES.kill_all()
    held.set()  # (what tshark wrote before it died, then its end)
    _wait(lambda: any(e.get("event") in ("done", "failed") for e in events))
    service.close()
    entry = _entry(cache_dir)
    # (What tshark wrote before it died is read: maybe all of this small file.)
    assert entry is not None and entry["complete"] is False
    assert 5 <= entry["frames"] <= 11
    assert not any(e.get("event") == "done" for e in events)


@pytest.mark.usefixtures("held")
def test_closing_mid_index_keeps_an_incomplete_entry(
    service: PcapService, ctx: RequestContext, tmp_path: Path
) -> None:
    cache_dir = tmp_path / "cache"
    known = _close_mid_index(service, ctx, cache_dir)
    entry = _entry(cache_dir)
    assert entry is not None and entry["complete"] is False
    assert 5 <= known < 11 and entry["rows"] == known
    (folder,) = [p.parent for p in cache_dir.glob("*/meta.json")]
    assert (folder / "rows.tsv").read_bytes().count(b"\n") == known
    assert len(ts.PROCESSES) == 0
    # An incomplete entry is never opened as a finished index.
    hit = IndexCache(cache_dir, 1 << 30).load(folder.name)
    assert hit is not None and not hit.complete


def test_reopen_resumes_catches_up_and_matches_a_full_index(
    service: PcapService,
    ctx: RequestContext,
    tmp_path: Path,
    held: threading.Event,
    fresh_rows: list[Any],
) -> None:
    cache_dir = tmp_path / "cache"
    known = _close_mid_index(service, ctx, cache_dir)

    events: list[dict[str, Any]] = []
    service.notify = lambda method, p: events.append({"method": method, **p})
    started = time.monotonic()
    res = _open(service, ctx, cache_dir)
    assert time.monotonic() - started < 2, "the saved rows are shown at once"
    assert res["indexing"] is True and res["resumedAt"] == known and res["frames"] == known
    assert "fromCache" not in res
    assert _rows(service, ctx) == fresh_rows[:known], "the saved rows, at once"
    # Everything that needs every row still waits for the pass.
    with pytest.raises(IndexingError):
        service.list_packets({"sort": {"field": "frame.len"}}, ctx)

    catching_up = _wait(lambda: [e for e in events if e.get("phase") == "catching-up"])
    assert all(e["frames"] == known and e["resumedAt"] == known for e in catching_up)
    assert _published(service) == known, "rows 1…N aren't stored again"
    held.set()
    done = _wait(lambda: next((e for e in events if e.get("event") == "done"), None))
    assert done["info"]["frames"] == 11
    phases = [e["phase"] for e in events if e.get("event") == "progress"]
    assert "catching-up" in phases and "indexing" in phases
    assert phases.index("indexing") > phases.index("catching-up")
    assert _rows(service, ctx) == fresh_rows, "identical to a fresh full index"
    service.close()
    entry = _entry(cache_dir)
    assert entry is not None and entry["complete"] is True and entry["frames"] == 11
    # And now it opens from the saved index, without any pass.
    assert _open(service, ctx, cache_dir)["fromCache"] is True
    assert _rows(service, ctx) == fresh_rows


def test_closing_again_grows_the_incomplete_entry(
    service: PcapService, ctx: RequestContext, tmp_path: Path, held: threading.Event
) -> None:
    cache_dir = tmp_path / "cache"
    known = _close_mid_index(service, ctx, cache_dir, at_least=4)
    assert known < 9
    # Closed again while catching up: the entry stays as it was.
    _open(service, ctx, cache_dir)
    service.close()
    entry = _entry(cache_dir)
    assert entry is not None and (entry["complete"], entry["frames"]) == (False, known)
    # Closed again after going past it: the entry grows.
    res = _open(service, ctx, cache_dir)
    assert res["resumedAt"] == known
    held.set()  # (lets the catch-up through, then the pass runs to its end)
    _wait(lambda: _published(service) > known)
    service.close()
    entry = _entry(cache_dir)
    assert entry is not None and entry["frames"] > known


def test_rows_that_no_longer_match_fall_back_to_a_full_index(
    service: PcapService,
    ctx: RequestContext,
    tmp_path: Path,
    held: threading.Event,
    fresh_rows: list[Any],
    capfd: pytest.CaptureFixture[str],
) -> None:
    cache_dir = tmp_path / "cache"
    known = _close_mid_index(service, ctx, cache_dir)
    # As if a preference that isn't in the key had changed the Info column.
    rows_file = next(cache_dir.glob("*/rows.tsv"))
    lines = rows_file.read_bytes().split(b"\n")
    lines[known - 1] = lines[known - 1][:-2] + b"XX"  # same length: offsets still fit
    rows_file.write_bytes(b"\n".join(lines))

    events: list[dict[str, Any]] = []
    service.notify = lambda _m, p: events.append(p)
    res = _open(service, ctx, cache_dir)
    assert res["resumedAt"] == known
    held.set()
    _wait(lambda: any(e.get("event") == "done" for e in events))
    assert any(e.get("restarted") for e in events), "the viewer is told to start over"
    assert _rows(service, ctx) == fresh_rows
    assert "can't resume indexing" in capfd.readouterr().err
    service.close()
    entry = _entry(cache_dir)
    assert entry is not None and entry["complete"] is True and entry["frames"] == 11


def test_an_incomplete_entry_gives_no_colors_or_filter_results(
    service: PcapService, ctx: RequestContext, tmp_path: Path, held: threading.Event
) -> None:
    cache_dir = tmp_path / "cache"
    rules = [
        {"filter": "http", "background": "#e4ffc7"},
        {"filter": "tcp", "background": "#e7e6ff"},
    ]
    known = _close_mid_index(service, ctx, cache_dir, coloring={"rules": rules})
    folder = next(cache_dir.glob("*/meta.json")).parent
    assert not list(folder.glob("colors-*")), "colors of an unfinished pass aren't saved"

    res = _open(service, ctx, cache_dir, coloring={"rules": rules})
    assert res["resumedAt"] == known
    assert "colored" not in res.get("coloring", {}), "no saved colors: the pass colors"
    service.close()
    # A finished index keeps its colors.
    held.set()
    res = _open(service, ctx, cache_dir, coloring={"rules": rules})
    events: list[dict[str, Any]] = []
    service.notify = lambda _m, p: events.append(p)
    if res["indexing"]:
        _wait(lambda: any(e.get("event") == "done" for e in events))
    service.close()
    assert list(folder.glob("colors-*.bin")), "saved with the finished index"
    res = _open(service, ctx, cache_dir, coloring={"rules": rules})
    assert res["fromCache"] is True and res["coloring"]["colored"] == 11
