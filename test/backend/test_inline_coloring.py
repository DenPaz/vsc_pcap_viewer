"""Coloring rules evaluated by the index pass (open {coloring}): rows come with
their colors, also while a streaming open is indexing, and colors are saved
with the index."""

import threading
import time
from pathlib import Path
from typing import Any

import pytest

from pcap_backend.pcap_service import PcapService
from pcap_backend.protocol import InvalidParamsError, RequestContext

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures"
MIXED = str(FIXTURES / "mixed.pcapng")
RULES = [
    {"filter": "dns", "foreground": "#000000", "background": "#c8e2ff"},
    {"filter": "tcp", "foreground": "#000000", "background": "#e7e6ff"},
    {"filter": "udp", "foreground": "#000000", "background": "#daeeff"},
]


def _page(svc: PcapService, ctx: RequestContext) -> dict[str, Any]:
    return svc.list_packets({"offset": 0, "limit": 100}, ctx)


def _colors(page: dict[str, Any]) -> list[int | None]:
    return [r.get("color") for r in page["rows"]]


@pytest.mark.tshark
def test_open_colors_rows_like_a_coloring_pass(service: PcapService, ctx: RequestContext) -> None:
    plain = PcapService()
    try:
        plain.open({"path": MIXED}, ctx)
        expected = plain.set_coloring({"rules": RULES}, ctx)
        expected_colors = _colors(_page(plain, ctx))
        expected_rows = [r["cells"] for r in _page(plain, ctx)["rows"]]
    finally:
        plain.shutdown()
    res = service.open({"path": MIXED, "coloring": {"rules": RULES}}, ctx)
    assert res["coloring"]["colored"] == expected["colored"] == 23  # 3 ARP packets match none
    assert res["coloring"]["errors"] == {}
    page = _page(service, ctx)
    assert page["coloringId"] == res["coloring"]["coloringId"] > 0
    assert _colors(page) == expected_colors
    assert set(expected_colors) == {None, 0, 1, 2}, "dns, then other tcp/udp; ARP: none"
    assert [r["cells"] for r in page["rows"]] == expected_rows, "the rule isn't a column"
    # Later rule changes still use set_coloring.
    again = service.set_coloring({"rules": RULES[1:]}, ctx)
    assert again["coloringId"] > res["coloring"]["coloringId"]


@pytest.mark.tshark
def test_rules_that_dont_compile_are_reported_not_warned(
    service: PcapService, ctx: RequestContext
) -> None:
    rules = [{"filter": "tcp.port =="}, {"filter": "no @ allowed"}, *RULES]
    res = service.open({"path": MIXED, "coloring": {"rules": rules}}, ctx)
    assert set(res["coloring"]["errors"]) == {"0", "1"}
    assert not [w for w in res["warnings"] if "colorfilters" in w or "color filter" in w]
    assert set(_colors(_page(service, ctx))) == {None, 2, 3, 4}, "the other rules apply"


@pytest.mark.tshark
def test_without_coloring_nothing_is_colored(service: PcapService, ctx: RequestContext) -> None:
    res = service.open({"path": MIXED, "coloring": {"rules": []}}, ctx)
    assert "coloring" not in res
    assert set(_colors(_page(service, ctx))) == {None}
    with pytest.raises(InvalidParamsError):
        service.open({"path": MIXED, "coloring": ["dns"]}, ctx)


@pytest.mark.tshark
def test_rows_are_colored_while_indexing(
    service: PcapService, ctx: RequestContext, slow_index: threading.Event
) -> None:
    events: list[dict[str, Any]] = []
    service.notify = lambda method, params: events.append({"method": method, **params})
    res = service.open({"path": MIXED, "stream": True, "coloring": {"rules": RULES}}, ctx)
    assert res["indexing"] is True and set(res["coloring"]) == {"coloringId"}
    time.sleep(0.5)
    page = _page(service, ctx)
    assert page["coloringId"] == res["coloring"]["coloringId"]
    assert 3 <= len(page["rows"]) < 26
    early = _colors(page)
    assert any(c is not None for c in early), "rows come with their colors"
    slow_index.set()
    for _ in range(100):
        done = [e for e in events if e.get("event") == "done"]
        if done:
            break
        time.sleep(0.05)
    assert done[0]["coloring"] == {
        "coloringId": res["coloring"]["coloringId"],
        "colored": 23,
        "errors": {},
    }
    final = _colors(_page(service, ctx))
    assert final[: len(early)] == early, "a row's color doesn't change once shown"
    assert len([c for c in final if c is not None]) == 23


@pytest.mark.tshark
def test_colors_are_saved_with_the_index(
    service: PcapService, ctx: RequestContext, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    cache = {"dir": str(tmp_path / "cache")}
    first = service.open({"path": MIXED, "cache": cache, "coloring": {"rules": RULES}}, ctx)
    colors = _colors(_page(service, ctx))
    for _ in range(100):  # the index and its colors are saved in the background
        if list((tmp_path / "cache").glob("*/colors-*.bin")):
            break
        time.sleep(0.05)
    assert list((tmp_path / "cache").glob("*/colors-*.bin"))

    def no_pass(*_args: Any) -> Any:
        raise AssertionError("the saved colors should be used")

    monkeypatch.setattr(PcapService, "_coloring_pass", no_pass)
    again = service.open({"path": MIXED, "cache": cache, "coloring": {"rules": RULES}}, ctx)
    assert again["fromCache"] is True
    assert again["coloring"]["colored"] == first["coloring"]["colored"]
    assert _colors(_page(service, ctx)) == colors
    # Other rules: no saved colors, so no coloring (the host runs set_coloring).
    other = service.open({"path": MIXED, "cache": cache, "coloring": {"rules": RULES[:1]}}, ctx)
    assert other["fromCache"] is True and "coloring" not in other
