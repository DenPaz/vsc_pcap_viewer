"""Find Packet, conversation stepping, marks, time formats and marked export."""

import subprocess
from datetime import datetime
from pathlib import Path
from typing import Any

import pytest

from pcap_backend import navigation, pcap_service
from pcap_backend.pcap_service import PcapService
from pcap_backend.protocol import FilterError, InvalidParamsError, RequestContext
from pcap_backend.tshark import find_tool

# ---------------------------------------------------------------------- pure helpers


@pytest.mark.parametrize(
    ("text", "octets"),
    [
        ("474554", ["47", "45", "54"]),
        ("47 45 54", ["47", "45", "54"]),
        ("47:45:54", ["47", "45", "54"]),
        ("47-45-54", ["47", "45", "54"]),
        ("0x47 0x45", ["47", "45"]),
        ("AB", ["ab"]),
        ("a b", ["0a", "0b"]),
    ],
)
def test_parse_hex_bytes(text: str, octets: list[str]) -> None:
    assert navigation.parse_hex_bytes(text) == octets


@pytest.mark.parametrize("text", ["", "abc", "zz", "4 7 4x", "0x"])
def test_parse_hex_bytes_rejects(text: str) -> None:
    with pytest.raises(ValueError, match="pairs of hex digits"):
        navigation.parse_hex_bytes(text)


def test_find_expression() -> None:
    fe = navigation.find_expression
    assert fe("filter", "  dns  ", False) == "dns"
    assert fe("string", 'say "hi"', True) == 'frame contains "say \\"hi\\""'
    assert fe("string", "a.b", False) == 'frame matches "(?i)a\\\\.b"'
    assert fe("hex", "47 45 54", False) == "frame contains 47:45:54"
    assert fe("hex", "ff", False) == 'frame contains "\\xff"'
    for mode, value in (("filter", " "), ("string", ""), ("string", "a\nb"), ("bogus", "x")):
        with pytest.raises(ValueError):
            fe(mode, value, False)


def test_frame_ranges_and_chunked_filters() -> None:
    assert navigation.frame_ranges([7, 1, 2, 3, 3, 9, 10]) == ["1..3", "7", "9..10"]
    frames = list(range(1, 200_000, 2))  # 100k frames, no runs: the worst case
    filters = navigation.frame_set_filters(frames, 16_000)
    assert len(filters) > 1
    assert all(len(f) <= 16_000 and f.startswith("frame.number in {") for f in filters)
    members = [int(m) for f in filters for m in f[len("frame.number in {") : -1].split(",")]
    assert members == frames  # everything, once, in frame order
    assert navigation.frame_set_filters([5], 10) == ["frame.number in {5}"]  # never empty


def test_time_helpers() -> None:
    assert navigation.parse_ns("1700000000.123456789") == 1_700_000_000_123_456_789
    assert navigation.parse_ns("0.5") == 500_000_000
    assert navigation.parse_ns("-0.25") == -250_000_000
    assert navigation.parse_ns("") is None
    assert navigation.parse_ns("x") is None
    assert navigation.format_seconds(1_234_567_890) == "1.234567"
    assert navigation.format_seconds(-3_000_000) == "-0.003000"
    assert (
        navigation.format_absolute(1_700_000_000_000_001_000, utc=True)
        == "2023-11-14 22:13:20.000001"
    )


# ---------------------------------------------------------------------- integration


@pytest.fixture
def mixed(service: PcapService, fixtures: Path, ctx: RequestContext) -> PcapService:
    service.open({"path": str(fixtures / "mixed.pcapng")}, ctx)
    return service


def _find(svc: PcapService, ctx: RequestContext, **params: Any) -> Any:
    return svc.find_packet(params, ctx)["frame"]


@pytest.mark.tshark
def test_find_by_filter_wraps(mixed: PcapService, ctx: RequestContext) -> None:
    assert _find(mixed, ctx, mode="filter", value="dns") == 4
    assert _find(mixed, ctx, mode="filter", value="dns", **{"from": 4}) == 5
    res = mixed.find_packet(
        {"mode": "filter", "value": "dns", "from": 4, "direction": "previous"}, ctx
    )
    assert (res["frame"], res["index"], res["wrapped"]) == (9, 8, True)
    assert mixed._filters.get("dns") is not None  # cached like any filter
    assert _find(mixed, ctx, mode="filter", value="dns", direction="previous") == 9


@pytest.mark.tshark
def test_find_string_case(mixed: PcapService, ctx: RequestContext) -> None:
    # (DNS names are length-prefixed labels on the wire; the text is in the HTTP request.)
    assert _find(mixed, ctx, mode="string", value="INDEX.HTML") == 13  # case-insensitive
    assert _find(mixed, ctx, mode="string", value="INDEX.HTML", caseSensitive=True) is None
    assert _find(mixed, ctx, mode="string", value="index.html", caseSensitive=True) == 13
    assert _find(mixed, ctx, mode="string", value="Host: EXAMPLE.com") == 13
    assert (
        _find(mixed, ctx, mode="string", value="index.html", **{"from": 13}) == 13
    )  # only match: wraps to itself


@pytest.mark.tshark
def test_find_hex(mixed: PcapService, ctx: RequestContext) -> None:
    for value in ("47 45 54", "474554", "47:45:54"):  # "GET"
        assert _find(mixed, ctx, mode="hex", value=value) == 13
    assert _find(mixed, ctx, mode="hex", value="ff") == 1  # broadcast MAC of the ARP request


@pytest.mark.tshark
def test_find_within_filter_and_sort(mixed: PcapService, ctx: RequestContext) -> None:
    mixed.set_filter({"expr": "tcp"}, ctx)
    assert _find(mixed, ctx, mode="string", value="index.html") == 13
    assert _find(mixed, ctx, mode="filter", value="dns") is None  # not in the view
    mixed.set_filter({"expr": "udp"}, ctx)
    mixed.list_packets({"offset": 0, "limit": 1, "sort": {"field": "frame.len", "desc": True}}, ctx)
    # View order by length: 7 (102), 5 (98), 8, 9 (79), 6 (73), 4 (71), then 21..26 (55).
    assert _find(mixed, ctx, mode="filter", value="dns") == 7
    assert _find(mixed, ctx, mode="filter", value="dns", **{"from": 7}) == 5
    res = mixed.find_packet({"mode": "filter", "value": "dns", "from": 7}, ctx)
    assert res["index"] == 1


@pytest.mark.tshark
def test_find_invalid(mixed: PcapService, ctx: RequestContext) -> None:
    with pytest.raises(FilterError):
        mixed.find_packet({"mode": "filter", "value": "tcp.port =="}, ctx)
    for params in (
        {"mode": "hex", "value": "xyz"},
        {"mode": "string", "value": ""},
        {"mode": "nope", "value": "x"},
    ):
        with pytest.raises(InvalidParamsError):
            mixed.find_packet(params, ctx)


@pytest.mark.tshark
def test_marks_and_find_marked(mixed: PcapService, ctx: RequestContext) -> None:
    assert mixed.mark_packets({"frames": [3, 20]}, ctx) == {"count": 2, "marked": [3, 20]}
    rows = mixed.list_packets({"offset": 0, "limit": 30}, ctx)["rows"]
    assert [r["number"] for r in rows if r.get("marked")] == [3, 20]
    assert _find(mixed, ctx, mode="marked", **{"from": 5}) == 20
    res = mixed.find_packet({"mode": "marked", "from": 20}, ctx)
    assert (res["frame"], res["wrapped"]) == (3, True)
    assert mixed.mark_packets({"frames": [3, 4]}, ctx)["marked"] == [4]  # toggle
    assert mixed.mark_packets({"frames": [4], "mark": True}, ctx)["count"] == 2  # already on
    assert mixed.unmark_all({}, ctx) == {"count": 0}
    assert _find(mixed, ctx, mode="marked") is None
    with pytest.raises(InvalidParamsError):
        mixed.mark_packets({"frames": "3"}, ctx)


@pytest.mark.tshark
def test_neighbor_frame(mixed: PcapService, ctx: RequestContext) -> None:
    def nb(frame: int, direction: str = "next") -> Any:
        return mixed.neighbor_frame({"frame": frame, "direction": direction}, ctx)["frame"]

    assert nb(4) == 5  # udp.stream 0
    assert nb(5) is None  # no wrap-around
    assert nb(5, "previous") == 4
    assert nb(10) == 11  # tcp.stream 0
    assert nb(20, "previous") == 19
    assert nb(2) == 3  # ICMP: address pair
    assert nb(1) is None  # ARP to Broadcast: alone
    mixed.set_filter({"expr": "tcp.flags.fin == 1 || http"}, ctx)  # 13, 16, 18, 19
    assert nb(13) == 16
    with pytest.raises(InvalidParamsError):
        nb(12)  # not displayed


def _times(svc: PcapService, ctx: RequestContext, fmt: str, **extra: Any) -> dict[int, str]:
    page = svc.list_packets({"offset": 0, "limit": 30, "timeFormat": fmt, **extra}, ctx)
    return {r["number"]: r["cells"][1] for r in page["rows"]}


@pytest.mark.tshark
def test_time_formats(opened: PcapService, ctx: RequestContext) -> None:
    rel = _times(opened, ctx, "relative")
    assert rel[1] == "0.000000" and rel[11] == "0.010000"
    assert _times(opened, ctx, "epoch")[2] == "1700000000.001000"
    assert _times(opened, ctx, "utc")[1] == "2023-11-14 22:13:20.000000"
    local = datetime.fromtimestamp(1_700_000_000).strftime("%Y-%m-%d %H:%M:%S")
    assert _times(opened, ctx, "absolute")[1] == f"{local}.000000"
    captured = _times(opened, ctx, "delta_captured")
    assert captured[1] == "0.000000" and captured[5] == "0.001000"
    # Without timeFormat the raw value stays (backwards compatible).
    raw = opened.list_packets({"offset": 0, "limit": 1}, ctx)["rows"][0]["cells"][1]
    assert raw == "0.000000000"
    for bad in ({"timeFormat": "fortnights"}, {"timeFormat": "relative", "timeRef": 99}):
        with pytest.raises(InvalidParamsError):
            opened.list_packets({"offset": 0, "limit": 1, **bad}, ctx)


@pytest.mark.tshark
def test_delta_displayed_follows_filter_and_sort(mixed: PcapService, ctx: RequestContext) -> None:
    mixed.set_filter({"expr": "http"}, ctx)  # 13, 16
    assert _times(mixed, ctx, "delta_displayed") == {13: "0.000000", 16: "0.006000"}
    mixed.set_filter({"expr": "dns"}, ctx)
    sort = {"field": "frame.len", "desc": True}  # 7, 5, 8, 9, 6, 4
    page = mixed.list_packets(
        {"offset": 0, "limit": 10, "sort": sort, "timeFormat": "delta_displayed"}, ctx
    )
    assert [(r["number"], r["cells"][1]) for r in page["rows"]] == [
        (7, "0.000000"),
        (5, "-0.004000"),
        (8, "0.006000"),
        (9, "0.002000"),
        (6, "-0.006000"),
        (4, "-0.004000"),
    ]
    # A page that starts mid-view still measures from the row before it.
    page = mixed.list_packets(
        {"offset": 2, "limit": 2, "sort": sort, "timeFormat": "delta_displayed"}, ctx
    )
    assert [(r["number"], r["cells"][1]) for r in page["rows"]] == [
        (8, "0.006000"),
        (9, "0.002000"),
    ]


@pytest.mark.tshark
def test_time_reference(opened: PcapService, ctx: RequestContext) -> None:
    rel = _times(opened, ctx, "relative", timeRef=4)
    assert rel[4] == "*REF*"
    assert rel[5] == "0.001000"
    assert rel[1] == "-0.003000"
    assert _times(opened, ctx, "utc", timeRef=4)[4] == "*REF*"


@pytest.mark.tshark
def test_field_types(opened: PcapService, ctx: RequestContext) -> None:
    types = opened.field_types(
        {"names": ["tcp.analysis.acks_frame", "dns.response_in", "ip.src", "no.such"]}, ctx
    )["types"]
    assert types["tcp.analysis.acks_frame"]["type"] == "FT_FRAMENUM"
    assert types["dns.response_in"]["type"] == "FT_FRAMENUM"
    assert types["ip.src"] == {"type": "FT_IPv4", "desc": "Source Address"}
    assert "no.such" not in types


def _exported_frames(path: Path) -> list[str]:
    out = subprocess.run(
        [str(find_tool("tshark")), "-r", str(path), "-T", "fields", "-e", "frame.time_relative"],
        capture_output=True,
        check=True,
    ).stdout.decode()
    return out.split()


@pytest.mark.tshark
def test_export_marked(opened: PcapService, ctx: RequestContext, tmp_path: Path) -> None:
    with pytest.raises(InvalidParamsError, match="No packets are marked"):
        opened.export(
            {"kind": "pcapng", "dest": str(tmp_path / "none.pcapng"), "marked": True}, ctx
        )
    opened.mark_packets({"frames": [1, 3, 5, 7, 9, 11]}, ctx)
    res = opened.export(
        {"kind": "pcapng", "dest": str(tmp_path / "marked.pcapng"), "marked": True}, ctx
    )
    assert res["packets"] == 6 and res["filter"] == "marked packets"
    assert len(_exported_frames(tmp_path / "marked.pcapng")) == 6


@pytest.mark.tshark
def test_export_large_mark_set_in_chunks(
    opened: PcapService, ctx: RequestContext, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A mark set whose filter exceeds the argv budget is exported in chunks and
    joined with mergecap, keeping frame order."""
    monkeypatch.setattr(pcap_service, "MAX_FILTER_ARG", 24)  # forces one chunk per mark
    opened.mark_packets({"frames": [1, 3, 5, 7, 9, 11]}, ctx)
    res = opened.export(
        {"kind": "pcap", "dest": str(tmp_path / "chunked.pcap"), "marked": True}, ctx
    )
    assert res["packets"] == 6
    times = _exported_frames(tmp_path / "chunked.pcap")
    assert times == sorted(times, key=float) and len(times) == 6
    assert sorted(p.name for p in tmp_path.iterdir()) == ["chunked.pcap"]
