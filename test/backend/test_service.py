"""Integration tests: PcapService against the fixture captures with a real tshark."""

import os
import threading
from pathlib import Path
from typing import Any

import pytest

from pcap_backend.cancellation import CancelledError
from pcap_backend.pcap_service import (
    PcapService,
    parse_capinfos,
    parse_decode_as_choices,
    parse_field_list,
    script_in_lua_message,
)
from pcap_backend.protocol import FilterError, InvalidParamsError, NotOpenError, RequestContext
from pcap_backend.tshark import PROCESSES, ConfigError

pytestmark = pytest.mark.tshark


def test_open_reports_metadata(service: PcapService, fixtures: Path, ctx: RequestContext) -> None:
    events: list[dict[str, Any]] = []
    ctx.progress = lambda p: events.append(dict(p))
    info = service.open({"path": str(fixtures / "http.pcap")}, ctx)
    assert info["frames"] == 11
    assert info["linkType"] == "ether"
    assert info["startTime"] == pytest.approx(1_700_000_000.0)
    assert info["warnings"] == []
    assert service.list_packets({"offset": 0, "limit": 1}, ctx)["filterId"] == info["filterId"]
    assert [c["title"] for c in info["columns"]] == [
        "No.", "Time", "Source", "Destination", "Protocol", "Length", "Info",
    ]  # fmt: skip
    assert events
    assert events[-1]["fraction"] == 1.0


def test_open_pcapng(service: PcapService, fixtures: Path, ctx: RequestContext) -> None:
    info = service.open({"path": str(fixtures / "mixed.pcapng")}, ctx)
    assert info["frames"] == 26
    page = service.list_packets({"offset": 0, "limit": 3}, ctx)
    assert [r["cells"][4] for r in page["rows"]] == ["ARP", "ICMP", "ICMP"]


def test_list_packets_paging(opened: PcapService, ctx: RequestContext) -> None:
    page = opened.list_packets({"offset": 2, "limit": 3}, ctx)
    assert page["total"] == 11
    assert [r["number"] for r in page["rows"]] == [3, 4, 5]
    row = page["rows"][1]["cells"]
    assert row[0] == "4"
    assert row[2:6] == ["192.168.1.10", "93.184.216.34", "HTTP", "144"]
    assert row[6].startswith("GET /index.html HTTP/1.1")
    assert opened.list_packets({"offset": 50, "limit": 10}, ctx)["rows"] == []


def test_filter_and_page(opened: PcapService, ctx: RequestContext) -> None:
    res = opened.set_filter({"expr": "http"}, ctx)
    assert res["matchCount"] == 2
    page = opened.list_packets({"offset": 0, "limit": 100}, ctx)
    assert [r["number"] for r in page["rows"]] == [4, 7]
    assert page["filterId"] == res["filterId"]
    # Clearing the filter restores the full list with a new filter id.
    cleared = opened.set_filter({"expr": ""}, ctx)
    assert cleared["matchCount"] == 11
    assert cleared["filterId"] != res["filterId"]
    # Re-applying a cached filter does not need tshark and yields the same frames.
    again = opened.set_filter({"expr": "http"}, ctx)
    assert again["matchCount"] == 2


def test_invalid_filter(opened: PcapService, ctx: RequestContext) -> None:
    before = opened.list_packets({"offset": 0, "limit": 1}, ctx)["filterId"]
    with pytest.raises(FilterError) as info:
        opened.set_filter({"expr": "tcp.port =="}, ctx)
    assert info.value.data == {"expr": "tcp.port =="}
    # An invalid filter never replaces the current view.
    assert opened.list_packets({"offset": 0, "limit": 1}, ctx)["filterId"] == before
    assert opened.validate_filter({"expr": "tcp.port =="}, ctx)["valid"] is False
    assert opened.validate_filter({"expr": "tcp.port == 80"}, ctx) == {"valid": True}


def test_filter_with_no_matches(opened: PcapService, ctx: RequestContext) -> None:
    res = opened.set_filter({"expr": "dns"}, ctx)
    assert res["matchCount"] == 0
    assert opened.list_packets({"offset": 0, "limit": 10}, ctx)["rows"] == []


def test_sorting(opened: PcapService, ctx: RequestContext) -> None:
    page = opened.list_packets(
        {"offset": 0, "limit": 3, "sort": {"field": "frame.len", "desc": True}}, ctx
    )
    assert [r["cells"][5] for r in page["rows"]] == ["345", "254", "144"]
    # Sorting composes with filtering.
    opened.set_filter({"expr": "tcp.len == 0"}, ctx)
    page = opened.list_packets(
        {"offset": 0, "limit": 100, "sort": {"field": "frame.number", "desc": True}}, ctx
    )
    assert [r["number"] for r in page["rows"]] == [11, 10, 9, 8, 5, 3, 2, 1]
    page = opened.list_packets({"offset": 0, "limit": 2}, ctx)
    assert [r["number"] for r in page["rows"]] == [1, 2]


def test_custom_columns(service: PcapService, fixtures: Path, ctx: RequestContext) -> None:
    info = service.open(
        {"path": str(fixtures / "http.pcap"), "columns": ["tcp.stream", "no.such.field"]}, ctx
    )
    assert [c["field"] for c in info["columns"]][-1] == "tcp.stream"
    assert any("no.such.field" in w for w in info["warnings"])
    # Default: the columns given to open().
    page = service.list_packets({"offset": 3, "limit": 1}, ctx)
    assert page["columns"][-1] == "tcp.stream"
    assert page["rows"][0]["cells"][-1] == "0"
    # Explicit list: exactly those custom columns, in order, extracted on demand.
    page = service.list_packets(
        {"offset": 3, "limit": 1, "columns": ["http.host", "tcp.stream", "frame.number"]}, ctx
    )
    assert page["columns"][-2:] == ["http.host", "tcp.stream"]
    assert len(page["rows"][0]["cells"]) == 9
    assert page["rows"][0]["cells"][-2:] == ["example.com", "0"]
    page = service.list_packets({"offset": 3, "limit": 1, "columns": []}, ctx)
    assert len(page["rows"][0]["cells"]) == 7
    # Unknown to tshark: blank cells and reported, not an error (and cached).
    page = service.list_packets({"offset": 0, "limit": 1, "columns": ["bogus.field.x"]}, ctx)
    assert page["rows"][0]["cells"][-1] == ""
    assert page["rejectedColumns"] == ["bogus.field.x"]
    page = service.list_packets(
        {"offset": 0, "limit": 1, "columns": ["no.such.field", "tcp.stream"]}, ctx
    )
    assert page["rejectedColumns"] == ["no.such.field"]  # rejected at open, remembered
    assert page["rows"][0]["cells"][-2:] == ["", "0"]
    with pytest.raises(InvalidParamsError, match="unknown field"):
        service.list_packets(
            {"offset": 0, "limit": 1, "sort": {"field": "bogus.field.x", "desc": False}}, ctx
        )
    with pytest.raises(InvalidParamsError):
        service.list_packets({"offset": 0, "limit": 1, "columns": ["-X"]}, ctx)


def test_find_frame(opened: PcapService, ctx: RequestContext) -> None:
    opened.set_filter({"expr": "http"}, ctx)
    assert opened.find_frame({"number": 7}, ctx)["index"] == 1
    assert opened.find_frame({"number": 1}, ctx)["index"] is None


def test_packet_detail_tree_and_bytes(opened: PcapService, ctx: RequestContext) -> None:
    detail = opened.packet_detail({"number": 4}, ctx)
    assert detail["number"] == 4
    protos = [n.get("name") for n in detail["tree"]]
    assert protos == ["frame", "eth", "ip", "tcp", "http"]
    (frame,) = detail["sources"]
    raw = bytes.fromhex(frame["hex"])
    assert len(raw) == 144
    ip = detail["tree"][2]
    src = next(c for c in ip["children"] if c.get("name") == "ip.src")
    # The field's byte range points at the address bytes in the frame.
    assert raw[src["pos"] : src["pos"] + src["size"]] == bytes([192, 168, 1, 10])
    assert opened.packet_detail({"number": 4}, ctx) is detail  # cached


def test_packet_detail_reassembled(opened: PcapService, ctx: RequestContext) -> None:
    detail = opened.packet_detail({"number": 7}, ctx)
    names = [s["name"] for s in detail["sources"]]
    assert names == ["Frame", "Reassembled TCP"]
    http = next(n for n in detail["tree"] if n.get("name") == "http")
    assert http["src"] == 1
    data = bytes.fromhex(detail["sources"][1]["hex"])
    assert data.startswith(b"HTTP/1.1 200 OK")
    assert data[http["pos"] : http["pos"] + 8] == b"HTTP/1.1"


def test_packet_detail_bounds(opened: PcapService, ctx: RequestContext) -> None:
    with pytest.raises(InvalidParamsError):
        opened.packet_detail({"number": 0}, ctx)
    with pytest.raises(InvalidParamsError):
        opened.packet_detail({"number": 12}, ctx)
    with pytest.raises(InvalidParamsError):
        opened.packet_detail({"number": "4"}, ctx)


def test_requires_open(service: PcapService, ctx: RequestContext) -> None:
    with pytest.raises(NotOpenError):
        service.list_packets({"offset": 0, "limit": 1}, ctx)


def test_open_missing_file(service: PcapService, tmp_path: Path, ctx: RequestContext) -> None:
    with pytest.raises(InvalidParamsError, match="not found"):
        service.open({"path": str(tmp_path / "nope.pcap")}, ctx)


def test_open_rejects_bad_decode_as(
    service: PcapService, fixtures: Path, ctx: RequestContext
) -> None:
    with pytest.raises(ConfigError):
        service.open({"path": str(fixtures / "http.pcap"), "decodeAs": ["-Y,x"]}, ctx)


def test_truncated_capture_is_usable(
    service: PcapService, fixtures: Path, ctx: RequestContext
) -> None:
    info = service.open({"path": str(fixtures / "truncated.pcap")}, ctx)
    assert info["frames"] == 10
    assert any("cut short" in w for w in info["warnings"])


def test_decode_as_changes_dissection(
    service: PcapService, fixtures: Path, ctx: RequestContext
) -> None:
    service.open(
        {"path": str(fixtures / "udp_custom.pcap"), "decodeAs": ["udp.port==9999,syslog"]}, ctx
    )
    page = service.list_packets({"offset": 0, "limit": 1}, ctx)
    assert page["rows"][0]["cells"][4] == "Syslog"


@pytest.mark.skipif(
    hasattr(os, "geteuid") and os.geteuid() == 0, reason="tshark disables Lua for root"
)
def test_lua_dissector(service: PcapService, fixtures: Path, ctx: RequestContext) -> None:
    lua = Path(__file__).resolve().parents[2] / "backend" / "dissectors" / "example.lua"
    service.open({"path": str(fixtures / "udp_custom.pcap"), "lua": [str(lua)]}, ctx)
    page = service.list_packets({"offset": 0, "limit": 1}, ctx)
    assert page["rows"][0]["cells"][4] == "EXAMPLE"
    assert service.set_filter({"expr": "example.type == 2"}, ctx)["matchCount"] == 2


def test_lua_as_root_warns(service: PcapService, fixtures: Path, ctx: RequestContext) -> None:
    if not (hasattr(os, "geteuid") and os.geteuid() == 0):
        pytest.skip("only meaningful as root")
    lua = Path(__file__).resolve().parents[2] / "backend" / "dissectors" / "example.lua"
    info = service.open({"path": str(fixtures / "udp_custom.pcap"), "lua": [str(lua)]}, ctx)
    assert any("root" in w for w in info["warnings"])


def test_cancel_filter(opened: PcapService) -> None:
    ctx = RequestContext()
    ctx.token.cancel()
    with pytest.raises(CancelledError):
        opened.set_filter({"expr": "tcp"}, ctx)
    assert len(PROCESSES) == 0


def test_superseded_filter(opened: PcapService, ctx: RequestContext) -> None:
    """A slow filter finishing after a newer one must not overwrite it."""
    gate = threading.Event()
    original = opened._run_filter

    def slow(f: Any, expr: str, c: RequestContext) -> Any:
        if expr == "tcp":
            gate.wait(5)
        return original(f, expr, c)

    opened._run_filter = slow  # type: ignore[method-assign]
    errors: list[BaseException] = []

    def first() -> None:
        try:
            opened.set_filter({"expr": "tcp"}, RequestContext())
        except BaseException as exc:
            errors.append(exc)

    t = threading.Thread(target=first)
    t.start()
    opened.set_filter({"expr": "http"}, ctx)
    gate.set()
    t.join()
    assert isinstance(errors[0], CancelledError)
    assert opened.list_packets({"offset": 0, "limit": 10}, ctx)["total"] == 2


def test_field_index(service: PcapService, ctx: RequestContext) -> None:
    assert service.field_index({"limit": 0}, ctx)["fields"] == []  # cache warm-up
    res = service.field_index({"prefix": "ip.sr", "limit": 10}, ctx)
    names = [f["name"] for f in res["fields"]]
    assert "ip.src" in names
    ip_src = next(f for f in res["fields"] if f["name"] == "ip.src")
    assert ip_src["type"] == "FT_IPv4"
    protos = service.field_index({"prefix": "http", "limit": 5}, ctx)["protocols"]
    assert any(p["name"] == "http" for p in protos)


def test_close_removes_temp_files(opened: PcapService, ctx: RequestContext) -> None:
    work_dir = opened._work_dir
    assert work_dir is not None
    assert work_dir.exists()
    opened.close()
    assert not work_dir.exists()
    with pytest.raises(NotOpenError):
        opened.list_packets({"offset": 0, "limit": 1}, ctx)


def test_parse_capinfos() -> None:
    text = (
        "File name\tFile type\tFile encapsulation\tStart time\tEnd time\n"
        "a\tb.pcap\tpcap\tether\t1.5\tn/a\n"
    )
    assert parse_capinfos(text) == {
        "start_time": 1.5,
        "end_time": None,
        "link_type": "ether",
        "file_type": "pcap",
    }
    assert parse_capinfos("") == {}


def test_parse_field_list() -> None:
    text = (
        "P\tInternet Protocol Version 4\tip\n"
        "F\tSource Address\tip.src\tFT_IPv4\tip\t\t0x0\tSource IP\n"
        "F\tbad\n"
    )
    parsed = parse_field_list(text)
    assert parsed["protocols"] == [{"name": "ip", "desc": "Internet Protocol Version 4"}]
    assert parsed["fields"] == [
        {
            "name": "ip.src",
            "desc": "Source Address",
            "type": "FT_IPv4",
            "proto": "ip",
            "blurb": "Source IP",
        }
    ]


def test_parse_decode_as_choices() -> None:
    stderr = (
        'tshark: Unknown protocol -- "x"\n'
        'tshark: Valid protocols for layer type "tcp.port" are:\n'
        "\t5co_rap (FiveCo RAP Register Access Protocol)\n"
        "\thttp (Hypertext Transfer Protocol)\r\n"
        "not a choice\n"
    )
    assert parse_decode_as_choices(stderr) == [
        {"name": "5co_rap", "desc": "FiveCo RAP Register Access Protocol"},
        {"name": "http", "desc": "Hypertext Transfer Protocol"},
    ]


def test_script_in_lua_message_handles_shortened_paths() -> None:
    scripts = ["/home/me/proj/dissectors/very/long/path/to/broken.lua", "/home/me/other.lua"]
    msg = "Lua: syntax error: ...proj/dissectors/very/long/path/to/broken.lua:2: ')' expected"
    assert script_in_lua_message(scripts, msg) == scripts[0]
    assert (
        script_in_lua_message(scripts, "Lua: Error during loading:\n/home/me/other.lua:1: boom")
        == scripts[1]
    )
    assert script_in_lua_message(scripts, "Lua: something without a path") is None
    # An ambiguous tail matches nothing rather than the wrong script.
    assert script_in_lua_message(["/a/x.lua", "/b/x.lua"], "Lua: ...x.lua:1: e") is None
    win = [r"C:\\Users\\me\\diss\\proto.lua"]
    assert script_in_lua_message(win, r"Lua: syntax error: ...me\\diss\\proto.lua:3: e") == win[0]
