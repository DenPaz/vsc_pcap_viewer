"""Live capture (capture.py and the capture_* methods), mostly with a fake dumpcap."""

import json
import struct
import sys
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

from pcap_backend import capture, comments
from pcap_backend.capture import CaptureOptions, parse_interfaces
from pcap_backend.pcap_service import PcapService
from pcap_backend.protocol import InvalidParamsError, RequestContext
from pcap_backend.tshark import PROCESSES, ToolError

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures"
FAKE = FIXTURES / "fake_dumpcap.py"
MIXED_PACKETS = 26


def test_parse_interfaces() -> None:
    text = (
        "1. eth0\t\t\t0\t192.0.2.2,fe80::1\tnetwork\t\n"
        "2. lo\t\tLoopback\t0\t127.0.0.1\tloopback\t\r\n"
        "3. \\Device\\NPF_{A1B2}\tIntel\tEthernet 2\t0\t10.0.0.5\tnetwork\t\n"
        "not an interface line\n"
    )
    got = parse_interfaces(text)
    assert [i.name for i in got] == ["eth0", "lo", "\\Device\\NPF_{A1B2}"]
    assert got[0].addresses == ("192.0.2.2", "fe80::1") and not got[0].loopback
    assert got[1].description == "Loopback" and got[1].loopback
    assert got[2].description == "Ethernet 2", "the friendly name, else the vendor"


def test_filter_problem() -> None:
    stderr = (
        "Capturing on 'Loopback: lo'\n"
        "dumpcap: Invalid capture filter \"udpx\" for interface 'lo'.\n\n"
        "That string isn't a valid capture filter (can't parse filter expression: "
        "syntax error).\n"
    )
    assert capture.filter_problem(stderr) == "can't parse filter expression: syntax error"
    assert capture.filter_problem("Capturing on 'lo'\n") is None


def test_dumpcap_args() -> None:
    options = CaptureOptions(
        interfaces=("eth0", "lo"),
        capture_filter="tcp port 443",
        packets=100,
        seconds=2.4,
        promiscuous=False,
        snaplen=128,
    )
    assert options.dumpcap_args() == [
        "-q",
        "-i", "eth0", "-f", "tcp port 443", "-p", "-s", "128",
        "-i", "lo", "-f", "tcp port 443", "-p", "-s", "128",
        "-c", "100", "-a", "duration:2", "-w", "-",
    ]  # fmt: skip
    assert CaptureOptions(interfaces=("lo",)).dumpcap_args() == ["-q", "-i", "lo", "-w", "-"]


def _pcapng(endian: str, packets: int) -> bytes:
    def block(kind: int, body: bytes) -> bytes:
        total = len(body) + 12
        return struct.pack(endian + "II", kind, total) + body + struct.pack(endian + "I", total)

    out = block(0x0A0D0D0A, struct.pack(endian + "IHHq", 0x1A2B3C4D, 1, 0, -1))
    out += block(1, struct.pack(endian + "HHI", 1, 0, 65535))
    for _ in range(packets):
        out += block(6, struct.pack(endian + "IIIII", 0, 0, 0, 4, 4) + b"abcd")
    return out


@pytest.mark.parametrize("endian", ["<", ">"])
def test_blocks_are_cut_whole(endian: str) -> None:
    data = _pcapng(endian, 3)
    blocks = capture._Blocks()
    out = b""
    for i in range(0, len(data), 7):  # chunks that split blocks anywhere
        out += blocks.feed(data[i : i + 7])
    assert out == data and blocks.packets == 3
    assert blocks.feed(data[:10]) == b"", "an incomplete block waits"
    with pytest.raises(ToolError, match="isn't pcapng"):
        capture._Blocks().feed(b"garbage!" * 4)


def test_permission_hints() -> None:
    denied = "You don't have permission to capture on that device (socket: Operation not permitted)"
    assert "CAP_NET_RAW" in (capture.permission_hint(denied, "linux") or "")
    assert "ChmodBPF" in (capture.permission_hint("(BIOCSETIF) failed", "darwin") or "")
    assert "Npcap" in (capture.permission_hint("wpcap.dll not found", "win32") or "")
    assert capture.permission_hint('There is no device named "x"', "linux") is None


# --------------------------------------------------------------------------- with the fake


@pytest.fixture
def fake(monkeypatch: pytest.MonkeyPatch) -> Callable[..., None]:
    """Use the fake dumpcap; ``fake(delay=…, drops=…, fail=…)`` sets its behaviour."""
    monkeypatch.setenv(capture.DUMPCAP_ENV, json.dumps([sys.executable, str(FAKE)]))

    def configure(**env: Any) -> None:
        for key, value in env.items():
            monkeypatch.setenv(f"FAKE_DUMPCAP_{key.upper()}", str(value))

    configure(delay=0.01)
    return configure


def _events(service: PcapService) -> list[tuple[str, dict[str, Any]]]:
    events: list[tuple[str, dict[str, Any]]] = []
    service.notify = lambda method, params: events.append((method, params))
    return events


def _wait(check: Callable[[], bool], timeout: float = 20) -> None:
    deadline = time.monotonic() + timeout
    while not check():
        assert time.monotonic() < deadline, "timed out"
        time.sleep(0.02)


def _index_done(events: list[tuple[str, dict[str, Any]]]) -> dict[str, Any] | None:
    return next((p for m, p in events if m == "index" and p["event"] != "progress"), None)


def _start(service: PcapService, tmp_path: Path, **params: Any) -> dict[str, Any]:
    return service.capture_start(
        {"dest": str(tmp_path / "live.pcapng"), "interfaces": ["fake0"], **params},
        RequestContext(),
    )


@pytest.mark.tshark
@pytest.mark.usefixtures("fake")
def test_interfaces_and_filters(service: PcapService) -> None:
    ifaces = service.list_interfaces({}, RequestContext())["interfaces"]
    assert [i["name"] for i in ifaces] == ["fake0", "lo"]
    assert ifaces[1]["loopback"] and ifaces[0]["addresses"] == ["10.0.0.1", "fe80::1"]
    check = service.validate_capture_filter
    assert check({"interface": "fake0", "filter": ""}, RequestContext())["valid"]
    assert check({"interface": "fake0", "filter": "tcp"}, RequestContext()) == {
        "valid": True,
        "checked": True,
    }
    bad = check({"interface": "fake0", "filter": "invalid x"}, RequestContext())
    assert bad["valid"] is False and "syntax error" in bad["error"]


@pytest.mark.tshark
def test_capture_until_stopped(
    service: PcapService, fake: Callable[..., None], tmp_path: Path
) -> None:
    fake(delay=0.05, drops=3)
    events = _events(service)
    res = _start(service, tmp_path, filter="ip")
    assert res["indexing"] is True and res["capture"]["running"] is True
    assert res["capture"]["interfaces"] == ["fake0"] and res["capture"]["filter"] == "ip"
    _wait(lambda: len(service.list_packets({"limit": 50}, RequestContext())["rows"]) >= 5)
    detail = service.packet_detail({"number": 2}, RequestContext())
    assert detail["tree"][0]["label"].startswith("Frame 2:"), "the file is readable meanwhile"
    _wait(lambda: any(m == "capture" and p["event"] == "stats" for m, p in events))
    assert service.capture_stop({}, RequestContext()) == {"stopped": True}
    _wait(lambda: _index_done(events) is not None)
    stopped = next(p for m, p in events if m == "capture" and p["event"] == "stopped")
    done = _index_done(events)
    assert done is not None and done["event"] == "done"
    frames = done["info"]["frames"]
    assert 5 <= frames <= MIXED_PACKETS and stopped["packets"] == frames
    if sys.platform != "win32":  # (Windows kills dumpcap: no statistics)
        assert stopped["dropped"] == 3
        assert any("3 packets were dropped" in w for w in done["info"]["warnings"])
    assert done["info"]["capture"]["running"] is False
    assert service.capture_stop({}, RequestContext()) == {"stopped": False}
    # The file is a complete pcapng: sorting and everything else work now.
    page = service.list_packets(
        {"limit": 3, "sort": {"field": "frame.len", "desc": True}}, RequestContext()
    )
    assert len(page["rows"]) == 3
    assert comments.read_comments(tmp_path / "live.pcapng") == {}
    assert done["info"]["size"] == (tmp_path / "live.pcapng").stat().st_size


@pytest.mark.tshark
@pytest.mark.usefixtures("fake")
def test_limits_stop_the_capture(service: PcapService, tmp_path: Path) -> None:
    events = _events(service)
    _start(service, tmp_path, limits={"packets": 4})
    _wait(lambda: _index_done(events) is not None)
    assert service.capture_info({}, RequestContext())["frames"] == 4

    events.clear()
    service.capture_start(
        {"dest": str(tmp_path / "b.pcapng"), "interfaces": ["fake0"], "limits": {"bytes": 1000}},
        RequestContext(),
    )
    _wait(lambda: _index_done(events) is not None)
    size = (tmp_path / "b.pcapng").stat().st_size
    assert 1000 <= size < 3000, "stops at the first block past the limit"
    assert service.capture_info({}, RequestContext())["frames"] < MIXED_PACKETS
    for bad in ({"packets": -1}, {"seconds": "x"}, {"packets": 1.5}):
        with pytest.raises(InvalidParamsError):
            _start(service, tmp_path, limits=bad)


@pytest.mark.tshark
def test_capture_failures(service: PcapService, fake: Callable[..., None], tmp_path: Path) -> None:
    fake(fail="You don't have permission to capture on that device (socket: Operation not "
         "permitted)")  # fmt: skip
    with pytest.raises(ToolError) as info:
        _start(service, tmp_path)
    assert "don't have permission" in str(info.value)
    assert "Capturing on 'fake0'" not in str(info.value), "dumpcap's own chatter is dropped"
    if sys.platform.startswith("linux"):
        assert "CAP_NET_RAW" in str(info.value)
    fake(fail="")
    with pytest.raises(ToolError, match="no device named"):
        _start(service, tmp_path, interfaces=["nosuch"])
    with pytest.raises(InvalidParamsError):
        _start(service, tmp_path, interfaces=[])
    with pytest.raises(InvalidParamsError):
        service.capture_start({"dest": "relative.pcapng", "interfaces": ["x"]}, RequestContext())
    assert len(PROCESSES) == 0


@pytest.mark.tshark
def test_close_while_capturing(
    service: PcapService, fake: Callable[..., None], tmp_path: Path
) -> None:
    fake(delay=0.2)
    _start(service, tmp_path)
    started = time.monotonic()
    service.close()
    assert time.monotonic() - started < 10
    _wait(lambda: len(PROCESSES) == 0)


@pytest.mark.tshark
@pytest.mark.usefixtures("fake")
def test_rejected_columns_are_retried_before_capturing(
    service: PcapService, tmp_path: Path
) -> None:
    """The live stream can be read once: fields tshark rejects are found with
    the empty capture, and the pass runs without them."""
    events = _events(service)
    res = _start(service, tmp_path, columns=["ip.ttl", "no.such_field"], limits={"packets": 6})
    assert [c["id"] for c in res["columns"]][-1] == "ip.ttl"
    assert any("no.such_field" in w for w in res["warnings"])
    _wait(lambda: _index_done(events) is not None)
    rows = service.list_packets({"limit": 10}, RequestContext())["rows"]
    assert len(rows) == 6


@pytest.mark.tshark
def test_filter_during_capture_is_not_cached(
    service: PcapService, fake: Callable[..., None], tmp_path: Path
) -> None:
    fake(delay=0.1)
    events = _events(service)
    _start(service, tmp_path)
    _wait(lambda: len(service.list_packets({"limit": 50}, RequestContext())["rows"]) >= 3)
    early = service.set_filter({"expr": "frame", "stream": True}, RequestContext())
    _wait(lambda: any(m == "filter" and p["event"] == "done" for m, p in events))
    service.capture_stop({}, RequestContext())
    _wait(lambda: _index_done(events) is not None)
    total = service.capture_info({}, RequestContext())["frames"]
    again = service.set_filter({"expr": "frame"}, RequestContext())
    assert again["matchCount"] == total
    assert early["matchCount"] <= total


def _loopback_name(service: PcapService) -> str | None:
    try:
        ifaces = service.list_interfaces({}, RequestContext())["interfaces"]
    except ToolError, OSError:
        return None
    return next((i["name"] for i in ifaces if i["loopback"]), None)


@pytest.mark.tshark
def test_real_capture_on_loopback(service: PcapService, tmp_path: Path) -> None:
    """With the real dumpcap, when this machine lets us capture on loopback."""
    import socket  # noqa: PLC0415

    name = _loopback_name(service)
    if name is None:
        pytest.skip("dumpcap lists no loopback interface")
    events = _events(service)
    port = 40000 + int(time.time()) % 20000
    try:
        service.capture_start(
            {
                "dest": str(tmp_path / "lo.pcapng"),
                "interfaces": [name],
                "filter": f"udp port {port}",
            },
            RequestContext(),
        )
    except ToolError as exc:
        pytest.skip(f"no permission to capture here: {exc}")
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        for _ in range(20):
            sock.sendto(b"hello", ("127.0.0.1", port))
            time.sleep(0.05)
            if service.list_packets({"limit": 5}, RequestContext())["total"] >= 3:
                break
    _wait(lambda: service.list_packets({"limit": 5}, RequestContext())["total"] >= 3)
    service.capture_stop({}, RequestContext())
    _wait(lambda: _index_done(events) is not None)
    assert (
        service.set_filter({"expr": f"udp.dstport == {port}"}, RequestContext())["matchCount"] >= 3
    )
