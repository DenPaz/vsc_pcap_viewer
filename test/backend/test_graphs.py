"""Flow graph (flow_graph) and TCP stream graphs (tcp_graph)."""

import threading
from pathlib import Path

import pytest

from pcap_backend import pcap_service
from pcap_backend.pcap_service import PcapService, parse_tcp_graph
from pcap_backend.protocol import IndexingError, InvalidParamsError, RequestContext

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures"


@pytest.mark.tshark
def test_flow_graph(service: PcapService, ctx: RequestContext) -> None:
    service.open({"path": str(FIXTURES / "mixed.pcapng")}, ctx)
    flow = service.flow_graph({"offset": 0, "limit": 3}, ctx)
    assert flow["total"] == 26 and flow["more"] == 0
    # Endpoints in order of first appearance (ARP's MACs first, then IPs).
    assert flow["nodes"][:4] == ["02:00:00:00:00:01", "Broadcast", "192.168.1.10", "192.168.1.1"]
    first = flow["rows"][0]
    assert (first["number"], first["from"], first["to"], first["protocol"]) == (1, 0, 1, "ARP")
    assert [r["number"] for r in flow["rows"]] == [1, 2, 3]
    ping, reply = flow["rows"][1:]
    assert (ping["from"], ping["to"]) == (reply["to"], reply["from"])

    page = service.flow_graph({"offset": 24, "limit": 10}, ctx)
    assert [r["number"] for r in page["rows"]] == [25, 26]

    # It follows the display filter, in capture order whatever the sort.
    service.set_filter({"expr": "dns"}, ctx)
    service.list_packets(
        {"offset": 0, "limit": 5, "sort": {"field": "frame.len", "desc": True}}, ctx
    )
    flow = service.flow_graph({"offset": 0, "limit": 10}, ctx)
    assert flow["nodes"] == ["192.168.1.10", "8.8.8.8"] and flow["total"] == 6
    numbers = [r["number"] for r in flow["rows"]]
    assert numbers == sorted(numbers)
    assert flow["filterId"] == service.list_packets({"limit": 1}, ctx)["filterId"]


@pytest.mark.tshark
def test_flow_graph_caps_the_endpoints(
    service: PcapService, ctx: RequestContext, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(pcap_service, "MAX_FLOW_NODES", 3)
    service.open({"path": str(FIXTURES / "mixed.pcapng")}, ctx)
    flow = service.flow_graph({"offset": 0, "limit": 30}, ctx)
    assert len(flow["nodes"]) == 3 and flow["more"] == 5
    assert all(-1 <= r["from"] < 3 and -1 <= r["to"] < 3 for r in flow["rows"])
    assert any(r["to"] == -1 for r in flow["rows"]), "past the cap: the 'other' column"


@pytest.mark.tshark
def test_flow_graph_waits_for_indexing(
    service: PcapService, ctx: RequestContext, slow_index: threading.Event
) -> None:
    assert service.open({"path": str(FIXTURES / "mixed.pcapng"), "stream": True}, ctx)["indexing"]
    with pytest.raises(IndexingError):
        service.flow_graph({}, ctx)
    slow_index.set()


def test_parse_tcp_graph() -> None:
    text = "\n".join(  # noqa: FLY002 - one tshark row per line
        [
            "1\t0.000\t10.0.0.1\t\t4000\t0\t0\t0\t64240\t\t\tTrue",
            "2\t0.010\t10.0.0.2\t\t80\t0\t0\t1\t65535\t0.010\t\t1",
            "3\t0.020\t10.0.0.1\t\t4000\t1\t100\t1\t64240\t\t\t0",
            "4\t0.030\t10.0.0.1\t\t4000\t1\t100\t1\t64240\t\t1\t0",  # a retransmission
            "5\t0.040\t\tfe80::2\t80\t1\t0\t101\t65535\t0.02\t\t0",
            "garbage",
        ]
    )
    graph = parse_tcp_graph(text)
    assert graph["endpoints"] == ["10.0.0.1:4000", "10.0.0.2:80"]
    assert graph["fields"][:3] == ["frame", "time", "dir"]
    assert graph["points"][0] == [1, 0.0, 0, 0, 0, 0, 64240, None, 0, 1]
    assert graph["points"][1][2] == 1 and graph["points"][1][7] == 0.01
    assert graph["points"][3][8] == 1
    assert len(graph["points"]) == 5
    assert parse_tcp_graph("") == {"endpoints": [], "fields": graph["fields"], "points": []}


@pytest.mark.tshark
def test_tcp_graph(opened: PcapService, ctx: RequestContext) -> None:
    graph = opened.tcp_graph({"frame": 4}, ctx)
    assert graph["stream"] == 0
    assert graph["endpoints"] == ["192.168.1.10:50000", "93.184.216.34:80"]
    points = graph["points"]
    assert len(points) == 11 and [p[0] for p in points] == list(range(1, 12))
    assert points[0][9] == 1, "the SYN"
    data = [(p[3], p[4]) for p in points if p[2] == 1 and p[4]]
    assert data == [(1, 200), (201, 291)], "the response in two segments"
    assert any(p[7] is not None for p in points), "round-trip times"
    assert opened.tcp_graph({"stream": 0}, ctx) is graph, "cached"
    assert opened.tcp_graph({"stream": 7}, ctx)["points"] == [], "no such stream"
    with pytest.raises(InvalidParamsError):
        opened.tcp_graph({"stream": -1}, ctx)


@pytest.mark.tshark
def test_tcp_graph_needs_a_tcp_packet(service: PcapService, ctx: RequestContext) -> None:
    service.open({"path": str(FIXTURES / "dns.pcap")}, ctx)
    with pytest.raises(InvalidParamsError, match="not part of a TCP stream"):
        service.tcp_graph({"frame": 1}, ctx)
