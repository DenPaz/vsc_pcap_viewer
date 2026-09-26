from pcap_backend import stats


def test_parse_size_units() -> None:
    assert stats.parse_size("1175 bytes") == 1175
    assert stats.parse_size("12 kB") == 12_000
    assert stats.parse_size("1.5 MB") == 1_500_000
    assert stats.parse_size("1,234") == 1234
    assert stats.parse_size("") == 0
    assert stats.parse_size("n/a") == 0


def test_split_endpoint() -> None:
    assert stats.split_endpoint("10.0.0.1:80", True) == ("10.0.0.1", "80")
    assert stats.split_endpoint("[fe80::1]:443", True) == ("fe80::1", "443")
    assert stats.split_endpoint("fe80::1", False) == ("fe80::1", None)
    assert stats.split_endpoint("host.example", True) == ("host.example", None)


def test_endpoint_filter() -> None:
    assert (
        stats.endpoint_filter("tcp", ["10.0.0.1:80", "10.0.0.2:5000"])
        == "ip.addr == 10.0.0.1 && tcp.port == 80 && ip.addr == 10.0.0.2 && tcp.port == 5000"
    )
    assert stats.endpoint_filter("ipv6", ["fe80::1"]) == "ipv6.addr == fe80::1"
    assert (
        stats.endpoint_filter("tcp", ["[fe80::1]:443"]) == "ipv6.addr == fe80::1 && tcp.port == 443"
    )
    assert stats.endpoint_filter("eth", ["02:00:00:00:00:01"]) == "eth.addr == 02:00:00:00:00:01"
    # Resolved names or missing ports can't be turned into a reliable filter.
    assert stats.endpoint_filter("ip", ["router.local"]) is None
    assert stats.endpoint_filter("tcp", ["10.0.0.1"]) is None


CONV = """\
================================================================================
TCP Conversations
Filter:<No Filter>
                                               |       <-      | |       ->      | |     Total     |    Relative    |   Duration   |
                                               | Frames  Bytes | | Frames  Bytes | | Frames  Bytes |      Start     |              |
10.0.0.1:443           <-> 10.0.0.2:50000        1200 1.5 MB         900 64 kB        2100 1.564 MB   0.000100000       12.5000
router.local:53        <-> 10.0.0.2:40000           1 98 bytes         1 71 bytes         2 169 bytes     0.006000000         0.0020
================================================================================
"""


def test_parse_conversations_units_and_directions() -> None:
    table = stats.parse_conversations(CONV, "tcp")
    assert table.title == "TCP Conversations"
    first, second = table.rows
    # cells: a, b, packets, bytes, packets A->B, bytes A->B, packets B->A, bytes B->A, start, dur
    assert first["cells"] == [
        "10.0.0.1:443", "10.0.0.2:50000", 2100, 1_564_000, 900, 64_000, 1200, 1_500_000, 0.0001, 12.5,
    ]  # fmt: skip
    assert "filter" in first
    assert "filter" not in second  # resolved name


ENDPOINTS_TCP = """\
================================================================================
TCP Endpoints
Filter:<No Filter>
                       |  Port  ||  Packets  | |  Bytes  | | Tx Packets | | Tx Bytes | | Rx Packets | | Rx Bytes |
192.168.1.10              50000         11          1175          6             414           5             761
fe80::1                     443          3        2 kB          1             500           2          1500
================================================================================
"""


def test_parse_endpoints_with_ports() -> None:
    table = stats.parse_endpoints(ENDPOINTS_TCP, "tcp")
    assert [c["label"] for c in table.columns][:2] == ["Address", "Port"]
    assert table.rows[0]["cells"] == ["192.168.1.10", 50000, 11, 1175, 6, 414, 5, 761]
    assert table.rows[0]["filter"] == "ip.addr == 192.168.1.10 && tcp.port == 50000"
    assert table.rows[1]["cells"][3] == 2000
    assert table.rows[1]["filter"] == "ipv6.addr == fe80::1 && tcp.port == 443"


PHS = """\
===================================================================
Protocol Hierarchy Statistics
Filter:

eth                                      frames:10 bytes:1000
  ip                                     frames:8 bytes:900
    tcp                                  frames:8 bytes:900
  arp                                    frames:2 bytes:100
===================================================================
"""


def test_parse_protocol_hierarchy_percentages() -> None:
    table = stats.parse_protocol_hierarchy(PHS)
    assert [(r["depth"], r["cells"][0]) for r in table.rows] == [
        (0, "eth"), (1, "ip"), (2, "tcp"), (1, "arp"),
    ]  # fmt: skip
    assert table.rows[1]["cells"] == ["ip", 80.0, 8, 90.0, 900]
    assert table.rows[3]["filter"] == "arp"


# test/fixtures/mixed.pcapng, as tshark 4.2.2 prints it.
PHS_42 = """\
eth                                      frames:26 bytes:2141
  arp                                    frames:1 bytes:42
  ip                                     frames:25 bytes:2099
    icmp                                 frames:2 bytes:92
    udp                                  frames:12 bytes:832
      dns                                frames:6 bytes:502
      data                               frames:6 bytes:330
    tcp                                  frames:11 bytes:1175
"""
# tshark 4.6 adds a top-level "frame" row, so every protocol is one level
# deeper (eth at depth 1, dns at depth 4), as reported from a 4.6.4 run.
PHS_46 = "frame                                    frames:26 bytes:2141\n" + "".join(
    f"  {line}\n" for line in PHS_42.strip("\n").split("\n")
)


def _parent(rows: list[dict[str, object]], name: str) -> tuple[object, object, object]:
    i = next(i for i, r in enumerate(rows) if r["cells"][0] == name)  # type: ignore[index]
    depth = rows[i]["depth"]
    up = next(r for r in reversed(rows[:i]) if r["depth"] < depth)  # type: ignore[operator]
    return up["cells"][0], depth, rows[i]["cells"][2]  # type: ignore[index]


def test_protocol_hierarchy_depth_differs_by_version_parent_does_not() -> None:
    old = stats.parse_protocol_hierarchy(PHS_42).rows
    new = stats.parse_protocol_hierarchy(PHS_46).rows
    assert [(r["depth"], r["cells"][0]) for r in new][:3] == [(0, "frame"), (1, "eth"), (2, "arp")]
    assert _parent(old, "dns") == ("udp", 3, 6)
    assert _parent(new, "dns") == ("udp", 4, 6)
    # Percentages only count the top level, so the extra level changes nothing.
    assert [r["cells"][1] for r in old if r["cells"][0] == "dns"] == [23.1]
    assert [r["cells"][1] for r in new if r["cells"][0] == "dns"] == [23.1]


IO = """\
| Interval     | Frames | Bytes |
|-------------------------------|
| 0.0 <> 1.0   |      5 |   303 |
| 1.0 <> Dur   |      2 |    90 |
=================================
"""


def test_parse_io_stat_last_interval() -> None:
    table = stats.parse_io_stat(IO, 1.0)
    assert [r["cells"] for r in table.rows] == [[0, 1, 5, 303], [1, 2, 2, 90]]
    assert table.to_json()["interval"] == 1.0


def test_io_interval_picks_1_2_5_steps() -> None:
    assert stats.io_interval(0.05) == 0.001
    assert stats.io_interval(1.0) == 0.01
    assert stats.io_interval(30) == 0.5
    assert stats.io_interval(3600) == 50
    assert stats.io_interval(None) == 1.0
    assert stats.io_interval(0) == 1.0


# Rows as tshark prints them ("%12u %10s %18s  %s"), including overflowing groups.
EXPERT = "\nErrors (1)\n=============\n   Frequency      Group           Protocol  Summary\n           1  Malformed                DNS  Malformed Packet (Exception occurred)\n\nWarns (2)\n=============\n   Frequency      Group           Protocol  Summary\n           3 Dissector bug                TCP  Bad, thing, happened\n           1 Response code             HTTP 2  Server error  (500)\n\nChats (1)\n=============\n   Frequency      Group           Protocol  Summary\n           2   Sequence                TCP  Connection finish (FIN)\n"

EXPERT_FIELDS = (
    "5\tExpert Info (Error/Malformed): Malformed Packet (Exception occurred)\n"
    "7\tExpert Info (Warning/Dissector bug): Bad, thing, happened\x1e"
    "Expert Info (Chat/Sequence): Connection finish (FIN)\n"
    "8\tExpert Info (Chat/Sequence): Connection finish (FIN)\n"
    "\n"
)


def test_parse_expert_joins_frames_and_orders_by_severity() -> None:
    table = stats.parse_expert(EXPERT, EXPERT_FIELDS)
    rows = [(r["cells"], r.get("frames")) for r in table.rows]
    assert rows == [
        (["Error", "Malformed Packet (Exception occurred)", "Malformed", "DNS", 1], [5]),
        (["Warning", "Bad, thing, happened", "Dissector bug", "TCP", 3], [7]),
        (["Warning", "Server error  (500)", "Response code", "HTTP 2", 1], None),
        (["Chat", "Connection finish (FIN)", "Sequence", "TCP", 2], [7, 8]),
    ]


def test_parse_expert_splits_only_on_newlines() -> None:
    # \x1c-\x1e are line breaks for str.splitlines but can appear in packet text.
    fields = "3\tExpert Info (Chat/Sequence): odd\x1cmessage\n"
    summary = (
        "Chats (1)\n=============\n   Frequency      Group           Protocol  Summary\n"
        "           1   Sequence                TCP  odd\x1cmessage\n"
    )
    (row,) = stats.parse_expert(summary, fields).rows
    assert row["frames"] == [3]


CAPINFOS = """\
File name:           a.pcapng
Number of packets:   26
Interface #0 info:
                     Encapsulation = Ethernet (1 - ether)
                     Capture length = 262144
"""


def test_parse_capinfos_properties() -> None:
    rows = [(r["cells"], r.get("depth", 0)) for r in stats.parse_capinfos_properties(CAPINFOS).rows]
    assert rows == [
        (["File name", "a.pcapng"], 0),
        (["Number of packets", "26"], 0),
        (["Interface #0 info", ""], 0),
        (["Encapsulation", "Ethernet (1 - ether)"], 1),
        (["Capture length", "262144"], 1),
    ]


FOLLOW = """\

===================================================================
Follow: tcp,raw
Filter: tcp.stream eq 3
Node 0: 10.0.0.1:5000
Node 1: [fe80::1]:80
4142
4344
\t6f6b
zz-not-hex
abc
===================================================================
"""


def test_parse_follow_raw_merges_directions_and_skips_garbage() -> None:
    res = stats.parse_follow_raw(FOLLOW)
    assert res["filter"] == "tcp.stream eq 3"
    assert res["nodes"] == ["10.0.0.1:5000", "[fe80::1]:80"]
    assert res["segments"] == [{"dir": 0, "hex": "41424344"}, {"dir": 1, "hex": "6f6b"}]
    assert res["bytes"] == [4, 2]


def test_parse_follow_raw_truncated_output() -> None:
    res = stats.parse_follow_raw("Filter: udp.stream eq 0\nNode 0: a:1\nNode 1: b:2\n00ff\n\t012")
    assert res["segments"] == [{"dir": 0, "hex": "00ff"}]  # odd-length trailing chunk dropped
