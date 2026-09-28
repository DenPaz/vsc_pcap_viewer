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


# test/fixtures/services.pcap, as tshark 4.2.2 prints ``-z http,tree`` (trimmed).
HTTP_TREE = """\

=========================================================================================================
HTTP/Packet Counter:
Topic / Item              Count         Average       Min Val       Max Val       Rate (ms)     Percent
---------------------------------------------------------------------------------------------------------
Total HTTP Packets        8                                                       0.0265        100%
 HTTP Response Packets    4                                                       0.0132        50.00%
  2xx: Success            2                                                       0.0066        50.00%
   200 OK                 2                                                       0.0066        100.00%
  ???: broken             0                                                       0.0000        0.00%
 HTTP Request Packets     4                                                       0.0132        50.00%
  GET                     3                                                       0.0099        75.00%
  M-SEARCH                1                                                       0.0033        25.00%

---------------------------------------------------------------------------------------------------------
"""


def test_parse_stats_tree_depths_empty_columns_and_filters() -> None:
    table = stats.parse_stats_tree(HTTP_TREE, "http").to_json()
    # Average/Min/Max are blank in every row: dropped.
    assert [c["label"] for c in table["columns"]] == [
        "Topic / Item",
        "Count",
        "Rate (ms)",
        "Percent",
    ]
    rows = {r["cells"][0]: r for r in table["rows"]}
    assert rows["200 OK"]["depth"] == 3
    assert rows["200 OK"]["cells"] == ["200 OK", 2, 0.0066, 100.0]
    assert rows["Total HTTP Packets"]["cells"][3] == 100
    assert rows["200 OK"]["filter"] == "http.response.code == 200"
    assert rows["2xx: Success"]["filter"] == (
        "http.response.code >= 200 && http.response.code <= 299"
    )
    assert rows["M-SEARCH"]["filter"] == 'http.request.method == "M-SEARCH"'
    assert "filter" not in rows["???: broken"]


def test_stats_tree_filters_quote_hosts_and_uris() -> None:
    text = """\
Topic / Item                Count         Rate (ms)     Percent
---------------------------------------------------------------
HTTP Requests by HTTP Host  1             0.0100        100%
 we"ird.example             1             0.0100        100.00%
  /a b\\c                    1             0.0100        100.00%
"""
    rows = stats.parse_stats_tree(text, "http_requests").rows
    assert rows[1]["filter"] == 'http.host == "we\\"ird.example"'
    assert rows[2]["filter"] == (
        'http.host == "we\\"ird.example" && http.request.uri == "/a b\\\\c"'
    )


def test_stats_tree_packet_length_buckets() -> None:
    text = """\
Topic / Item       Count         Average       Min Val       Max Val
--------------------------------------------------------------------
Packet Lengths     2             60.00         54            66
 40-79             2             60.00         54            66
 5120 and greater  0             -             -             -
"""
    rows = stats.parse_stats_tree(text, "plen").rows
    assert "filter" not in rows[0]
    assert rows[1]["filter"] == "frame.len >= 40 && frame.len <= 79"
    assert rows[1]["cells"] == ["40-79", 2, 60.0, 54, 66]
    assert rows[2]["filter"] == "frame.len >= 5120"
    assert rows[2]["cells"] == ["5120 and greater", 0, None, None, None]


def test_stats_tree_without_a_header_is_empty() -> None:
    assert stats.parse_stats_tree("tshark: nothing\n", "dns").rows == []


SNMP_SRT = """\

===================================================================
SNMP SRT Statistics:
Filter: snmp.data
Index  Procedure              Calls    Min SRT    Max SRT    Avg SRT    Sum SRT
    0  Get                         3   0.004000   0.010000   0.007000   0.021000
    1  GetNext                     1   0.002000   0.002000   0.002000   0.002000
==================================================================
"""


def test_parse_srt_rows_filter_on_the_reported_field() -> None:
    table = stats.parse_srt(SNMP_SRT, "snmp").to_json()
    assert table["title"] == "SNMP Service Response Time"
    assert table["rows"][0]["cells"] == ["Get", 0, 3, 0.004, 0.01, 0.007, 0.021]
    assert table["rows"][1]["filter"] == "snmp.data == 1"


def test_parse_srt_several_tables_get_a_table_column_and_no_filter() -> None:
    text = """\
===================================================================
SMB SRT Statistics:
Filter: smb.cmd
Index  Commands               Calls    Min SRT    Max SRT    Avg SRT    Sum SRT
  114  Negotiate Protocol          1   0.001000   0.001000   0.001000   0.001000

Transaction2 Commands
Index  Transaction2 Commands  Calls    Min SRT    Max SRT    Avg SRT    Sum SRT
    1  FIND_FIRST2                 2   0.002000   0.004000   0.003000   0.006000
==================================================================
"""
    table = stats.parse_srt(text, "smb").to_json()
    assert table["columns"][0]["label"] == "Table"
    assert [r["cells"][:2] for r in table["rows"]] == [
        ["Commands", "Negotiate Protocol"],
        ["Transaction2 Commands", "FIND_FIRST2"],
    ]
    assert all("filter" not in r for r in table["rows"])


def test_parse_icmp_srt_goes_to_the_slowest_reply() -> None:
    text = """\
==========================================================================
ICMP Service Response Time (SRT) Statistics (all times in ms):
Filter: <none>

Requests  Replies   Lost      % Loss
3         2         1          33.3%

Minimum   Maximum   Mean      Median    SDeviation     Min Frame Max Frame
3.000     9.000     6.000     6.000     4.243          58        60
==========================================================================
"""
    table = stats.parse_icmp_srt(text, "icmp").to_json()
    assert table["rows"] == [
        {
            "cells": [3, 2, 1, 33.3, 3, 9, 6, 6, 4.243, 58, 60],
            "frame": 60,
            "filter": "icmp.type == 8 || icmp.type == 0",
        }
    ]
    no_replies = text.replace(
        "3         2         1          33.3%", "1         0         1         100.0%"
    )
    no_replies = no_replies.split("Minimum")[0]
    assert stats.parse_icmp_srt(no_replies, "icmp").rows[0]["cells"][:4] == [1, 0, 1, 100]


def _tree_46(first_column: str, rows: list[tuple[int, str, list[str]]]) -> str:
    """A stats tree as tshark 4.6's stats_tree.c prints it: the name column is
    padded to the longest topic (a longer first-column name isn't cut), then
    " %-14s" per value column; the rules are as long as a row."""
    cols = ["Count", "Average", "Min Val", "Max Val", "Rate (ms)", "Percent", "Burst Rate"]
    width = max(len(name) + depth for depth, name, _ in rows)
    rule = width + 15 * len(cols)
    head = first_column.ljust(width) + "".join(" " + c.ljust(14) for c in cols)
    body = [
        " " * depth + name.ljust(width - depth) + "".join(" " + v.ljust(14) for v in values)
        for depth, name, values in rows
    ]
    return "\n".join(["", "=" * rule, "DNS:", head, "-" * rule, *body, "", "-" * rule, ""])


def test_stats_tree_first_column_named_by_the_tree() -> None:
    """tshark 4.4+: HTTP and DNS name the first column "Packet Type"."""
    text = _tree_46(
        "Packet Type",
        [
            (0, "Total Packets", ["8", "", "", "", "0.0242", "100%", "0.0300"]),
            (1, "rcode", ["8", "", "", "", "0.0242", "100.00%", "0.0300"]),
            (2, "No such name", ["1", "", "", "", "0.0030", "12.50%", "0.0100"]),
        ],
    )
    table = stats.parse_stats_tree(text, "dns").to_json()
    assert [c["label"] for c in table["columns"]] == [
        "Packet Type", "Count", "Rate (ms)", "Percent", "Burst Rate",
    ]  # fmt: skip
    assert table["rows"][2]["cells"] == ["No such name", 1, 0.003, 12.5, 0.01]
    assert table["rows"][2]["depth"] == 2
    assert table["rows"][2]["filter"] == "dns.flags.rcode == 3"


def test_stats_tree_first_column_name_longer_than_every_topic() -> None:
    """The header's value columns sit right of the rows' by the overflow."""
    text = _tree_46(
        "Request Type",
        [
            (0, "GET", ["3", "", "", "", "0.0099", "75.00%", "0.0100"]),
            (0, "POST", ["1", "", "", "", "0.0033", "25.00%", "0.0100"]),
        ],
    )
    assert "Request Type Count" in text  # one space: the name column is 4 wide
    rows = stats.parse_stats_tree(text, "http_requests").rows
    assert [r["cells"] for r in rows] == [
        ["GET", 3, 0.0099, 75.0, 0.01],
        ["POST", 1, 0.0033, 25.0, 0.01],
    ]


def test_dns_filters_follow_the_parent_whatever_the_depth() -> None:
    """tshark 4.2 nests Query Type under Total Packets; 4.6 puts it on top."""
    for rows in (
        [(0, "Total Packets"), (1, "Query Type"), (2, "AAAA")],
        [(0, "Total Packets"), (0, "Query Type"), (1, "AAAA")],
    ):
        text = _tree_46(
            "Packet Type",
            [(d, n, ["2", "", "", "", "0.0061", "25.00%", "0.0200"]) for d, n in rows],
        )
        by_name = {r["cells"][0]: r for r in stats.parse_stats_tree(text, "dns").rows}
        assert by_name["AAAA"]["filter"] == "dns.qry.type == 28"
        assert by_name["Total Packets"]["filter"] == "dns"
    text = _tree_46(
        "Packet Type",
        [(0, "Query Name", ["1"] + [""] * 6), (1, "example.com", ["1"] + [""] * 6),
         (0, "Answer Type", ["1"] + [""] * 6), (1, "MX", ["1"] + [""] * 6)],
    )  # fmt: skip
    rows = stats.parse_stats_tree(text, "dns").rows
    assert rows[1]["filter"] == 'dns.qry.name == "example.com"'
    assert rows[3]["filter"] == "dns.resp.type == 15"


def test_dns_query_response_under_its_46_display_name() -> None:
    """tshark 4.6 shows the top-level "Query/Response" node as "Response"."""
    for parent, depth in (("Query/Response", 1), ("Response", 0)):
        rows = [(0, "Total Packets")] if depth else []
        rows += [(depth, parent), (depth + 1, "Response"), (depth + 1, "Query")]
        text = _tree_46("Packet Type", [(d, n, ["4"] + [""] * 6) for d, n in rows])
        by_depth = [r for r in stats.parse_stats_tree(text, "dns").rows if r["depth"] == depth + 1]
        assert [r.get("filter") for r in by_depth] == [
            "dns.flags.response == 1",
            "dns.flags.response == 0",
        ]
