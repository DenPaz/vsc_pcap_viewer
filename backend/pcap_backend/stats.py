"""Parsers for tshark's statistics (``-z``) reports and ``follow`` output.

tshark prints these reports as human-oriented text tables; each parser turns
one into a generic :class:`Table` that the webview renders:

* ``columns``: ``{"id", "label", "numeric"}``
* ``rows``: ``{"cells": [...], "filter"?: display filter for the row,
  "frame"?: first frame to jump to, "depth"?: tree depth (protocol hierarchy)}``

Parsers are pure functions of the text so they can be unit-tested against
captured output; the tshark invocations live in ``pcap_service``.
"""

import re
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from .navigation import dfilter_string

# ---------------------------------------------------------------------- tables


@dataclass
class Table:
    kind: str
    title: str
    columns: list[dict[str, Any]]
    rows: list[dict[str, Any]] = field(default_factory=list)
    extra: dict[str, Any] = field(default_factory=dict)

    def to_json(self) -> dict[str, Any]:
        return {
            "kind": self.kind,
            "title": self.title,
            "columns": self.columns,
            "rows": self.rows,
            **self.extra,
        }


def _lines(text: str) -> list[str]:
    """Split on newlines only: ``str.splitlines`` also breaks on characters such
    as ``\x1c``-``\x1e`` and ``\x85``, which can occur in packet-derived text
    (and ``\x1e`` is our field aggregator)."""
    return [line.removesuffix("\r") for line in text.split("\n")]


def _col(id_: str, label: str, numeric: bool = False) -> dict[str, Any]:
    return {"id": id_, "label": label, "numeric": numeric}


_UNITS = {"bytes": 1, "byte": 1, "kB": 1000, "MB": 1000**2, "GB": 1000**3, "TB": 1000**4}


def parse_size(text: str) -> int | float:
    """``'1175 bytes'`` / ``'12 kB'`` / ``'1.5 MB'`` / ``'42'`` -> number of bytes."""
    parts = text.split()
    if not parts:
        return 0
    try:
        value = float(parts[0].replace(",", ""))
    except ValueError:
        return 0
    scale = _UNITS.get(parts[1], 1) if len(parts) > 1 else 1
    result = value * scale
    return int(result) if result == int(result) else result


def _number(text: str) -> int | float:
    try:
        f = float(text)
    except ValueError:
        return 0
    return int(f) if f == int(f) else f


# ---------------------------------------------------------------------- addresses


def split_endpoint(text: str, with_port: bool) -> tuple[str, str | None]:
    """Split ``'10.0.0.1:80'`` / ``'[fe80::1]:443'`` / ``'fe80::1'`` into (address, port)."""
    if not with_port:
        return text, None
    if text.startswith("["):
        addr, _, rest = text[1:].partition("]")
        return addr, rest.lstrip(":") or None
    addr, sep, port = text.rpartition(":")
    return (addr, port) if sep and port.isdigit() else (text, None)


def _addr_field(addr: str, conv_type: str) -> str | None:
    if conv_type == "eth":
        return "eth.addr"
    if conv_type == "ipv6" or addr.count(":") > 1:
        return "ipv6.addr"
    if re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", addr):
        return "ip.addr"
    return None  # resolved names etc.: no reliable filter


def endpoint_filter(conv_type: str, endpoints: list[str]) -> str | None:
    """Display filter matching traffic of one endpoint or between two endpoints."""
    with_port = conv_type in ("tcp", "udp")
    terms: list[str] = []
    for ep in endpoints:
        addr, port = split_endpoint(ep, with_port)
        fld = _addr_field(addr, conv_type)
        if fld is None:
            return None
        terms.append(f"{fld} == {addr}")
        if with_port:
            if port is None:
                return None
            terms.append(f"{conv_type}.port == {port}")
    return " && ".join(terms) if terms else None


# ---------------------------------------------------------------------- conversations

CONV_TYPES = ("eth", "ip", "ipv6", "tcp", "udp")
_CONV_ROW = re.compile(
    r"^(?P<a>\S+)\s+<->\s+(?P<b>\S+)\s+"
    r"(?P<fba>\d+)\s+(?P<bba>[\d.,]+(?: \w+)?)\s+"
    r"(?P<fab>\d+)\s+(?P<bab>[\d.,]+(?: \w+)?)\s+"
    r"(?P<ft>\d+)\s+(?P<bt>[\d.,]+(?: \w+)?)\s+"
    r"(?P<start>[\d.]+)\s+(?P<dur>[\d.]+)\s*$"
)


def parse_conversations(text: str, conv_type: str) -> Table:
    """``tshark -q -z conv,<type>``. Direction "A → B" is tshark's ``->`` column."""
    table = Table(
        "conversations",
        f"{_TYPE_LABEL.get(conv_type, conv_type)} Conversations",
        [
            _col("a", "Address A"),
            _col("b", "Address B"),
            _col("packets", "Packets", True),
            _col("bytes", "Bytes", True),
            _col("packets_ab", "Packets A → B", True),
            _col("bytes_ab", "Bytes A → B", True),
            _col("packets_ba", "Packets B → A", True),
            _col("bytes_ba", "Bytes B → A", True),
            _col("start", "Rel Start", True),
            _col("duration", "Duration", True),
        ],
    )
    for line in _lines(text):
        m = _CONV_ROW.match(line.strip())
        if not m:
            continue
        row: dict[str, Any] = {
            "cells": [
                m["a"],
                m["b"],
                int(m["ft"]),
                parse_size(m["bt"]),
                int(m["fab"]),
                parse_size(m["bab"]),
                int(m["fba"]),
                parse_size(m["bba"]),
                _number(m["start"]),
                _number(m["dur"]),
            ]
        }
        flt = endpoint_filter(conv_type, [m["a"], m["b"]])
        if flt:
            row["filter"] = flt
        table.rows.append(row)
    return table


_TYPE_LABEL = {"eth": "Ethernet", "ip": "IPv4", "ipv6": "IPv6", "tcp": "TCP", "udp": "UDP"}

# ---------------------------------------------------------------------- endpoints

_ENDPOINT_ROW = re.compile(
    r"^(?P<addr>\S+)(?:\s+(?P<port>\d+))?\s+"
    r"(?P<p>\d+)\s+(?P<b>[\d.,]+(?: (?:bytes|kB|MB|GB|TB))?)\s+"
    r"(?P<tp>\d+)\s+(?P<tb>[\d.,]+(?: (?:bytes|kB|MB|GB|TB))?)\s+"
    r"(?P<rp>\d+)\s+(?P<rb>[\d.,]+(?: (?:bytes|kB|MB|GB|TB))?)\s*$"
)


def parse_endpoints(text: str, ep_type: str) -> Table:
    """``tshark -q -z endpoints,<type>``."""
    with_port = ep_type in ("tcp", "udp")
    columns = [_col("address", "Address")]
    if with_port:
        columns.append(_col("port", "Port", True))
    columns += [
        _col("packets", "Packets", True),
        _col("bytes", "Bytes", True),
        _col("tx_packets", "Tx Packets", True),
        _col("tx_bytes", "Tx Bytes", True),
        _col("rx_packets", "Rx Packets", True),
        _col("rx_bytes", "Rx Bytes", True),
    ]
    table = Table("endpoints", f"{_TYPE_LABEL.get(ep_type, ep_type)} Endpoints", columns)
    in_body = False
    for line in _lines(text):
        if line.lstrip().startswith("|"):
            in_body = True  # rows follow the column header
            continue
        m = _ENDPOINT_ROW.match(line.strip()) if in_body else None
        if not m or (with_port and m["port"] is None):
            continue
        cells: list[Any] = [m["addr"]]
        if with_port:
            cells.append(int(m["port"]))
        cells += [
            int(m["p"]),
            parse_size(m["b"]),
            int(m["tp"]),
            parse_size(m["tb"]),
            int(m["rp"]),
            parse_size(m["rb"]),
        ]
        row: dict[str, Any] = {"cells": cells}
        ep = f"{m['addr']}:{m['port']}" if with_port else m["addr"]
        flt = endpoint_filter(ep_type, [ep])
        if flt:
            row["filter"] = flt
        table.rows.append(row)
    return table


# ---------------------------------------------------------------------- protocol hierarchy

_PHS_ROW = re.compile(
    r"^(?P<indent> *)(?P<proto>\S+)\s+frames:(?P<frames>\d+)\s+bytes:(?P<bytes>\d+)"
)


def parse_protocol_hierarchy(text: str) -> Table:
    """``tshark -q -z io,phs``: indentation (2 spaces per level) gives the tree."""
    table = Table(
        "phs",
        "Protocol Hierarchy",
        [
            _col("protocol", "Protocol"),
            _col("percent_packets", "Percent Packets", True),
            _col("packets", "Packets", True),
            _col("percent_bytes", "Percent Bytes", True),
            _col("bytes", "Bytes", True),
        ],
    )
    parsed = []
    for line in _lines(text):
        m = _PHS_ROW.match(line)
        if m:
            parsed.append((len(m["indent"]) // 2, m["proto"], int(m["frames"]), int(m["bytes"])))
    total_frames = sum(p[2] for p in parsed if p[0] == 0) or 1
    total_bytes = sum(p[3] for p in parsed if p[0] == 0) or 1
    for depth, proto, frames, nbytes in parsed:
        table.rows.append(
            {
                "cells": [
                    proto,
                    round(100 * frames / total_frames, 1),
                    frames,
                    round(100 * nbytes / total_bytes, 1),
                    nbytes,
                ],
                "depth": depth,
                "filter": proto,
            }
        )
    return table


# ---------------------------------------------------------------------- IO graph

_IO_ROW = re.compile(
    r"^\|\s*(?P<start>[\d.]+)\s*<>\s*(?P<end>[\d.]+|Dur)\s*\|\s*(?P<frames>\d+)\s*\|\s*(?P<bytes>\d+)\s*\|"
)


def parse_io_stat(text: str, interval: float) -> Table:
    """``tshark -q -z io,stat,<interval>[,<filter>]`` (first column: frames and bytes)."""
    table = Table(
        "io",
        "I/O Graph",
        [
            _col("start", "Start (s)", True),
            _col("end", "End (s)", True),
            _col("packets", "Packets", True),
            _col("bytes", "Bytes", True),
        ],
        extra={"interval": interval},
    )
    for line in _lines(text):
        m = _IO_ROW.match(line.strip())
        if not m:
            continue
        start = _number(m["start"])
        end = _number(m["end"]) if m["end"] != "Dur" else start + interval
        table.rows.append({"cells": [start, end, int(m["frames"]), int(m["bytes"])]})
    return table


def io_interval(duration: float | None, target_buckets: int = 100) -> float:
    """A 1-2-5 interval giving roughly ``target_buckets`` buckets (min 1 ms)."""
    if not duration or duration <= 0:
        return 1.0
    raw = duration / target_buckets
    step = 0.001
    while True:
        for m in (1, 2, 5):
            if step * m >= raw:
                return round(step * m, 6)
        step *= 10


# ---------------------------------------------------------------------- expert info

_SEVERITY_ORDER = {"Error": 0, "Errors": 0, "Warning": 1, "Warns": 1, "Note": 2, "Notes": 2}
_SEVERITY_NAME = {
    "Errors": "Error",
    "Warns": "Warning",
    "Notes": "Note",
    "Chats": "Chat",
    "Comments": "Comment",
}
_EXPERT_SECTION = re.compile(r"^(?P<name>Errors|Warns|Notes|Chats|Comments) \((?P<count>\d+)\)")
# tshark prints rows as "%12u %10s %18s  %s" (count, group, protocol, summary);
# multi-word groups overflow their column, so match known names explicitly.
_EXPERT_ROW = re.compile(
    r"^\s*(?P<count>\d+)\s+(?P<group>Response code|Request code|Dissector bug|\S+)\s+"
    r"(?P<proto>\S+(?: \S+)*?)  (?P<summary>.*)$"
)
_EXPERT_FIELD = re.compile(r"Expert Info \((?P<sev>[^/]+)/(?P<group>[^)]+)\): (?P<msg>.*)")
_EXPERT_SEVERITY_ALIAS = {"Warn": "Warning"}


def parse_expert(summary_text: str, fields_text: str, max_frames: int = 1000) -> Table:
    """Combine ``-z expert`` (severity/group/protocol/summary/count) with a
    ``-Y _ws.expert -T fields -e frame.number -e _ws.expert`` pass that maps each
    message to the frames it appears in (so rows can jump to packets).

    ``fields_text`` uses ``\\x1e`` as the aggregator between multiple items per frame.
    """
    frames: dict[tuple[str, str], list[int]] = {}
    for line in _lines(fields_text):
        number, _, items = line.partition("\t")
        if not number.isdigit():
            continue
        for item in items.split("\x1e"):
            m = _EXPERT_FIELD.match(item)
            if m:
                sev = _EXPERT_SEVERITY_ALIAS.get(m["sev"], m["sev"])
                lst = frames.setdefault((sev, m["msg"]), [])
                if len(lst) < max_frames and (not lst or lst[-1] != int(number)):
                    lst.append(int(number))

    table = Table(
        "expert",
        "Expert Information",
        [
            _col("severity", "Severity"),
            _col("summary", "Summary"),
            _col("group", "Group"),
            _col("protocol", "Protocol"),
            _col("count", "Count", True),
        ],
    )
    severity = None
    for line in _lines(summary_text):
        sec = _EXPERT_SECTION.match(line.strip())
        if sec:
            severity = _SEVERITY_NAME[sec["name"]]
            continue
        m = _EXPERT_ROW.match(line) if severity else None
        if not m or severity is None:
            continue
        summary = m["summary"]
        row: dict[str, Any] = {
            "cells": [severity, summary, m["group"], m["proto"], int(m["count"])]
        }
        hits = frames.get((severity, summary))
        if hits:
            row["frame"] = hits[0]
            row["frames"] = hits
        table.rows.append(row)
    table.rows.sort(key=lambda r: _SEVERITY_ORDER.get(r["cells"][0], 3))
    return table


# ---------------------------------------------------------------------- stats trees

# Taps printed by tshark's generic stats_tree code (a "Topic / Item" table).
TREE_TAPS = {
    "http": "http,tree",
    "http_requests": "http_req,tree",
    "http_load": "http_srv,tree",
    "dns": "dns,tree",
    "plen": "plen,tree",
}
TREE_TITLES = {
    "http": "HTTP Packet Counter",
    "http_requests": "HTTP Requests",
    "http_load": "HTTP Load Distribution",
    "dns": "DNS",
    "plen": "Packet Lengths",
}
_IPV4 = re.compile(r"\d{1,3}(\.\d{1,3}){3}")
_HEADER_CELL = re.compile(r"\S+(?: \S+)*")
# The first value column: the name column is padded to the longest topic, so a
# long first-column name may be followed by a single space.
_COUNT_HEADER = re.compile(r"\s(Count)(?:\s|$)")
_STATUS_CLASS = re.compile(r"^(?P<d>[1-5])xx: ")
_STATUS_CODE = re.compile(r"^(?P<code>[1-5]\d\d) ")
_METHOD = re.compile(r"^[A-Z][A-Z-]*$")
_BUCKET = re.compile(r"^(?P<lo>\d+)-(?P<hi>\d+)$")
_BUCKET_UP = re.compile(r"^(?P<lo>\d+) and greater$")
# Labels tshark's DNS tree uses (packet-dns.c value strings) -> field values.
_DNS_RCODES = {
    "No error": 0,
    "Format error": 1,
    "Server failure": 2,
    "No such name": 3,
    "Not implemented": 4,
    "Refused": 5,
}
_DNS_TYPES = {
    "A": 1, "NS": 2, "CNAME": 5, "SOA": 6, "PTR": 12, "HINFO": 13, "MX": 15, "TXT": 16,
    "AAAA": 28, "SRV": 33, "NAPTR": 35, "OPT": 41, "DS": 43, "RRSIG": 46, "NSEC": 47,
    "DNSKEY": 48, "SVCB": 64, "HTTPS": 65, "ANY": 255, "CAA": 257,
}  # fmt: skip
_DNS_CLASSES = {"IN": 1, "CH": 3, "HS": 4}


def _tree_value(text: str) -> int | float | None:
    """A stats_tree cell: ``'8'``, ``'30.00'``, ``'87.50%'``; ``'-'`` or blank = none."""
    text = text.strip().removesuffix("%")
    if not text or text == "-":
        return None
    try:
        f = float(text)
    except ValueError:
        return None
    return int(f) if f == int(f) and "." not in text else f


def _address_filter(addr: str) -> str | None:
    if _IPV4.fullmatch(addr):
        return f"ip.addr == {addr}"
    if addr.count(":") > 1 and re.fullmatch(r"[0-9A-Fa-f:.]+", addr):
        return f"ipv6.addr == {addr}"
    return None


def _http_filter(path: list[str]) -> str | None:
    topic = path[-1]
    if len(path) == 1:
        return "http"
    if len(path) == 2:
        return {
            "HTTP Response Packets": "http.response",
            "HTTP Request Packets": "http.request",
        }.get(topic)
    if path[1] == "HTTP Response Packets":
        if m := _STATUS_CLASS.match(topic):
            d = int(m["d"])
            return f"http.response.code >= {d}00 && http.response.code <= {d}99"
        if m := _STATUS_CODE.match(topic):
            return f"http.response.code == {m['code']}"
    if path[1] == "HTTP Request Packets" and _METHOD.fullmatch(topic):
        return f"http.request.method == {dfilter_string(topic)}"
    return None


def _http_requests_filter(path: list[str]) -> str | None:
    if len(path) == 1:
        return "http.request"
    host = f"http.host == {dfilter_string(path[1])}"
    if len(path) == 2:
        return host
    return f"{host} && http.request.uri == {dfilter_string(path[2])}"


def _http_load_filter(path: list[str]) -> str | None:
    """Rows nest addresses and hosts (either way round) under requests, and
    OK/Error under the responses of each server address (tshark counts codes
    of 400 and above as errors); a row filters on everything above it."""
    requests = path[0] == "HTTP Requests by Server"
    terms = ["http.request" if requests else "http.response"]
    for topic in path[1:]:
        if topic.startswith("HTTP Requests by "):
            continue  # a grouping node
        if addr := _address_filter(topic):
            terms.append(addr)
        elif requests:
            terms.append(f"http.host == {dfilter_string(topic)}")
        elif topic in ("OK", "Error"):
            terms.append(f"http.response.code {'<' if topic == 'OK' else '>='} 400")
        else:
            return None
    return " && ".join(terms)


def _dns_filter(path: list[str]) -> str | None:
    if len(path) == 1:
        return "dns" if path[0] == "Total Packets" else None
    if len(path) == 2:
        return None
    parent, topic = path[1], path[2]
    if parent == "rcode" and topic in _DNS_RCODES:
        return f"dns.flags.rcode == {_DNS_RCODES[topic]}"
    if parent == "opcodes" and topic == "Standard query":
        return "dns.flags.opcode == 0"
    if parent == "Query/Response" and topic in ("Query", "Response"):
        return f"dns.flags.response == {int(topic == 'Response')}"
    if parent == "Query Type" and topic in _DNS_TYPES:
        return f"dns.qry.type == {_DNS_TYPES[topic]}"
    if parent == "Class" and topic in _DNS_CLASSES:
        return f"dns.qry.class == {_DNS_CLASSES[topic]}"
    return None


def _plen_filter(path: list[str]) -> str | None:
    topic = path[-1]
    if m := _BUCKET.match(topic):
        return f"frame.len >= {m['lo']} && frame.len <= {m['hi']}"
    if m := _BUCKET_UP.match(topic):
        return f"frame.len >= {m['lo']}"
    return None


_TREE_FILTERS: dict[str, Callable[[list[str]], str | None]] = {
    "http": _http_filter,
    "http_requests": _http_requests_filter,
    "http_load": _http_load_filter,
    "dns": _dns_filter,
    "plen": _plen_filter,
}


def parse_stats_tree(text: str, kind: str) -> Table:
    """tshark's generic stats_tree report (``-z http,tree``, ``dns,tree``, ``plen,tree``…).

    Fixed-width columns under a header line, the line above the first rule of
    dashes (its first column is "Topic / Item", or since tshark 4.4 a name the
    tree sets: "Packet Type" for HTTP and DNS, "Request Type"…); one space of
    indentation per tree level. The header's column positions cut each row
    (topics may hold spaces, and empty cells are blank): the first value column
    starts at "Count", the others are at least two spaces apart. Columns that
    are empty in every row (Average/Min/Max of plain counters) are dropped.
    Rows whose topic maps onto a display filter (a status code, a host, a
    length bucket…) carry it.
    """
    lines = _lines(text)
    rule = next((i for i, line in enumerate(lines) if line and set(line) == {"-"}), None)
    table = Table(kind, TREE_TITLES.get(kind, kind), [])
    count = _COUNT_HEADER.search(lines[rule - 1]) if rule else None
    if rule is None or count is None:
        return table
    header = rule - 1
    head = lines[header]
    # A first-column name longer than every topic isn't cut: it pushes the
    # header's value columns right. The rule is as long as a row (topics padded
    # to the longest), so what the header has beyond it is that shift.
    shift = max(0, len(head.rstrip("\n")) - len(lines[rule]))
    spans = [(0, head[: count.start(1)].strip())]
    spans += [
        (count.start(1) + m.start() - shift, m.group())
        for m in _HEADER_CELL.finditer(head[count.start(1) :])
    ]
    starts = [start for start, _ in spans]
    labels = [label for _, label in spans]
    to_filter = _TREE_FILTERS.get(kind)
    path: list[str] = []
    parsed: list[tuple[int, list[Any], str | None]] = []
    for line in lines[header + 1 :]:
        if not line.strip() or set(line.strip()) <= {"-", "="}:
            continue
        name_part = line[: starts[1]] if len(starts) > 1 else line
        topic = name_part.strip()
        depth = len(name_part) - len(name_part.lstrip(" "))
        del path[depth:]
        path.append(topic)
        cells: list[Any] = [topic]
        for i in range(1, len(starts)):
            end = starts[i + 1] if i + 1 < len(starts) else len(line)
            cells.append(_tree_value(line[starts[i] : end]))
        parsed.append((depth, cells, to_filter(list(path)) if to_filter else None))
    keep = [0] + [i for i in range(1, len(labels)) if any(p[1][i] is not None for p in parsed)]
    table.columns = [
        _col(re.sub(r"\W+", "_", labels[i].lower()).strip("_"), labels[i], i > 0) for i in keep
    ]
    for depth, cells, flt in parsed:
        row: dict[str, Any] = {"cells": [cells[i] for i in keep], "depth": depth}
        if flt:
            row["filter"] = flt
        table.rows.append(row)
    return table


# ---------------------------------------------------------------------- service response time

# Protocols with a generic ``-z <proto>,srt`` table that needs no arguments,
# plus ICMP/ICMPv6 (their own report). DCE-RPC and ONC-RPC need a program or
# interface, SCSI a command set: not offered.
SRT_PROTOCOLS = {
    "icmp": "ICMP",
    "icmpv6": "ICMPv6",
    "smb": "SMB",
    "smb2": "SMB2",
    "ldap": "LDAP",
    "snmp": "SNMP",
    "diameter": "Diameter",
    "gtp": "GTP",
    "gtpv2": "GTPv2",
    "ncp": "NCP",
    "afp": "AFP",
    "camel": "CAMEL",
    "fc": "Fibre Channel",
}
# Protocol hierarchy names that mean a protocol has traffic to report on.
SRT_PHS_NAMES = {"fc": ("fc", "fcp", "fcels"), "gtpv2": ("gtpv2",), "gtp": ("gtp", "gtpprime")}

_SRT_HEADER = re.compile(r"^Index\s+(?P<proc>.+?)\s+Calls\s+Min SRT")
_SRT_ROW = re.compile(
    r"^\s*(?P<index>\d+)\s+(?P<name>.+?)\s+(?P<calls>\d+)\s+(?P<min>[\d.]+)\s+"
    r"(?P<max>[\d.]+)\s+(?P<avg>[\d.]+)\s+(?P<sum>[\d.]+)\s*$"
)
_ICMP_COUNTS = re.compile(r"^(?P<req>\d+)\s+(?P<rep>\d+)\s+(?P<lost>\d+)\s+(?P<loss>[\d.]+)%\s*$")
_ICMP_TIMES = re.compile(
    r"^(?P<min>[\d.]+)\s+(?P<max>[\d.]+)\s+(?P<mean>[\d.]+)\s+(?P<median>[\d.]+)\s+"
    r"(?P<sd>[\d.]+)\s+(?P<minf>\d+)?\s*(?P<maxf>\d+)?\s*$"
)
_FILTER_FIELD = re.compile(r"^[a-z][a-z0-9_.]*$")


def parse_srt(text: str, protocol: str) -> Table:
    """``tshark -z <proto>,srt``: one or more tables of procedures.

    Each row is ``Index  Procedure  Calls  Min SRT  Max SRT  Avg SRT  Sum SRT``
    (seconds). With one table, the report's ``Filter:`` line names the field
    the index is a value of (``snmp.data``, ``smb2.cmd``…), so rows filter on
    it. With several (SMB: commands, Transaction2, NT Transaction), a Table
    column names each row's table and rows get no filter.
    """
    label = SRT_PROTOCOLS.get(protocol, protocol)
    cols = [
        _col("procedure", "Procedure"),
        _col("index", "Index", True),
        _col("calls", "Calls", True),
        _col("min", "Min SRT (s)", True),
        _col("max", "Max SRT (s)", True),
        _col("avg", "Avg SRT (s)", True),
        _col("sum", "Sum SRT (s)", True),
    ]
    field_name = ""
    tables: list[tuple[str, list[list[Any]]]] = []
    previous = ""
    for line in _lines(text):
        stripped = line.strip()
        if stripped.startswith("Filter:"):
            field_name = stripped.removeprefix("Filter:").strip()
        elif m := _SRT_HEADER.match(stripped):
            name = previous if previous and not previous.startswith(("Filter:", "=")) else ""
            tables.append((name or m["proc"], []))
        elif (m := _SRT_ROW.match(line)) and tables:
            tables[-1][1].append(
                [
                    m["name"],
                    int(m["index"]),
                    int(m["calls"]),
                    _number(m["min"]),
                    _number(m["max"]),
                    _number(m["avg"]),
                    _number(m["sum"]),
                ]
            )
        if stripped:
            previous = stripped
    several = len(tables) > 1
    table = Table(
        "srt",
        f"{label} Service Response Time",
        ([_col("table", "Table")] if several else []) + cols,
    )
    table.extra["protocol"] = protocol
    for name, rows in tables:
        for cells in rows:
            row: dict[str, Any] = {"cells": ([name] if several else []) + cells}
            if not several and _FILTER_FIELD.fullmatch(field_name):
                row["filter"] = f"{field_name} == {cells[1]}"
            table.rows.append(row)
    return table


def parse_icmp_srt(text: str, protocol: str) -> Table:
    """``tshark -z icmp,srt`` / ``icmpv6,srt``: counts and times (ms) of echo
    requests and replies, one row; it goes to the slowest reply's frame."""
    label = SRT_PROTOCOLS.get(protocol, protocol)
    table = Table(
        "srt",
        f"{label} Service Response Time",
        [
            _col("requests", "Requests", True),
            _col("replies", "Replies", True),
            _col("lost", "Lost", True),
            _col("loss", "% Loss", True),
            _col("min", "Min (ms)", True),
            _col("max", "Max (ms)", True),
            _col("mean", "Mean (ms)", True),
            _col("median", "Median (ms)", True),
            _col("sd", "Std Dev (ms)", True),
            _col("min_frame", "Min Frame", True),
            _col("max_frame", "Max Frame", True),
        ],
        extra={"protocol": protocol},
    )
    counts: list[Any] | None = None
    times: list[Any] = [None] * 7
    for line in _lines(text):
        stripped = line.strip()
        if m := _ICMP_COUNTS.match(stripped):
            counts = [int(m["req"]), int(m["rep"]), int(m["lost"]), _number(m["loss"])]
        elif counts is not None and (m := _ICMP_TIMES.match(stripped)):
            times = [
                _number(m["min"]),
                _number(m["max"]),
                _number(m["mean"]),
                _number(m["median"]),
                _number(m["sd"]),
                int(m["minf"]) if m["minf"] else None,
                int(m["maxf"]) if m["maxf"] else None,
            ]
    if counts is not None:
        row: dict[str, Any] = {"cells": counts + times}
        if times[6]:
            row["frame"] = times[6]
        row["filter"] = (
            "icmp.type == 8 || icmp.type == 0"
            if protocol == "icmp"
            else ("icmpv6.type == 128 || icmpv6.type == 129")
        )
        table.rows.append(row)
    return table


# ---------------------------------------------------------------------- capinfos


def parse_capinfos_properties(text: str) -> Table:
    """Plain ``capinfos <file>`` output: ``Key:  value`` lines, indented continuations."""
    table = Table(
        "properties", "Capture File Properties", [_col("key", "Property"), _col("value", "Value")]
    )
    for line in _lines(text):
        if not line.strip():
            continue
        if line.startswith((" ", "\t")) and table.rows:
            # Continuation (e.g. per-interface details): its own indented row.
            key, sep, value = line.strip().partition(" = ")
            table.rows.append(
                {"cells": [key if sep else "", value if sep else line.strip()], "depth": 1}
            )
            continue
        key, sep, value = line.partition(":")
        if sep:
            table.rows.append({"cells": [key.strip(), value.strip()]})
    return table


# ---------------------------------------------------------------------- follow

FOLLOW_PROTOCOLS = ("tcp", "udp", "tls", "http")
_NODE = re.compile(r"^Node (?P<n>[01]): (?P<addr>.*)$")


def parse_follow_raw(text: str) -> dict[str, Any]:
    """``tshark -q -z follow,<proto>,raw,<stream>``.

    Each data line is hex; lines starting with a tab come from node 1 (the
    server side), others from node 0 (the side that sent the first packet).
    """
    nodes: list[str] = ["", ""]
    segments: list[dict[str, Any]] = []
    filt = ""
    in_body = False
    totals = [0, 0]
    for raw in _lines(text):
        if raw.startswith("====="):
            if in_body:
                break
            continue
        if raw.startswith("Follow:"):
            continue
        if raw.startswith("Filter:"):
            filt = raw.partition(":")[2].strip()
            continue
        node = _NODE.match(raw)
        if node:
            nodes[int(node["n"])] = node["addr"].strip()
            in_body = True
            continue
        if not in_body or not raw.strip():
            continue
        direction = 1 if raw.startswith("\t") else 0
        data = raw.strip()
        if not re.fullmatch(r"[0-9a-fA-F]*", data) or len(data) % 2:
            continue
        totals[direction] += len(data) // 2
        if segments and segments[-1]["dir"] == direction:
            segments[-1]["hex"] += data  # merge consecutive chunks in one direction
        else:
            segments.append({"dir": direction, "hex": data})
    return {"filter": filt, "nodes": nodes, "segments": segments, "bytes": totals}
