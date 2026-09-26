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
from dataclasses import dataclass, field
from typing import Any

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
