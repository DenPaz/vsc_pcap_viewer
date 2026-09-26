"""Turn tshark PDML and ``-x`` hex dumps into the JSON the webview renders.

A detail tree node looks like::

    {"id": 7, "label": "Source Address: 10.0.0.1", "name": "ip.src",
     "show": "10.0.0.1", "pos": 26, "size": 4, "src": 0, "children": [...]}

``pos``/``size`` index into the byte source ``src`` (0 = the frame itself,
higher indexes = reassembled/decompressed buffers, in the order tshark
prints them with ``-x``).
"""

import re
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from typing import Any

TreeNode = dict[str, Any]

# Top-level items that introduce a new byte source (reassembly info). Every
# item after one of these lives in the next data source.
_NEW_SOURCE_RE = re.compile(r"\.(segments|fragments)$")
_SKIP_PROTOS = frozenset({"geninfo"})


class PdmlError(ValueError):
    """tshark produced PDML we could not parse."""


def parse_pdml(data: bytes, source_count: int = 1) -> list[TreeNode]:
    """Parse the first ``<packet>`` of a PDML document into a list of tree nodes."""
    try:
        root = ET.fromstring(data)  # noqa: S314 - trusted producer, escaped content
    except ET.ParseError as exc:
        raise PdmlError(f"could not parse tshark PDML output: {exc}") from exc
    packet = root.find("packet")
    if packet is None:
        return []
    counter = _Counter()
    top: list[ET.Element] = []
    for proto in packet:
        if proto.tag != "proto" or proto.get("name") in _SKIP_PROTOS:
            continue
        if proto.get("name") == "fake-field-wrapper":
            # Wireshark shows these children (e.g. reassembly info) at top level.
            top.extend(child for child in proto if child.tag in ("field", "proto"))
        else:
            top.append(proto)
    nodes: list[TreeNode] = []
    src = 0
    for el in top:
        if _NEW_SOURCE_RE.search(el.get("name", "")) and src + 1 < source_count:
            src += 1
        node = _convert(el, src, counter)
        if node is not None:
            nodes.append(node)
    return nodes


class _Counter:
    def __init__(self) -> None:
        self.value = 0

    def next(self) -> int:
        self.value += 1
        return self.value


def _convert(el: ET.Element, src: int, counter: _Counter) -> TreeNode | None:
    if el.get("hide") == "yes":
        return None
    name = el.get("name", "")
    show = el.get("show")
    showname = el.get("showname")
    if showname:
        label = showname
    elif name and show:
        label = f"{name}: {show}"
    else:
        label = show or name or "(unnamed)"
    node: TreeNode = {"id": counter.next(), "label": label, "src": src}
    if name:
        node["name"] = name
    if show is not None:
        node["show"] = show
    value = el.get("value")
    if value:
        node["value"] = value
    size = _int(el.get("size"))
    pos = _int(el.get("pos"))
    if size and pos is not None:
        node["pos"] = pos
        node["size"] = size
    if el.tag == "proto":
        node["proto"] = True
    children = []
    for child in el:
        if child.tag not in ("field", "proto"):
            continue
        converted = _convert(child, src, counter)
        if converted is not None:
            children.append(converted)
    if children:
        node["children"] = children
    return node


def _int(v: str | None) -> int | None:
    if v is None:
        return None
    try:
        return int(v)
    except ValueError:
        return None


@dataclass(slots=True)
class ByteSource:
    name: str
    data: bytearray

    def to_json(self) -> dict[str, Any]:
        return {"name": self.name, "hex": self.data.hex()}


# Name of the first byte source (the packet's own bytes) whatever tshark calls it:
# "Frame" up to 4.4, "Packet" from 4.6. Single-source packets print no header.
FRAME_SOURCE = "Frame"
_HEADER_RE = re.compile(r"^(?P<name>.+) \((?P<len>\d+) bytes?\):$")
_ROW_RE = re.compile(r"^(?P<off>[0-9a-fA-F]{4,})  (?P<rest>.*)$")
_BYTE_RE = re.compile(r"[0-9a-fA-F]{2}")


def parse_hexdump(text: str) -> list[ByteSource]:
    """Parse ``tshark -x`` output into byte sources.

    Single-source packets have no header line; multi-source packets print
    ``Frame (N bytes):`` (``Packet (N bytes):`` in tshark 4.6) /
    ``Reassembled TCP (N bytes):`` headers. The first source is always named
    FRAME_SOURCE, so the UI reads the same across tshark versions and for
    single- and multi-source packets.
    """
    sources: list[ByteSource] = []
    current: ByteSource | None = None
    for line in text.splitlines():
        if not line.strip():
            continue
        header = _HEADER_RE.match(line)
        if header:
            current = ByteSource(header["name"] if sources else FRAME_SOURCE, bytearray())
            sources.append(current)
            continue
        row = _ROW_RE.match(line)
        if not row:
            continue
        if current is None:
            current = ByteSource(FRAME_SOURCE, bytearray())
            sources.append(current)
        offset = int(row["off"], 16)
        # Hex area is 16 * "xx " = 48 chars; the ASCII column follows.
        tokens = _BYTE_RE.findall(row["rest"][:48])
        chunk = bytes.fromhex("".join(tokens))
        if offset != len(current.data):
            # Pad defensively if tshark ever skips rows.
            current.data.extend(b"\0" * max(0, offset - len(current.data)))
            del current.data[offset:]
        current.data.extend(chunk)
    return sources
