"""Import from Hex Dump with text2pcap: the options of ``import_hexdump``.

text2pcap reads hex dumps with an offset at the start of each line (``od -Ax
-tx1``, Wireshark's *Copy as Hex Dump*, ``hexdump -C`` with ``asciiDump``),
one packet per run of offsets starting at 0, and writes pcapng. Options:

* ``offsets``: ``hex`` (default), ``oct``, ``dec`` or ``none`` (``-o``);
* ``timestamp``: a strptime format (plus ``%f``) or ``ISO`` for a time before
  each packet (``-t``), ``direction`` for an I/O mark before it (``-D``),
  ``asciiDump`` to skip a trailing ASCII column that looks like hex (``-a``);
* ``linkType`` (``-l``, default 1 = Ethernet) for data that is already a whole
  frame, or ``header``: a dummy header text2pcap puts in front of each packet:
  ``ethernet`` (``-e`` ethertype), ``ip`` (``-i`` protocol), ``udp``/``tcp``
  (``-u``/``-T`` ports), ``sctp`` (``-s`` ports, tag), ``sctpData`` (``-S``
  ports, PPI) or ``exportPdu`` (``-P`` dissector name); IPv4/IPv6 addresses of
  the dummy IP header go in ``srcIp``/``dstIp`` (``-4``/``-6``);
* ``maxPacket`` (``-m``) and ``interfaceName`` (``-N``).
"""

import ipaddress
import re
from collections.abc import Mapping
from typing import Any

from .protocol import InvalidParamsError

OFFSETS = ("hex", "oct", "dec", "none")
HEADERS = ("none", "ethernet", "ip", "udp", "tcp", "sctp", "sctpData", "exportPdu")
MAX_PACKET = 262_144  # text2pcap's own default and maximum
MAX_TEXT = 64 * 1024 * 1024
_DISSECTOR_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.\-]*$")
_WROTE_RE = re.compile(r"Read (\d+) potential packets?, wrote (\d+) packets?")


def _int(params: Mapping[str, Any], key: str, low: int, high: int, default: int) -> int:
    raw = params.get(key, default)
    if raw is None or raw == "":
        return default
    if isinstance(raw, bool):
        raise InvalidParamsError(f"{key} must be a whole number")
    try:
        if isinstance(raw, str):
            raw = raw.strip()
            value = int(raw, 16) if raw.lower().startswith("0x") else int(raw)
        else:
            value = int(raw)
    except (TypeError, ValueError) as exc:
        raise InvalidParamsError(f"{key} must be a whole number") from exc
    if isinstance(raw, float) and raw != value:
        raise InvalidParamsError(f"{key} must be a whole number")
    if not low <= value <= high:
        raise InvalidParamsError(f"{key} must be from {low} to {high}")
    return value


def _text(params: Mapping[str, Any], key: str, limit: int = 200) -> str:
    raw = params.get(key, "")
    if raw is None:
        return ""
    if not isinstance(raw, str) or len(raw) > limit or any(ord(c) < 32 for c in raw):
        raise InvalidParamsError(f"{key} must be a single line of at most {limit} characters")
    return raw.strip()


def _addresses(params: Mapping[str, Any]) -> list[str]:
    """``-4 src,dst`` / ``-6 src,dst`` for the dummy IP header (both or neither)."""
    src, dst = _text(params, "srcIp", 64), _text(params, "dstIp", 64)
    if not src and not dst:
        return []
    try:
        a, b = ipaddress.ip_address(src), ipaddress.ip_address(dst)
    except ValueError as exc:
        raise InvalidParamsError("srcIp and dstIp must both be IP addresses") from exc
    if a.version != b.version:
        raise InvalidParamsError("srcIp and dstIp must both be IPv4 or both IPv6")
    return [f"-{a.version}", f"{a},{b}"]


def _ports(params: Mapping[str, Any]) -> str:
    return f"{_int(params, 'srcPort', 0, 65535, 0)},{_int(params, 'dstPort', 0, 65535, 0)}"


def text2pcap_options(params: Mapping[str, Any]) -> list[str]:
    """text2pcap's options (before the file names) for ``params``; checks them all."""
    offsets = params.get("offsets", "hex") or "hex"
    if offsets not in OFFSETS:
        raise InvalidParamsError(f"offsets must be one of {', '.join(OFFSETS)}")
    options = ["-o", str(offsets)]
    if timestamp := _text(params, "timestamp"):
        options += ["-t", timestamp]
    if params.get("direction"):
        options.append("-D")
    if params.get("asciiDump"):
        options.append("-a")
    header = params.get("header", "none") or "none"
    if header not in HEADERS:
        raise InvalidParamsError(f"header must be one of {', '.join(HEADERS)}")
    if header == "none":
        options += ["-l", str(_int(params, "linkType", 0, 65535, 1))]
    elif "linkType" in params and params["linkType"] not in (None, "", 1):
        raise InvalidParamsError("a dummy header needs the Ethernet link type (1)")
    match header:
        case "ethernet":
            options += ["-e", hex(_int(params, "ethertype", 0, 0xFFFF, 0x0800))]
        case "ip":
            options += ["-i", str(_int(params, "protocol", 0, 255, 17))]
        case "udp":
            options += ["-u", _ports(params)]
        case "tcp":
            options += ["-T", _ports(params)]
        case "sctp":
            options += ["-s", f"{_ports(params)},{_int(params, 'tag', 0, 2**32 - 1, 0)}"]
        case "sctpData":
            options += ["-S", f"{_ports(params)},{_int(params, 'ppi', 0, 2**32 - 1, 0)}"]
        case "exportPdu":
            name = _text(params, "dissector", 64)
            if not _DISSECTOR_RE.fullmatch(name):
                raise InvalidParamsError("dissector must be a dissector name, e.g. sip or http")
            options += ["-P", name]
    if header in ("ip", "udp", "tcp", "sctp", "sctpData"):
        options += _addresses(params)
    elif params.get("srcIp") or params.get("dstIp"):
        raise InvalidParamsError("srcIp/dstIp need a dummy IP, UDP, TCP or SCTP header")
    options += ["-m", str(_int(params, "maxPacket", 1, MAX_PACKET, MAX_PACKET))]
    if name := _text(params, "interfaceName", 64):
        options += ["-N", name]
    return options


def written_packets(stderr: str) -> tuple[int, int] | None:
    """(packets read, packets written) from text2pcap's summary line."""
    m = _WROTE_RE.search(stderr)
    return (int(m.group(1)), int(m.group(2))) if m else None
