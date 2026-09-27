"""Pure helpers for Find Packet, marked-packet export and time display formats."""

import re
from collections.abc import Iterable
from datetime import UTC, datetime

FIND_MODES = ("filter", "string", "hex", "marked")
TIME_FORMATS = ("relative", "delta_displayed", "delta_captured", "absolute", "utc", "epoch")
NS = 1_000_000_000

_HEX_TOKEN = re.compile(r"[\s:.,\-]+")
_HEX = re.compile(r"[0-9a-f]+")
HEX_HELP = "Hex bytes are pairs of hex digits, e.g. 47 45 54, 47:45:54 or 474554"


def parse_hex_bytes(text: str) -> list[str]:
    """``"aabbcc"``, ``"aa bb cc"``, ``"aa:bb"``, ``"0xaa 0xbb"`` → ``["aa", "bb", ...]``."""
    tokens = [t.lower() for t in _HEX_TOKEN.split(text.strip()) if t]
    out: list[str] = []
    for token in tokens:
        t = token.removeprefix("0x")
        if len(tokens) > 1 and len(t) == 1:
            t = "0" + t  # "a b" → 0a 0b
        if not t or len(t) % 2 or not _HEX.fullmatch(t):
            raise ValueError(HEX_HELP)
        out += [t[i : i + 2] for i in range(0, len(t), 2)]
    if not out:
        raise ValueError(HEX_HELP)
    return out


def dfilter_string(value: str) -> str:
    """A display-filter string literal (backslashes and quotes escaped)."""
    return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'


def find_expression(mode: str, value: str, case_sensitive: bool) -> str:
    """The display filter Find Packet runs for a search.

    ``string``: ``frame contains "..."``, or case-insensitively ``frame matches
    "(?i)..."`` with the text regex-escaped. ``hex``: ``frame contains aa:bb:cc``.
    """
    if mode == "filter":
        expr = value.strip()
        if not expr:
            raise ValueError("Enter a display filter to find")
        return expr
    if mode == "string":
        if not value.strip():
            raise ValueError("Enter text to find")
        if "\n" in value or "\r" in value:
            raise ValueError("The search text must be a single line")
        if case_sensitive:
            return f"frame contains {dfilter_string(value)}"
        return f"frame matches {dfilter_string('(?i)' + re.escape(value))}"
    if mode == "hex":
        octets = parse_hex_bytes(value)
        if len(octets) == 1:  # a lone "aa" could parse as a field name
            return f'frame contains "\\x{octets[0]}"'
        return "frame contains " + ":".join(octets)
    raise ValueError(f"unknown find mode {mode!r}")


def frame_ranges(frames: Iterable[int]) -> list[str]:
    """Sorted, de-duplicated frame numbers as set members: ``1..3``, ``7``."""
    out: list[str] = []
    ordered = sorted(set(frames))
    i = 0
    while i < len(ordered):
        j = i
        while j + 1 < len(ordered) and ordered[j + 1] == ordered[j] + 1:
            j += 1
        out.append(str(ordered[i]) if i == j else f"{ordered[i]}..{ordered[j]}")
        i = j + 1
    return out


def frame_set_filters(frames: Iterable[int], max_length: int) -> list[str]:
    """``frame.number in {...}`` filters covering ``frames``, each at most
    ``max_length`` characters (so each fits in one argv entry), in frame order."""
    head, tail = "frame.number in {", "}"
    filters: list[str] = []
    chunk: list[str] = []
    size = len(head) + len(tail)
    for member in frame_ranges(frames):
        extra = len(member) + (1 if chunk else 0)
        if chunk and size + extra > max_length:
            filters.append(head + ",".join(chunk) + tail)
            chunk, size, extra = [], len(head) + len(tail), len(member)
        chunk.append(member)
        size += extra
    if chunk:
        filters.append(head + ",".join(chunk) + tail)
    return filters


def parse_ns(text: str) -> int | None:
    """``"1700000000.123456789"`` → nanoseconds (exact; no float rounding)."""
    s = text.strip().split(",")[0]
    if not s:
        return None
    sign = -1 if s.startswith("-") else 1
    whole, _, frac = s.lstrip("+-").partition(".")
    if not whole.isdigit() or (frac and not frac.isdigit()):
        return None
    return sign * (int(whole) * NS + int((frac + "000000000")[:9]))


def format_seconds(ns: int) -> str:
    """Seconds with microsecond precision, like Wireshark's default: ``-0.000123``."""
    sec, rem = divmod(abs(ns), NS)
    return f"{'-' if ns < 0 else ''}{sec}.{rem // 1000:06d}"


def format_absolute(epoch_ns: int, utc: bool) -> str:
    """``2023-11-14 22:13:20.000000`` in local time (the machine running VS Code) or UTC."""
    sec, rem = divmod(epoch_ns, NS)
    dt = datetime.fromtimestamp(sec, UTC)
    if not utc:
        dt = dt.astimezone()  # the local time zone
    return dt.strftime("%Y-%m-%d %H:%M:%S") + f".{rem // 1000:06d}"
