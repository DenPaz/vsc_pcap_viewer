"""Capture editing with editcap: the options of each operation (``edit_capture``).

Every operation reads the whole capture file (not the view) and writes pcapng:

* ``timeShift``: ``-t <offset>`` (seconds, may be negative);
* ``dedup``: ``-D <window>`` (packets) or ``-w <seconds>``; editcap reports on
  stderr how many it skipped;
* ``keep``: packets in frame ranges (``-r`` with ``1-100 250 300-``) and/or
  between two times (``-A``/``-B``, Unix epoch seconds);
* ``truncate``: ``-s <snaplen>`` (the packets keep their original length, so
  they show as "N bytes on wire, M bytes captured");
* ``injectSecrets``: ``--inject-secrets tls,<key log>`` (a pcapng Decryption
  Secrets Block, so the capture decrypts without the key log);
* ``split``: ``-c <packets>`` or ``-i <seconds>`` per file, named
  ``<name>_NNNNN_<time>.pcapng`` by editcap (what rotation.ts recognises).
"""

import re
from collections.abc import Mapping
from decimal import Decimal, InvalidOperation
from pathlib import Path
from typing import Any

from .protocol import InvalidParamsError

OPERATIONS = ("timeShift", "dedup", "keep", "truncate", "injectSecrets", "split")
MAX_DEDUP_WINDOW = 1_000_000  # editcap's own limit
MAX_RANGES = 10_000
_RANGE_RE = re.compile(r"^(\d+)(?:-(\d*))?$")
_SKIPPED_RE = re.compile(r"(\d+) packets seen, (\d+) packets skipped")


def _number(params: Mapping[str, Any], key: str) -> Decimal | None:
    """A decimal parameter given as a JSON number or a string (exact: no float noise)."""
    raw = params.get(key)
    if raw is None or raw == "":
        return None
    if isinstance(raw, bool) or not isinstance(raw, (int, float, str)):
        raise InvalidParamsError(f"{key} must be a number")
    try:
        value = Decimal(str(raw).strip())
    except InvalidOperation as exc:
        raise InvalidParamsError(f"{key} must be a number") from exc
    if not value.is_finite():
        raise InvalidParamsError(f"{key} must be a number")
    return value


def _seconds(value: Decimal) -> str:
    """Seconds as editcap takes them: plain decimal, at most 9 decimals."""
    text = format(value.quantize(Decimal("1e-9")).normalize(), "f")
    return "0" if text in ("-0", "") else text


def _whole(params: Mapping[str, Any], key: str, low: int, high: int) -> int | None:
    value = _number(params, key)
    if value is None:
        return None
    if value != value.to_integral_value() or not low <= value <= high:
        raise InvalidParamsError(f"{key} must be a whole number from {low:,} to {high:,}")
    return int(value)


def parse_ranges(text: str, frames: int) -> list[str]:
    """Frame ranges ("1-100, 250 300-") as editcap takes them, checked
    against the capture's ``frames``."""
    out: list[str] = []
    for item in re.split(r"[,\s]+", text.strip()):
        if not item:
            continue
        m = _RANGE_RE.match(item)
        if not m:
            raise InvalidParamsError(f"not a packet range: {item!r} (use e.g. 1-100, 250, 300-)")
        first = int(m.group(1))
        last = int(m.group(2)) if m.group(2) else None
        if first < 1 or first > frames or (last is not None and last < first):
            raise InvalidParamsError(f"packet range {item} is outside 1-{frames}")
        to_end = m.group(2) == "" or (last is not None and last > frames)  # ("300-")
        out.append(f"{first}-{frames}" if to_end else item)
    if not out:
        raise InvalidParamsError("give the packets to keep, e.g. 1-100, 250")
    if len(out) > MAX_RANGES:
        raise InvalidParamsError(f"at most {MAX_RANGES:,} packet ranges")
    return out


def editcap_options(
    operation: str, params: Mapping[str, Any], frames: int
) -> tuple[list[str], list[str]]:
    """(options before the file names, selections after them) for ``operation``."""
    if operation == "timeShift":
        offset = _number(params, "offset")
        if offset is None:
            raise InvalidParamsError("offset (seconds) is required")
        return ["-t", _seconds(offset)], []
    if operation == "dedup":
        seconds = _number(params, "seconds")
        if seconds is not None:
            if seconds <= 0:
                raise InvalidParamsError("seconds must be positive")
            return ["-w", _seconds(seconds)], []
        window = _whole(params, "window", 1, MAX_DEDUP_WINDOW)
        return ["-D", str(window or 5)], []
    if operation == "keep":
        options: list[str] = []
        start, end = _number(params, "from"), _number(params, "to")
        if start is not None:
            options += ["-A", _seconds(start)]
        if end is not None:
            options += ["-B", _seconds(end)]
        if start is not None and end is not None and end < start:
            raise InvalidParamsError("the end time is before the start time")
        ranges = str(params.get("frames") or "").strip()
        selections = parse_ranges(ranges, frames) if ranges else []
        if not options and not selections:
            raise InvalidParamsError("give packet ranges or a time range to keep")
        return (["-r", *options] if selections else options), selections
    if operation == "truncate":
        snaplen = _whole(params, "snaplen", 1, 262_144)
        if snaplen is None:
            raise InvalidParamsError("snaplen (bytes per packet) is required")
        return ["-s", str(snaplen)], []
    if operation == "injectSecrets":
        key_log = Path(str(params.get("keyLog") or "")).expanduser()
        if not key_log.is_absolute() or not key_log.is_file():
            raise InvalidParamsError(f"TLS key log file not found: {key_log}")
        return ["--inject-secrets", f"tls,{key_log}"], []
    if operation == "split":
        packets = _whole(params, "packets", 1, 1 << 31)
        seconds = _number(params, "seconds")
        if packets is not None:
            return ["-c", str(packets)], []
        if seconds is not None and seconds > 0:
            return ["-i", _seconds(seconds)], []
        raise InvalidParamsError("give the packets or seconds per file")
    raise InvalidParamsError(f"operation must be one of {', '.join(OPERATIONS)}")


def skipped_packets(stderr: str) -> int | None:
    """Duplicates editcap removed ("52 packets seen, 26 packets skipped …")."""
    m = _SKIPPED_RE.search(stderr)
    return int(m.group(2)) if m else None
