"""Recognising files of BER-encoded records (ASN.1), for probe_file.

tshark reads a file that is exactly one BER value (its "BER" file type), but
rejects several values back to back, which is how many record files (call
detail records, for example) are written. ``count_records`` walks the
tag-length headers without reading the values, so probe_file can say why such
a file isn't readable instead of only "not a capture file".
"""

from pathlib import Path
from typing import BinaryIO

# Records counted at most (enough to recognise the layout).
MAX_RECORDS = 100_000
# Record files are often padded to a block size with 0x00 or 0xFF bytes.
_PADDING = frozenset(b"\x00\xff")


def _header(fh: BinaryIO) -> int | None:
    """Read one tag-length header; the value's length, or None if it isn't one
    (a truncated header, an indefinite length, or more than 8 length bytes)."""
    tag = fh.read(1)
    if not tag:
        return None
    if tag[0] & 0x1F == 0x1F:  # high tag number: base-128 bytes, the last below 0x80
        for _ in range(5):
            more = fh.read(1)
            if not more:
                return None
            if not more[0] & 0x80:
                break
        else:
            return None
    first = fh.read(1)
    if not first or first[0] == 0x80:  # (indefinite lengths need parsing the value)
        return None
    if first[0] < 0x80:
        return first[0]
    count = first[0] & 0x7F
    raw = fh.read(count)
    if count > 8 or len(raw) != count:
        return None
    return int.from_bytes(raw, "big")


def _only_padding(fh: BinaryIO) -> bool:
    while chunk := fh.read(1 << 16):
        if not set(chunk) <= _PADDING:
            return False
    return True


def count_records(path: Path) -> int | None:
    """How many BER values ``path`` holds back to back, when that is all it
    holds (trailing 0x00/0xFF padding allowed); None if it isn't laid out so.
    Stops counting at MAX_RECORDS."""
    size = path.stat().st_size
    count = 0
    with path.open("rb") as fh:
        while fh.tell() < size and count < MAX_RECORDS:
            start = fh.tell()
            if count and fh.read(1) in (b"\x00", b"\xff"):
                fh.seek(start)
                return count if _only_padding(fh) else None
            fh.seek(start)
            length = _header(fh)
            if length is None or fh.tell() + length > size:
                return None
            fh.seek(length, 1)
            count += 1
    return count or None
