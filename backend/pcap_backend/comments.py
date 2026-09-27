"""Packet comments: read from pcapng blocks, written with ``editcap``.

tshark's field output can't carry a multi-line comment unambiguously (each
line becomes an occurrence of ``frame.comment``, then the whole text again),
so comments are read straight from the file: the ``opt_comment`` options of
pcapng packet blocks (Enhanced and obsolete Packet Blocks; Simple Packet
Blocks carry no options). Plain pcapng is read as is, gzip and zstd
compressed pcapng through the standard library; anything else (pcap and the
other formats have no packet comments) has none.

``editcap -a <frame>:<comment>`` sets one comment per packet (a second ``-a``
for the same frame replaces the first), and there is no per-packet delete:
``--discard-packet-comments`` drops them all except those added by ``-a``
in the same run. :func:`editcap_args` picks between the two.
"""

import gzip
import io
import struct
from collections.abc import Iterator, Mapping
from pathlib import Path

_SHB = 0x0A0D0D0A
_EPB, _SPB, _OBSOLETE_PB = 6, 3, 2
_BYTE_ORDER_MAGIC = 0x1A2B3C4D
_OPT_END, _OPT_COMMENT = 0, 1
_GZIP_MAGIC = b"\x1f\x8b"
_ZSTD_MAGIC = b"\x28\xb5\x2f\xfd"
_PCAPNG_MAGIC = b"\x0a\x0d\x0d\x0a"
_LZ4_MAGIC = b"\x04\x22\x4d\x18"


class UnreadableError(Exception):
    """The comments of this file can't be read (e.g. an LZ4-compressed pcapng)."""


def _open(path: Path) -> io.BufferedIOBase | None:
    """The file's pcapng stream, None if it isn't pcapng; UnreadableError if it
    might be but can't be decompressed here."""
    with path.open("rb") as fh:
        head = fh.read(4)
    if head == _PCAPNG_MAGIC:
        return path.open("rb")
    if head[:2] == _GZIP_MAGIC:
        stream: io.BufferedIOBase = gzip.open(path, "rb")  # noqa: SIM115 - returned open
    elif head == _ZSTD_MAGIC:
        try:
            from compression import zstd  # noqa: PLC0415 - Pythons built without libzstd lack it
        except ImportError as exc:
            raise UnreadableError("this Python can't read zstd files") from exc
        stream = zstd.open(path, "rb")
    elif head == _LZ4_MAGIC:
        raise UnreadableError("comments of LZ4-compressed files can't be read")
    else:
        return None
    if stream.read(4) != _PCAPNG_MAGIC:
        stream.close()
        return None
    stream.seek(0)
    return stream


def is_pcapng(path: Path) -> bool:
    """Uncompressed pcapng: the only kind a comment edit can be saved into in place."""
    try:
        with path.open("rb") as fh:
            return fh.read(4) == _PCAPNG_MAGIC
    except OSError:
        return False


def _options(data: bytes, endian: str) -> Iterator[tuple[int, bytes]]:
    pos = 0
    while pos + 4 <= len(data):
        code, length = struct.unpack_from(endian + "HH", data, pos)
        if code == _OPT_END:
            return
        value = data[pos + 4 : pos + 4 + length]
        yield code, value
        pos += 4 + length + (-length % 4)


def _packet_blocks(path: Path) -> Iterator[tuple[int, bytes, str]]:
    """(block type, body, byte order) of every packet block (EPB, SPB and
    obsolete PB) of a pcapng file, in order; nothing if it isn't pcapng. A
    truncated last block ends it."""
    stream = _open(path)
    if stream is None:
        return
    endian = "<"
    with stream:
        while True:
            header = stream.read(8)
            if len(header) < 8:
                break
            (block_type,) = struct.unpack("<I", header[:4])
            if block_type == _SHB:
                magic = stream.read(4)
                endian = "<" if struct.unpack("<I", magic)[0] == _BYTE_ORDER_MAGIC else ">"
                (total,) = struct.unpack(endian + "I", header[4:])
                body = magic + stream.read(total - 12)
            else:
                block_type, total = struct.unpack(endian + "II", header)
                body = stream.read(total - 8)
            if total < 12 or len(body) < total - 8:
                break  # truncated: keep what was read
            if block_type in (_EPB, _OBSOLETE_PB, _SPB):
                yield block_type, body[:-4], endian  # (without the trailing length)


def read_comments(path: Path) -> dict[int, list[str]]:
    """Comments by frame number (1-based, counting every packet block)."""
    comments: dict[int, list[str]] = {}
    for frame, (block_type, body, endian) in enumerate(_packet_blocks(path), start=1):
        if block_type == _SPB:
            continue  # (no options)
        captured = struct.unpack_from(endian + "I", body, 12)[0]
        start = 20 + captured + (-captured % 4)
        texts = [
            value.decode("utf-8", "replace")
            for code, value in _options(body[start:], endian)
            if code == _OPT_COMMENT
        ]
        if texts:
            comments[frame] = texts
    return comments


def packet_count(path: Path) -> int:
    """The number of packets of a pcapng file (0 if it isn't pcapng)."""
    return sum(1 for _ in _packet_blocks(path))


def editcap_args(
    saved: Mapping[int, list[str]], edits: Mapping[int, str | None]
) -> tuple[list[str], dict[int, str]]:
    """editcap options that apply ``edits`` (frame → new comment; None or ""
    deletes) to a file whose comments are ``saved``, and the comments the
    result will hold. Only edited frames are named, unless one loses its
    comment (no per-packet delete) or had several (``-a`` replaces just one):
    then all comments are discarded and every remaining one re-added, a
    packet's several comments joined into one."""
    result = {n: "\n".join(texts) for n, texts in saved.items()}
    for n, text in edits.items():
        if text:
            result[n] = text
        else:
            result.pop(n, None)
    rewrite = any(not text for text in edits.values()) or any(
        len(saved.get(n, [])) > 1 for n in edits
    )
    frames = sorted(result) if rewrite else sorted(n for n, t in edits.items() if t)
    args = ["--discard-packet-comments"] if rewrite else []
    for n in frames:
        args += ["-a", f"{n}:{result[n]}"]
    return args, result
