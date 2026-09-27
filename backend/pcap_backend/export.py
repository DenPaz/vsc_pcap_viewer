"""Helpers for the ``export`` method: destination checks, atomic output files,
the packet-list writers (CSV / JSON) and the writer that joins tshark's
dissection output (text / PDML / JSON) from several passes into one file.

Packet data is untrusted. CSV cells that a spreadsheet would evaluate as a
formula (``=``, ``+``, ``@``, ``-`` followed by a non-number, tab, CR) are
prefixed with ``'`` so opening an export cannot run anything.
"""

import csv
import json
import os
import re
from collections.abc import Iterable, Iterator, Sequence
from contextlib import contextmanager
from pathlib import Path
from typing import IO, BinaryIO

from .protocol import InvalidParamsError

CAPTURE_FORMATS = ("pcapng", "pcap")
LIST_FORMATS = ("csv", "json")
EXPORT_KINDS = (*CAPTURE_FORMATS, *LIST_FORMATS, "bytes", "dissections")
# Full dissections, as Wireshark's "Export Packet Dissections": tshark's options.
DISSECTION_FORMATS: dict[str, list[str]] = {
    "text": ["-V"],
    "pdml": ["-T", "pdml"],
    "json": ["-T", "json"],
}

_NUMBER_RE = re.compile(r"^-?\d+(\.\d+)?$")
_FORMULA_START = ("=", "+", "@", "\t", "\r")


def check_destination(dest: str, capture: Path) -> Path:
    """Validate an export destination: absolute, in an existing folder, and
    never the open capture file itself (tshark would truncate its own input)."""
    path = Path(dest).expanduser()
    if not path.is_absolute():
        raise InvalidParamsError("dest must be an absolute path")
    if path.is_dir():
        raise InvalidParamsError(f"dest is a folder: {path}")
    if not path.parent.is_dir():
        raise InvalidParamsError(f"folder does not exist: {path.parent}")
    same = path.resolve() == capture.resolve()
    if not same and path.exists():
        try:
            same = path.samefile(capture)
        except OSError:
            same = False
    if same:
        raise InvalidParamsError("cannot export over the open capture file")
    return path


@contextmanager
def atomic_output(dest: Path) -> Iterator[Path]:
    """Yield a temporary path next to ``dest``; it replaces ``dest`` only if the
    block finishes, so a cancelled or failed export never leaves a partial file."""
    tmp = dest.with_name(f".{dest.name}.{os.getpid()}.part")
    try:
        yield tmp
        tmp.replace(dest)
    finally:
        tmp.unlink(missing_ok=True)


def csv_cell(value: str) -> str:
    """Neutralise spreadsheet formulas in untrusted text."""
    if value.startswith(_FORMULA_START) or (value.startswith("-") and not _NUMBER_RE.match(value)):
        return "'" + value
    return value


def json_value(value: str, numeric: bool) -> str | int | float:
    if numeric and _NUMBER_RE.match(value):
        return float(value) if "." in value else int(value)
    return value


class PacketListWriter:
    """Streams packet-list rows to CSV (all cells quoted, like Wireshark) or to a
    JSON array of objects keyed by column id."""

    def __init__(
        self,
        fh: IO[str],
        fmt: str,
        headers: Sequence[str],
        keys: Sequence[str],
        numeric: Sequence[bool],
    ) -> None:
        if fmt not in LIST_FORMATS:
            raise InvalidParamsError(f"unknown packet list format {fmt!r}")
        self._fh = fh
        self._fmt = fmt
        self._keys = list(keys)
        self._numeric = list(numeric)
        self.rows = 0
        if fmt == "csv":
            self._csv = csv.writer(fh, quoting=csv.QUOTE_ALL, lineterminator="\n")
            self._csv.writerow([csv_cell(h) for h in headers])
        else:
            fh.write("[")

    def write(self, rows: Iterable[Sequence[str]]) -> None:
        for cells in rows:
            if self._fmt == "csv":
                self._csv.writerow([csv_cell(c) for c in cells])
            else:
                obj = {
                    k: json_value(c, n)
                    for k, c, n in zip(self._keys, cells, self._numeric, strict=True)
                }
                self._fh.write(("\n" if self.rows == 0 else ",\n") + json.dumps(obj))
            self.rows += 1

    def close(self) -> None:
        if self._fmt == "json":
            self._fh.write("\n]\n" if self.rows else "]\n")


_TEXT_PACKET = re.compile(rb"^Frame \d+: ")


class DissectionWriter:
    """Write tshark's dissection output to one file, possibly from several passes
    (a big frame set is filtered in chunks, see ``frame_set_filters``).

    Text is concatenated. PDML keeps the first pass's header and one closing
    ``</pdml>``. JSON is one array: the passes' ``[``/``]`` lines are dropped and
    a comma joins the last object of one pass to the first of the next. Feed
    each pass's lines (without line breaks) to :meth:`line`, calling
    :meth:`next_pass` before each pass and :meth:`close` at the end.
    """

    def __init__(self, fmt: str, out: BinaryIO) -> None:
        if fmt not in DISSECTION_FORMATS:
            raise InvalidParamsError(f"format must be one of {', '.join(DISSECTION_FORMATS)}")
        self.fmt = fmt
        self.out = out
        self.passes = 0
        self._in_header = False
        self._held: bytes | None = None  # JSON: the last line, until we know what follows
        if fmt == "json":
            out.write(b"[\n")

    def next_pass(self) -> None:
        self.passes += 1
        self._in_header = self.fmt == "pdml" and self.passes > 1

    def line(self, line: bytes) -> bool:
        """Write one line of the current pass; True if it starts a packet."""
        if self.fmt == "text":
            self.out.write(line + b"\n")
            return bool(_TEXT_PACKET.match(line))
        if self.fmt == "pdml":
            if self._in_header:  # later passes: skip up to and including <pdml ...>
                self._in_header = not line.startswith(b"<pdml")
                return False
            if line == b"</pdml>":
                return False
            self.out.write(line + b"\n")
            return line == b"<packet>"
        if line in (b"[", b"]", b"[]"):
            return False
        start = line == b"  {"
        if start and self._held == b"  }":
            self._held = b"  },"  # the previous pass's last packet
        if self._held is not None:
            self.out.write(self._held + b"\n")
        self._held = line
        return start

    def close(self) -> None:
        if self.fmt == "pdml":
            self.out.write(b"</pdml>\n")
        elif self.fmt == "json":
            if self._held is not None:
                self.out.write(self._held + b"\n")
            self.out.write(b"]\n")
