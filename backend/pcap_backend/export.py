"""Helpers for the ``export`` method: destination checks, atomic output files
and the packet-list writers (CSV / JSON).

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
from typing import IO

from .protocol import InvalidParamsError

CAPTURE_FORMATS = ("pcapng", "pcap")
LIST_FORMATS = ("csv", "json")
EXPORT_KINDS = (*CAPTURE_FORMATS, *LIST_FORMATS, "bytes")

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
