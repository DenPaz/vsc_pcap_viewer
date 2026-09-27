"""Export Objects: files carried by HTTP, SMB, TFTP, IMF, DICOM and FTP-DATA.

tshark extracts them itself (``--export-objects <proto>,<folder>``, one pass for
every protocol, with ``-2``: TFTP transfers are only complete then) but only
writes the files, named from the capture (the request's file name, a mail's
subject, ``object<frame>.<ext>`` when there is none, ``name(1).ext`` for
duplicates). The same pass prints a few fields per packet, which link each file
back to the packet that carried it (:class:`Linker`): HTTP bodies by content
(``http.file_data`` is the decoded body tshark saves), TFTP by the requested
file name, IMF by subject, ``object<N>`` names by N.
"""

import hashlib
import mimetypes
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import unquote, urlsplit

PROTOCOLS = ("http", "smb", "tftp", "imf", "dicom", "ftp-data")
FIELDS = (
    "frame.number",
    "frame.len",
    "http.file_data",
    "http.content_type",
    "http.response_for.uri",
    "http.request.full_uri",
    "imf.subject",
    "tftp.source_file",
    "tftp.destination_file",
)
# Occurrences of one field in a packet (several HTTP messages in one segment);
# URIs may contain commas, so not tshark's default.
AGGREGATOR = "\x1e"

_GENERIC_RE = re.compile(r"object(\d+)(?:\.[^.]*)?")
_DUPLICATE_RE = re.compile(r"\(\d+\)(?=\.[^.]*$|$)")
_UNSAFE_RE = re.compile(r'[\x00-\x1f\x7f<>:"/\\|?*]')
_WINDOWS_RESERVED = frozenset(
    ["CON", "PRN", "AUX", "NUL"] + [f"{p}{i}" for p in ("COM", "LPT") for i in range(1, 10)]
)


@dataclass(slots=True)
class _Hint:
    frame: int
    content_type: str = ""
    uri: str = ""
    used: bool = False


@dataclass(slots=True)
class ExportedObject:
    protocol: str
    name: str
    path: Path
    size: int
    frame: int | None = None
    host: str = ""
    content_type: str = ""

    def to_json(self, index: int) -> dict[str, Any]:
        return {
            "id": index,
            "protocol": self.protocol,
            "name": self.name,
            "size": self.size,
            "frame": self.frame,
            "host": self.host,
            "contentType": self.content_type,
        }


def _name_key(name: str) -> str:
    """Compare names the way tshark may have changed them to write the file."""
    return re.sub(r"[^0-9a-z.]+", "_", name.lower()).strip("_")


def _file_digest(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        while chunk := fh.read(1 << 20):
            h.update(chunk)
    return h.hexdigest()


@dataclass
class Linker:
    """Packets that carried objects, collected from the pass's field lines."""

    by_body: dict[str, list[_Hint]] = field(default_factory=dict)
    by_name: dict[tuple[str, str], list[_Hint]] = field(default_factory=dict)

    def add(self, values: dict[str, str]) -> None:
        """One packet's fields (name → value, occurrences joined by AGGREGATOR)."""
        if not any(values.get(f) for f in FIELDS[2:]):
            return
        try:
            frame = int(values["frame.number"])
        except KeyError, ValueError:
            return
        occurrences = {f: [v for v in values.get(f, "").split(AGGREGATOR) if v] for f in FIELDS[2:]}
        uris = occurrences["http.response_for.uri"] + occurrences["http.request.full_uri"]
        types = occurrences["http.content_type"]
        for i, body in enumerate(occurrences["http.file_data"]):
            uri = uris[i] if i < len(uris) else (uris[0] if uris else "")
            hint = _Hint(frame, types[i] if i < len(types) else "", uri)
            try:
                digest = hashlib.sha256(bytes.fromhex(body)).hexdigest()
            except ValueError:
                digest = ""  # (not hex: a tshark that prints the body as text)
            if digest:
                self.by_body.setdefault(digest, []).append(hint)
            name = unquote(urlsplit(uri).path.rsplit("/", 1)[-1])
            if name:
                self.by_name.setdefault(("http", _name_key(name)), []).append(hint)
        for subject in occurrences["imf.subject"]:
            self.by_name.setdefault(("imf", _name_key(f"{subject}.eml")), []).append(_Hint(frame))
        for requested in occurrences["tftp.source_file"] + occurrences["tftp.destination_file"]:
            name = re.split(r"[/\\]", requested)[-1]
            self.by_name.setdefault(("tftp", _name_key(name)), []).append(_Hint(frame))

    @staticmethod
    def _take(hints: list[_Hint] | None) -> _Hint | None:
        for hint in hints or ():
            if not hint.used:
                hint.used = True
                return hint
        return None

    def link(self, protocol: str, path: Path) -> _Hint | None:
        """The packet that carried the object tshark wrote to ``path``."""
        generic = _GENERIC_RE.fullmatch(_DUPLICATE_RE.sub("", path.name))
        if generic:
            return _Hint(int(generic[1]))
        hint = None
        if protocol == "http":
            hint = self._take(self.by_body.get(_file_digest(path)))
        base = _DUPLICATE_RE.sub("", path.name)
        return hint or self._take(self.by_name.get((protocol, _name_key(base))))


def _order(path: Path) -> tuple[str, int]:
    """``name.ext`` before ``name(1).ext`` before ``name(2).ext``."""
    m = re.search(r"\((\d+)\)(?=\.[^.]*$|$)", path.name)
    return (_DUPLICATE_RE.sub("", path.name), int(m[1]) if m else 0)


def collect(folder: Path, linker: Linker) -> list[ExportedObject]:
    """The files tshark wrote under ``folder/<protocol>/``, linked to packets and
    sorted by packet (unlinked ones last, by name)."""
    objects: list[ExportedObject] = []
    for protocol in PROTOCOLS:
        sub = folder / protocol
        if not sub.is_dir():
            continue
        for path in sorted((p for p in sub.iterdir() if p.is_file()), key=_order):
            hint = linker.link(protocol, path)
            content_type = (hint.content_type if hint else "") or (
                mimetypes.guess_type(path.name)[0] or ""
            )
            host = (urlsplit(hint.uri).hostname or "") if hint and hint.uri else ""
            objects.append(
                ExportedObject(
                    protocol,
                    path.name,
                    path,
                    path.stat().st_size,
                    hint.frame if hint else None,
                    host,
                    content_type.split(";")[0].strip(),
                )
            )
    objects.sort(key=lambda o: (o.frame is None, o.frame or 0, o.protocol, o.name))
    return objects


def safe_name(name: str) -> str:
    """A file name from the capture, made safe to create on any OS."""
    cleaned = _UNSAFE_RE.sub("_", name).strip().rstrip(". ")
    if not cleaned or cleaned in {".", ".."}:
        cleaned = "object"
    if cleaned.split(".")[0].upper() in _WINDOWS_RESERVED:
        cleaned = f"_{cleaned}"
    return cleaned[:200]


def unique_path(folder: Path, name: str, taken: set[str]) -> Path:
    """``folder/name``, or ``name (1).ext``… when that exists or was just used."""
    stem, dot, ext = name.rpartition(".") if "." in name.lstrip(".") else (name, "", "")
    n = 0
    while True:
        candidate = name if n == 0 else f"{stem} ({n}){dot}{ext}"
        if candidate.lower() not in taken and not (folder / candidate).exists():
            taken.add(candidate.lower())
            return folder / candidate
        n += 1
