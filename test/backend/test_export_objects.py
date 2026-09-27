"""Export Objects: one tshark pass, objects linked to packets, saving."""

import importlib.util
import threading
from pathlib import Path
from typing import Any

import pytest

from pcap_backend import objects
from pcap_backend.pcap_service import PcapService
from pcap_backend.protocol import InvalidParamsError, RequestContext

_spec = importlib.util.spec_from_file_location(
    "generate", Path(__file__).resolve().parents[1] / "fixtures" / "generate.py"
)


def _bodies() -> Any:
    """The fixture generator (for the objects' expected contents); needs scapy."""
    pytest.importorskip("scapy")
    assert _spec is not None and _spec.loader is not None
    module = importlib.util.module_from_spec(_spec)
    _spec.loader.exec_module(module)
    return module


def test_safe_names(tmp_path: Path) -> None:
    assert objects.safe_name("report.pdf") == "report.pdf"
    assert objects.safe_name('a/b\\c:d*e?"f<g>|h\x00') == "a_b_c_d_e__f_g__h_"
    assert objects.safe_name("..") == "object"
    assert objects.safe_name("CON.txt") == "_CON.txt"
    assert objects.safe_name("trailing. ") == "trailing"
    taken: set[str] = set()
    (tmp_path / "a.txt").write_text("x")
    assert objects.unique_path(tmp_path, "a.txt", taken).name == "a (1).txt"
    assert objects.unique_path(tmp_path, "a.txt", taken).name == "a (2).txt"
    assert objects.unique_path(tmp_path, "README", taken).name == "README"
    assert objects.unique_path(tmp_path, "readme", taken).name == "readme (1)"


def test_linker(tmp_path: Path) -> None:
    linker = objects.Linker()
    body = b"hello"
    linker.add(
        {
            "frame.number": "7",
            "http.file_data": body.hex(),
            "http.content_type": "text/plain",
            "http.response_for.uri": "http://h.example/dir/a%20b.txt",
        }
    )
    linker.add({"frame.number": "9", "tftp.source_file": "boot/x.bin"})
    linker.add({"frame.number": "12", "imf.subject": "Hi: there"})
    linker.add({"frame.number": "3"})  # nothing to link
    files = {"a b.txt": b"hello", "other.txt": b"hello", "x.bin": b".", "Hi_ there.eml": b".",
             "object42.html": b".", "nope": b"?"}  # fmt: skip
    for name, data in files.items():
        (tmp_path / name).write_bytes(data)
    first = linker.link("http", tmp_path / "a b.txt")
    assert first is not None and (first.frame, first.content_type) == (7, "text/plain")
    assert linker.link("http", tmp_path / "other.txt") is None, "each packet links one object"
    assert getattr(linker.link("tftp", tmp_path / "x.bin"), "frame", None) == 9
    assert getattr(linker.link("imf", tmp_path / "Hi_ there.eml"), "frame", None) == 12
    assert getattr(linker.link("http", tmp_path / "object42.html"), "frame", None) == 42
    assert linker.link("smb", tmp_path / "nope") is None


def _listed(svc: PcapService, ctx: RequestContext) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = svc.export_objects({}, ctx)["objects"]
    return result


@pytest.mark.tshark
def test_export_objects(service: PcapService, ctx: RequestContext, fixtures: Path) -> None:
    gen = _bodies()
    service.open({"path": str(fixtures / "objects.pcap")}, ctx)
    progress: list[dict[str, Any]] = []
    found = _listed(service, RequestContext(progress=progress.append))
    summary = [(o["protocol"], o["name"], o["frame"], o["contentType"]) for o in found]
    assert summary == [
        ("http", "logo.png", 6, "image/png"),
        ("http", "report", 10, "text/plain"),
        ("http", "upload", 12, "application/json"),
        ("http", "dup.txt", 18, "text/plain"),
        ("http", "dup(1).txt", 22, "text/plain"),
        ("tftp", "config.bin", 27, "application/octet-stream"),
        ("imf", "Test report.eml", 53, "message/rfc822"),
    ]
    assert [o["host"] for o in found[:5]] == ["example.com"] * 5
    assert [o["id"] for o in found] == list(range(7))
    assert progress and all(p["phase"] == "objects" for p in progress)
    # The objects are the transferred files: HTTP bodies decoded (gzip, chunked).
    expected = [gen.OBJECT_PNG, gen.OBJECT_REPORT, gen.OBJECT_UPLOAD, gen.OBJECT_DUP,
                gen.OBJECT_DUP, gen.OBJECT_TFTP, gen.OBJECT_MAIL]  # fmt: skip
    assert [o["size"] for o in found] == [len(b) for b in expected]
    assert _listed(service, ctx) == found, "cached"


@pytest.mark.tshark
def test_save_objects(
    service: PcapService, ctx: RequestContext, fixtures: Path, tmp_path: Path
) -> None:
    gen = _bodies()
    service.open({"path": str(fixtures / "objects.pcap")}, ctx)
    with pytest.raises(InvalidParamsError):
        service.save_objects({"ids": [0], "dir": str(tmp_path)}, ctx)  # not listed yet
    found = _listed(service, ctx)
    one = tmp_path / "logo-copy.png"
    assert service.save_objects({"ids": [0], "dest": str(one)}, ctx) == {"saved": [str(one)]}
    assert one.read_bytes() == gen.OBJECT_PNG

    folder = tmp_path / "all"
    folder.mkdir()
    (folder / "report").write_text("already here")
    saved = service.save_objects({"ids": [o["id"] for o in found], "dir": str(folder)}, ctx)[
        "saved"
    ]
    names = sorted(Path(p).name for p in saved)
    assert names == sorted(["logo.png", "report (1)", "upload", "dup.txt", "dup(1).txt",
                            "config.bin", "Test report.eml"])  # fmt: skip
    assert (folder / "report").read_text() == "already here", "never overwritten"
    assert (folder / "report (1)").read_bytes() == gen.OBJECT_REPORT
    assert (folder / "config.bin").read_bytes() == gen.OBJECT_TFTP
    assert not list(folder.glob(".*.part"))

    for bad in (
        {"ids": [99], "dir": str(folder)},
        {"ids": [], "dir": str(folder)},
        {"ids": [0, 1], "dest": str(tmp_path / "x")},
        {"ids": [0], "dest": str(fixtures / "objects.pcap")},  # the open capture
        {"ids": [0], "dir": str(tmp_path / "missing")},
    ):
        with pytest.raises(InvalidParamsError):
            service.save_objects(bad, ctx)


@pytest.mark.tshark
def test_no_objects(opened: PcapService, ctx: RequestContext, fixtures: Path) -> None:
    found = _listed(opened, ctx)
    assert [(o["name"], o["frame"]) for o in found] == [("index.html", 7)]
    opened.open({"path": str(fixtures / "dns.pcap")}, ctx)
    assert _listed(opened, ctx) == [], "a new capture: listed again"


@pytest.mark.tshark
def test_export_objects_while_indexing(
    service: PcapService, ctx: RequestContext, fixtures: Path, slow_index: threading.Event
) -> None:
    res = service.open({"path": str(fixtures / "objects.pcap"), "stream": True}, ctx)
    assert res["indexing"]
    assert len(_listed(service, ctx)) == 7
    slow_index.set()
