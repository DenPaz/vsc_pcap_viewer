"""Packet comments: read from pcapng, edited, saved with editcap."""

import gzip
import shutil
import struct
import time
from pathlib import Path
from typing import Any

import pytest

from pcap_backend import comments
from pcap_backend.pcap_service import PcapService
from pcap_backend.protocol import InvalidParamsError, RequestContext
from pcap_backend.tshark import ToolError

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures"
COMMENTED = FIXTURES / "comments.pcapng"
SAVED = {
    2: ["SYN-ACK from the server"],
    4: ["The request\nsecond line\twith a tab"],
    5: ["first of two", "second of two"],
}


def test_read_comments() -> None:
    assert comments.read_comments(COMMENTED) == SAVED
    assert comments.read_comments(FIXTURES / "http.pcap") == {}, "pcap has no comments"
    assert comments.read_comments(FIXTURES / "mixed.pcapng") == {}
    assert comments.is_pcapng(COMMENTED) and not comments.is_pcapng(FIXTURES / "http.pcap")
    with pytest.raises(comments.UnreadableError, match="LZ4"):
        comments.read_comments(FIXTURES / "formats" / "mixed.pcapng.lz4")


def test_read_compressed_and_truncated(tmp_path: Path) -> None:
    gz = tmp_path / "c.pcapng.gz"
    gz.write_bytes(gzip.compress(COMMENTED.read_bytes(), mtime=0))
    assert comments.read_comments(gz) == SAVED
    cut = tmp_path / "cut.pcapng"
    data = COMMENTED.read_bytes()
    cut.write_bytes(data[: len(data) - 10])  # the last block is incomplete
    assert comments.read_comments(cut) == SAVED


def _block(kind: int, body: bytes, endian: str) -> bytes:
    body += b"\0" * (-len(body) % 4)
    total = len(body) + 12
    return struct.pack(endian + "II", kind, total) + body + struct.pack(endian + "I", total)


def test_read_big_endian_and_other_packet_blocks(tmp_path: Path) -> None:
    """A big-endian section with a Simple Packet Block (no options, still a frame)
    and an obsolete Packet Block carrying a comment."""
    e = ">"
    shb = _block(0x0A0D0D0A, struct.pack(e + "IHHq", 0x1A2B3C4D, 1, 0, -1), e)
    idb = _block(1, struct.pack(e + "HHI", 1, 0, 65535), e)
    spb = _block(3, struct.pack(e + "I", 4) + b"abcd", e)
    text = "é comment".encode()
    opt = struct.pack(e + "HH", 1, len(text)) + text + b"\0" * (-len(text) % 4)
    opt += struct.pack(e + "HH", 0, 0)
    pb = _block(2, struct.pack(e + "HHIIII", 0, 0, 0, 0, 4, 4) + b"wxyz" + opt, e)
    path = tmp_path / "be.pcapng"
    path.write_bytes(shb + idb + spb + pb)
    assert comments.read_comments(path) == {2: ["é comment"]}


def test_editcap_args() -> None:
    # Only additions/changes of single-comment packets: name just those.
    args, result = comments.editcap_args(SAVED, {2: "new", 9: "added"})
    assert args == ["-a", "2:new", "-a", "9:added"]
    assert result == {2: "new", 4: SAVED[4][0], 5: "first of two\nsecond of two", 9: "added"}
    # A deletion (or a packet with several comments) rewrites them all.
    args, result = comments.editcap_args(SAVED, {4: None})
    assert args[0] == "--discard-packet-comments"
    assert args[1:] == ["-a", "2:SYN-ACK from the server", "-a", "5:first of two\nsecond of two"]
    args, _ = comments.editcap_args(SAVED, {5: "one"})
    assert args == ["--discard-packet-comments", "-a", f"2:{SAVED[2][0]}", "-a", f"4:{SAVED[4][0]}",
                    "-a", "5:one"]  # fmt: skip
    assert comments.editcap_args(SAVED, {}) == ([], {n: "\n".join(t) for n, t in SAVED.items()})


def _open_copy(svc: PcapService, tmp_path: Path, name: str = "c.pcapng") -> Path:
    path = tmp_path / name
    shutil.copyfile(COMMENTED, path)
    svc.open({"path": str(path)}, RequestContext())
    assert svc._file is not None
    assert svc._file.comments_ready.wait(10)
    return path


def _rows(svc: PcapService) -> dict[int, dict[str, Any]]:
    page = svc.list_packets({"offset": 0, "limit": 20}, RequestContext())
    return {r["number"]: r for r in page["rows"]}


@pytest.mark.tshark
def test_rows_and_edits(service: PcapService) -> None:
    events: list[tuple[str, dict[str, Any]]] = []
    service.notify = lambda method, params: events.append((method, params))
    res = service.open({"path": str(COMMENTED)}, RequestContext())
    assert res["comments"] == {"inPlace": True}
    deadline = time.monotonic() + 10
    while not events and time.monotonic() < deadline:
        time.sleep(0.02)
    assert events == [("comments", {"count": 3, "error": None})]
    rows = _rows(service)
    assert rows[2]["comment"] == SAVED[2][0]
    assert rows[5]["comment"] == "first of two\nsecond of two"
    assert "comment" not in rows[1] and "commentEdited" not in rows[2]

    service.set_comments({"edits": {"1": "new one", "2": None}}, RequestContext())
    rows = _rows(service)
    assert (rows[1]["comment"], rows[1]["commentEdited"]) == ("new one", True)
    assert "comment" not in rows[2] and rows[2]["commentEdited"] is True
    got = service.packet_comments({"all": True}, RequestContext())
    assert got["comments"] == {"1": "new one", "4": SAVED[4][0], "5": "first of two\nsecond of two"}
    assert got["edited"] == [1, 2] and got["error"] is None
    got = service.packet_comments({"frames": [4, 6]}, RequestContext())
    assert (got["comments"], got["edited"]) == ({"4": SAVED[4][0]}, [])
    for bad in ({"edits": {"99": "x"}}, {"edits": {"x": "y"}}, {"edits": {"1": 5}}, {"edits": []}):
        with pytest.raises(InvalidParamsError):
            service.set_comments(bad, RequestContext())


@pytest.mark.tshark
def test_save_as_a_new_file(service: PcapService, tmp_path: Path) -> None:
    path = _open_copy(service, tmp_path)
    service.set_comments({"edits": {"1": "added", "4": ""}}, RequestContext())
    dest = tmp_path / "out.pcapng"
    res = service.save_comments({"dest": str(dest)}, RequestContext())
    assert res == {"path": str(dest), "comments": 3}
    # A deletion rewrites them all: frame 5's two comments become one.
    assert comments.read_comments(dest) == {
        1: ["added"],
        2: SAVED[2],
        5: ["first of two\nsecond of two"],
    }
    assert comments.read_comments(path) == SAVED, "the open capture is unchanged"
    assert _rows(service)[1]["commentEdited"] is True, "still unsaved here"
    with pytest.raises(InvalidParamsError):
        service.save_comments({"dest": str(path)}, RequestContext())  # the open capture


@pytest.mark.tshark
def test_save_in_place(service: PcapService, tmp_path: Path) -> None:
    path = _open_copy(service, tmp_path)
    service.set_comments({"edits": {"1": "added", "3": "multi\nline"}}, RequestContext())
    service.save_comments({"inPlace": True}, RequestContext())
    expected = {1: ["added"], 2: SAVED[2], 3: ["multi\nline"], 4: SAVED[4], 5: SAVED[5]}
    assert comments.read_comments(path) == expected, "only named packets changed"
    rows = _rows(service)
    assert rows[3]["comment"] == "multi\nline" and "commentEdited" not in rows[3]
    # tshark sees them (detail tree, filters) straight away.
    assert service.set_filter({"expr": "frame.comment"}, RequestContext())["matchCount"] == 5
    tree = service.packet_detail({"number": 1}, RequestContext())["tree"]
    assert any("comment" in n["label"].lower() for n in tree)
    assert not list(tmp_path.glob(".*.part"))


@pytest.mark.tshark
def test_reload_after_another_editor_saved(service: PcapService, tmp_path: Path) -> None:
    path = _open_copy(service, tmp_path)
    other = PcapService()
    try:
        other.open({"path": str(path)}, RequestContext())
        other.save_comments(
            {"inPlace": True, "edits": {"6": "from the other editor"}}, RequestContext()
        )
    finally:
        other.shutdown()
    assert "comment" not in _rows(service)[6]
    service.set_comments({"edits": {}, "reload": True}, RequestContext())
    assert _rows(service)[6]["comment"] == "from the other editor"


@pytest.mark.tshark
def test_save_needs_pcapng_in_place(opened: PcapService, tmp_path: Path) -> None:
    assert opened.open({"path": str(FIXTURES / "http.pcap")}, RequestContext())["comments"] == {
        "inPlace": False
    }
    with pytest.raises(InvalidParamsError, match="save as"):
        opened.save_comments({"inPlace": True, "edits": {"1": "x"}}, RequestContext())
    dest = tmp_path / "http-comments.pcapng"
    opened.save_comments({"dest": str(dest), "edits": {"1": "x"}}, RequestContext())
    assert comments.read_comments(dest) == {1: ["x"]}


@pytest.mark.tshark
def test_many_comments_run_editcap_in_chunks(
    service: PcapService, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from pcap_backend import pcap_service  # noqa: PLC0415

    monkeypatch.setattr(pcap_service, "MAX_FILTER_ARG", 40)
    _open_copy(service, tmp_path)
    edits = {str(n): f"comment number {n}" for n in range(1, 12)}
    edits["2"] = ""  # a deletion: everything rewritten, over several runs
    dest = tmp_path / "chunks.pcapng"
    service.save_comments({"dest": str(dest), "edits": edits}, RequestContext())
    saved = comments.read_comments(dest)
    assert sorted(saved) == [1, *range(3, 12)]
    assert saved[5] == ["comment number 5"]
    assert not [p for p in tmp_path.iterdir() if p.name.startswith("chunks.pcapng.")]


@pytest.mark.tshark
def test_unreadable_comments_are_reported(service: PcapService) -> None:
    service.open({"path": str(FIXTURES / "formats" / "mixed.pcapng.lz4")}, RequestContext())
    got = service.packet_comments({"frames": [1]}, RequestContext())
    assert "LZ4" in got["error"]
    with pytest.raises(ToolError, match="LZ4"):
        service.save_comments({"dest": "/nonexistent/x.pcapng", "edits": {}}, RequestContext())
