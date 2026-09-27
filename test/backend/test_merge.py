"""Merging capture files (a rotated capture's pieces, or any captures) with mergecap."""

import subprocess
from pathlib import Path

import pytest

from pcap_backend.pcap_service import PcapService
from pcap_backend.protocol import InvalidParamsError, RequestContext
from pcap_backend.tshark import find_tool

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures"


@pytest.fixture
def pieces(tmp_path: Path) -> list[Path]:
    """mixed.pcapng (26 packets) split like a ring buffer: piece_0000N_<time>.pcapng."""
    editcap = find_tool("editcap")
    subprocess.run(
        [str(editcap), "-c", "10", str(FIXTURES / "mixed.pcapng"), str(tmp_path / "piece.pcapng")],
        check=True,
        capture_output=True,
    )
    return sorted(tmp_path.glob("piece_*.pcapng"))


def _frames(service: PcapService, ctx: RequestContext, path: Path) -> list[str]:
    service.open({"path": str(path)}, ctx)
    return [r["cells"][1] for r in service.list_packets({"limit": 100}, ctx)["rows"]]


@pytest.mark.tshark
def test_merging_a_rotated_capture_gives_back_the_original(
    service: PcapService, ctx: RequestContext, tmp_path: Path, pieces: list[Path]
) -> None:
    assert len(pieces) == 3
    original = _frames(service, ctx, FIXTURES / "mixed.pcapng")
    service.close()
    dest = tmp_path / "merged.pcapng"
    res = service.merge(
        {"inputs": [str(p) for p in pieces], "dest": str(dest), "append": True}, ctx
    )
    assert res["inputs"] == 3 and res["size"] == dest.stat().st_size > 0
    assert _frames(service, ctx, dest) == original, "same packets, same times"


@pytest.mark.tshark
def test_merging_captures_by_timestamp(
    service: PcapService, ctx: RequestContext, tmp_path: Path
) -> None:
    dest = tmp_path / "both.pcap"
    inputs = [str(FIXTURES / "http.pcap"), str(FIXTURES / "dns.pcap")]
    service.merge({"inputs": inputs, "dest": str(dest), "format": "pcap"}, ctx)
    assert dest.read_bytes()[:4] in (b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4"), "pcap, not pcapng"
    info = service.open({"path": str(dest)}, ctx)
    assert info["frames"] == 11 + 6


@pytest.mark.tshark
def test_merge_refuses_bad_requests(
    service: PcapService, ctx: RequestContext, tmp_path: Path, pieces: list[Path]
) -> None:
    two = [str(p) for p in pieces[:2]]
    with pytest.raises(InvalidParamsError, match="at least two"):
        service.merge({"inputs": two[:1], "dest": str(tmp_path / "x.pcapng")}, ctx)
    with pytest.raises(InvalidParamsError, match="not found"):
        service.merge(
            {"inputs": [*two, str(tmp_path / "nope.pcap")], "dest": str(tmp_path / "x.pcapng")}, ctx
        )
    with pytest.raises(InvalidParamsError, match="open capture"):
        service.merge({"inputs": two, "dest": two[1]}, ctx)  # never over an input
    with pytest.raises(InvalidParamsError, match="format"):
        service.merge({"inputs": two, "dest": str(tmp_path / "x.txt"), "format": "txt"}, ctx)
    assert not (tmp_path / "x.pcapng").exists()
