"""Capture editing with editcap (editing.py, edit_capture)."""

import subprocess
import threading
from decimal import Decimal
from pathlib import Path

import pytest

from pcap_backend import comments, editing
from pcap_backend.pcap_service import PcapService
from pcap_backend.protocol import IndexingError, InvalidParamsError, RequestContext
from pcap_backend.tshark import find_tool

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures"
MIXED = FIXTURES / "mixed.pcapng"  # 26 packets from epoch 1700000000.000, 2 ms apart


def test_editcap_options() -> None:
    opts = editing.editcap_options
    assert opts("timeShift", {"offset": -3600.5}, 10) == (["-t", "-3600.5"], [])
    assert opts("timeShift", {"offset": "0.000000001"}, 10) == (["-t", "0.000000001"], [])
    assert opts("timeShift", {"offset": 1e-12}, 10) == (["-t", "0"], [])
    assert opts("dedup", {}, 10) == (["-D", "5"], [])
    assert opts("dedup", {"window": 100}, 10) == (["-D", "100"], [])
    assert opts("dedup", {"seconds": 0.5}, 10) == (["-w", "0.5"], [])
    assert opts("keep", {"frames": "2-5, 10 8-"}, 10) == (["-r"], ["2-5", "10", "8-10"])
    assert opts("keep", {"frames": "1-99"}, 10) == (["-r"], ["1-10"])
    assert opts("keep", {"from": 1700000000.5}, 10) == (["-A", "1700000000.5"], [])
    assert opts("keep", {"from": 1, "to": 2, "frames": "3"}, 10) == (
        ["-r", "-A", "1", "-B", "2"],
        ["3"],
    )
    assert opts("truncate", {"snaplen": 64}, 10) == (["-s", "64"], [])
    assert opts("split", {"packets": 1000}, 10) == (["-c", "1000"], [])
    assert opts("split", {"seconds": "60"}, 10) == (["-i", "60"], [])
    for op, bad in [
        ("timeShift", {}),
        ("timeShift", {"offset": "1h"}),
        ("timeShift", {"offset": "nan"}),
        ("dedup", {"window": 0}),
        ("dedup", {"window": 2.5}),
        ("dedup", {"seconds": -1}),
        ("keep", {}),
        ("keep", {"frames": "0-3"}),
        ("keep", {"frames": "11"}),
        ("keep", {"frames": "5-2"}),
        ("keep", {"frames": "a-b"}),
        ("keep", {"from": 5, "to": 1}),
        ("truncate", {"snaplen": 0}),
        ("injectSecrets", {"keyLog": "/no/such/file"}),
        ("split", {}),
        ("rotate", {}),
    ]:
        with pytest.raises(InvalidParamsError):
            opts(op, bad, 10)


def test_skipped_packets() -> None:
    stderr = "52 packets seen, 26 packets skipped with duplicate window of 5 packets.\n"
    assert editing.skipped_packets(stderr) == 26
    assert editing.skipped_packets("") is None


def _epochs(path: Path) -> list[Decimal]:
    tshark = find_tool("tshark")
    out = subprocess.run(
        [str(tshark), "-r", str(path), "-T", "fields", "-e", "frame.time_epoch"],
        capture_output=True,
        check=True,
    ).stdout.decode()
    return [Decimal(x) for x in out.split()]


def _edit(service: PcapService, tmp_path: Path, **params: object) -> dict[str, object]:
    return service.edit_capture({"dest": str(tmp_path / "out.pcapng"), **params}, RequestContext())


@pytest.mark.tshark
def test_time_shift_and_ranges(service: PcapService, tmp_path: Path) -> None:
    service.open({"path": str(MIXED)}, RequestContext())
    before = _epochs(MIXED)
    res = _edit(service, tmp_path, operation="timeShift", offset="-3600.25")
    assert res == {"path": str(tmp_path / "out.pcapng"), "packets": 26}
    assert _epochs(tmp_path / "out.pcapng") == [t - Decimal("3600.25") for t in before]

    res = _edit(service, tmp_path, operation="keep", frames="2-5, 10 20-")
    assert res["packets"] == 4 + 1 + 7
    res = _edit(
        service, tmp_path, operation="keep", **{"from": str(before[3]), "to": str(before[8])}
    )
    assert _epochs(tmp_path / "out.pcapng") == before[3:8], "-B is exclusive"

    res = _edit(service, tmp_path, operation="truncate", snaplen=20)
    assert res["packets"] == 26
    with pytest.raises(InvalidParamsError, match="open capture"):
        service.edit_capture({"operation": "truncate", "snaplen": 20, "dest": str(MIXED)},
                             RequestContext())  # fmt: skip
    assert not list(tmp_path.glob(".*.part"))


@pytest.mark.tshark
def test_remove_duplicates(service: PcapService, tmp_path: Path) -> None:
    doubled = tmp_path / "doubled.pcapng"
    mergecap = find_tool("mergecap")
    subprocess.run([str(mergecap), "-w", str(doubled), str(MIXED), str(MIXED)], check=True)
    service.open({"path": str(doubled)}, RequestContext())
    res = _edit(service, tmp_path, operation="dedup")
    assert res["packets"] == 26 and res["removed"] == 26
    res = _edit(service, tmp_path, operation="dedup", seconds="0.000001")
    assert res["removed"] == 26


@pytest.mark.tshark
def test_split(service: PcapService, tmp_path: Path) -> None:
    service.open({"path": str(MIXED)}, RequestContext())
    out = tmp_path / "pieces"
    out.mkdir()
    res = service.edit_capture(
        {"operation": "split", "packets": 10, "dir": str(out)}, RequestContext()
    )
    files = [Path(p) for p in res["files"]]
    assert len(files) == 3 and all(p.parent == out for p in files)
    assert [comments.packet_count(p) for p in files] == [10, 10, 6]
    assert files[0].name.startswith("mixed_00000_") and files[0].suffix == ".pcapng"
    # Again: new names, nothing overwritten, no scratch folder left.
    again = service.edit_capture(
        {"operation": "split", "packets": 10, "dir": str(out)}, RequestContext()
    )
    assert not set(again["files"]) & set(res["files"])
    assert len(list(out.iterdir())) == 6
    with pytest.raises(InvalidParamsError):
        service.edit_capture({"operation": "split", "packets": 10, "dir": str(tmp_path / "x")},
                             RequestContext())  # fmt: skip


@pytest.mark.tshark
def test_inject_tls_secrets(
    service: PcapService, tmp_path: Path, tls_keylog: tuple[Path, Path]
) -> None:
    capture, keylog = tls_keylog
    service.open({"path": str(capture)}, RequestContext())
    res = _edit(service, tmp_path, operation="injectSecrets", keyLog=str(keylog))
    out = Path(str(res["path"]))
    # Opened without any key log setting, the embedded keys decrypt it.
    service.open({"path": str(out)}, RequestContext())
    assert service.set_filter({"expr": "http"}, RequestContext())["matchCount"] > 0


@pytest.mark.tshark
def test_refused_while_indexing(
    service: PcapService, tmp_path: Path, slow_index: threading.Event
) -> None:
    service.open({"path": str(MIXED), "stream": True}, RequestContext())
    with pytest.raises(IndexingError):
        _edit(service, tmp_path, operation="dedup")
    slow_index.set()
