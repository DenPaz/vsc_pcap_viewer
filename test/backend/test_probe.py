"""probe_file (Open File in PCAP Viewer…): whether tshark reads a file,
whatever it is called, and why not (ber.count_records for record files)."""

import shutil
from pathlib import Path

import pytest

from pcap_backend import ber
from pcap_backend.pcap_service import PcapService
from pcap_backend.protocol import InvalidParamsError, RequestContext

# SEQUENCE { INTEGER 5, OCTET STRING "hello" }, as test/fixtures/formats/capture.ber.
RECORD = bytes.fromhex("300a020105040568656c6c6f")


def _write(tmp_path: Path, name: str, data: bytes) -> Path:
    path = tmp_path / name
    path.write_bytes(data)
    return path


def test_count_records(tmp_path: Path) -> None:
    assert ber.count_records(_write(tmp_path, "one", RECORD)) == 1
    assert ber.count_records(_write(tmp_path, "three", RECORD * 3)) == 3
    # Block padding after the records.
    assert ber.count_records(_write(tmp_path, "padded", RECORD * 2 + b"\x00" * 20)) == 2
    assert ber.count_records(_write(tmp_path, "ff", RECORD * 2 + b"\xff" * 7)) == 2
    # Long-form length (0x82 0x01 0x00 = 256) and a high tag number (0x1f 0x81 0x01).
    long_value = bytes.fromhex("048201") + b"\x00" + b"x" * 256
    assert ber.count_records(_write(tmp_path, "long", long_value + RECORD)) == 2
    high_tag = bytes.fromhex("1f810103") + b"abc"
    assert ber.count_records(_write(tmp_path, "tag", high_tag * 2)) == 2
    # Not BER records: a cut-off record, junk after the records, an indefinite length, text.
    assert ber.count_records(_write(tmp_path, "cut", RECORD + RECORD[:-1])) is None
    assert ber.count_records(_write(tmp_path, "junk", RECORD + b"\x00junk")) is None
    assert ber.count_records(_write(tmp_path, "indef", bytes.fromhex("3080") + RECORD)) is None
    assert ber.count_records(_write(tmp_path, "text", b"hello world, not ASN.1\n")) is None
    assert ber.count_records(_write(tmp_path, "empty", b"")) is None


def test_count_records_stops_at_the_limit(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(ber, "MAX_RECORDS", 5)
    assert ber.count_records(_write(tmp_path, "many", RECORD * 50)) == 5


@pytest.mark.tshark
def test_probe_file(service: PcapService, fixtures: Path, tmp_path: Path) -> None:
    ctx = RequestContext()

    def probe(path: Path) -> dict:
        return service.probe_file({"path": str(path)}, ctx)

    # Captures open whatever they are called.
    renamed = tmp_path / "trace"
    shutil.copyfile(fixtures / "http.pcap", renamed)
    assert probe(renamed) == {"readable": True, "format": "pcap"}
    shutil.copyfile(fixtures / "mixed.pcapng", tmp_path / "mixed.dat")
    assert probe(tmp_path / "mixed.dat") == {"readable": True, "format": "pcapng"}
    # One BER value per file is tshark's BER file type, even without an extension.
    assert probe(_write(tmp_path, "record", RECORD)) == {"readable": True, "format": None}

    records = probe(_write(tmp_path, "cdrs", RECORD * 3))
    assert records["readable"] is False
    assert records["berRecords"] == 3
    assert "3 BER records one after another" in records["message"]
    text = probe(_write(tmp_path, "notes", b"just some text\n"))
    assert text == {
        "readable": False,
        "message": "notes isn't a capture file in a format tshark can read",
    }
    assert probe(_write(tmp_path, "nothing", b"")) == {
        "readable": False,
        "message": "nothing is empty",
    }
    with pytest.raises(InvalidParamsError, match="not found"):
        probe(tmp_path / "missing")
