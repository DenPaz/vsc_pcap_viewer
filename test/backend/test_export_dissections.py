"""Export Packet Dissections: text / PDML / JSON, joined across chunked passes."""

import io
import json
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any

import pytest

from pcap_backend import pcap_service
from pcap_backend.export import DissectionWriter
from pcap_backend.pcap_service import PcapService
from pcap_backend.protocol import FilterError, InvalidParamsError, RequestContext


def _pdml_packets(data: bytes) -> int:
    """Packets in PDML written from tshark's own output (parsing checks it's well formed)."""
    return len(ET.fromstring(data).findall("packet"))  # noqa: S314


def _frame_numbers(packets: list[dict[str, Any]]) -> list[str]:
    return [p["_source"]["layers"]["frame"]["frame.number"] for p in packets]


PDML_HEAD = [
    b'<?xml version="1.0" encoding="utf-8"?>',
    b"<!-- comment -->",
    b'<pdml version="0" creator="wireshark/4.2.2">',
]


def _write(fmt: str, passes: list[list[bytes]]) -> tuple[bytes, int]:
    out = io.BytesIO()
    writer = DissectionWriter(fmt, out)
    packets = 0
    for lines in passes:
        writer.next_pass()
        packets += sum(writer.line(line) for line in lines)
    writer.close()
    return out.getvalue(), packets


def test_dissection_writer_joins_passes() -> None:
    obj = [b"  {", b'    "_index": "x"', b"  }"]
    two = [b"[", *obj[:-1], b"  },", *obj, b"]"]
    data, packets = _write("json", [two, [b"[]"], [b"[", *obj, b"]"]])
    assert packets == 3 and len(json.loads(data)) == 3
    assert _write("json", [[b"[]"]])[0] == b"[\n]\n", "no packets: an empty array"

    packet = [b"<packet>", b'<proto name="frame"/>', b"</packet>"]
    first = [*PDML_HEAD, *packet, b"</pdml>"]
    data, packets = _write("pdml", [first, [*PDML_HEAD, *packet, *packet, b"</pdml>"]])
    assert packets == 3 and _pdml_packets(data) == 3
    assert data.count(b"<?xml") == 1 and data.count(b"</pdml>") == 1

    text = [b"Frame 1: 54 bytes on wire", b"    Encapsulation type: Ethernet (1)", b""]
    data, packets = _write("text", [text, [b"Frame 2: 60 bytes on wire", b""]])
    assert packets == 2 and data.startswith(b"Frame 1:")
    with pytest.raises(InvalidParamsError):
        DissectionWriter("xml", io.BytesIO())


def _export(svc: PcapService, ctx: RequestContext, dest: Path, **params: Any) -> dict[str, Any]:
    return svc.export({"kind": "dissections", "dest": str(dest), **params}, ctx)


@pytest.mark.tshark
def test_export_dissections(opened: PcapService, ctx: RequestContext, tmp_path: Path) -> None:
    opened.set_filter({"expr": "http"}, ctx)
    res = _export(opened, ctx, tmp_path / "http.txt")  # default: text, the displayed packets
    text = (tmp_path / "http.txt").read_text()
    assert (res["packets"], res["format"], res["filter"]) == (2, "text", "http")
    assert text.startswith("Frame 4: ") and "Hypertext Transfer Protocol" in text
    assert "\n0000  " not in text, "no bytes unless asked"
    res = _export(opened, ctx, tmp_path / "http-bytes.txt", bytes=True)
    assert "\n0000  " in (tmp_path / "http-bytes.txt").read_text()

    res = _export(opened, ctx, tmp_path / "all.pdml", format="pdml", filter="")
    assert res["packets"] == 11 and _pdml_packets((tmp_path / "all.pdml").read_bytes()) == 11

    res = _export(opened, ctx, tmp_path / "http.json", format="json")
    packets = json.loads((tmp_path / "http.json").read_text())
    assert res["packets"] == 2 and _frame_numbers(packets) == ["4", "7"]

    with pytest.raises(FilterError):
        _export(opened, ctx, tmp_path / "bad.txt", filter="tcp.port ==")
    with pytest.raises(InvalidParamsError):
        _export(opened, ctx, tmp_path / "bad.txt", format="html")
    assert not list(tmp_path.glob(".*.part")), "nothing half-written is left"


@pytest.mark.tshark
def test_export_dissections_of_many_frames_in_chunks(
    opened: PcapService, ctx: RequestContext, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Six scattered frames, and a filter limit that fits two per pass.
    monkeypatch.setattr(pcap_service, "MAX_FILTER_ARG", 30)
    frames = [1, 3, 5, 7, 9, 11]
    for fmt, count in (("json", lambda p: len(json.loads(p.read_text()))),
                       ("pdml", lambda p: _pdml_packets(p.read_bytes())),
                       ("text", lambda p: p.read_text().count("\nFrame ") + 1)):  # fmt: skip
        dest = tmp_path / f"sel.{fmt}"
        res = _export(opened, ctx, dest, format=fmt, frames=frames)
        assert (res["packets"], res["filter"], count(dest)) == (6, "selected packets", 6), fmt
    data = json.loads((tmp_path / "sel.json").read_text())
    assert _frame_numbers(data) == [str(n) for n in frames]

    opened.mark_packets({"frames": [2, 4]}, ctx)
    res = _export(opened, ctx, tmp_path / "marked.json", format="json", marked=True)
    assert res["packets"] == 2 and res["filter"] == "marked packets"
