import pytest

from pcap_backend.pdml import PdmlError, parse_hexdump, parse_pdml

PDML = b"""<?xml version="1.0" encoding="utf-8"?>
<pdml version="0" creator="wireshark/4.2.2">
<packet>
  <proto name="geninfo" pos="0" showname="General information" size="60">
    <field name="num" pos="0" show="1" showname="Number" value="1" size="60"/>
  </proto>
  <proto name="frame" showname="Frame 1: 60 bytes" size="60" pos="0">
    <field name="frame.number" showname="Frame Number: 1" size="0" pos="0" show="1"/>
  </proto>
  <proto name="ip" showname="Internet Protocol Version 4, Src: 10.0.0.1" size="20" pos="14">
    <field name="ip.src" showname="Source Address: 10.0.0.1" size="4" pos="26"
           show="10.0.0.1" value="0a000001"/>
    <field name="ip.addr" showname="Address" hide="yes" size="4" pos="26" show="10.0.0.1"/>
    <field name="" show="Text item &lt;script&gt;" size="2" pos="30" value="0102"/>
    <field name="ip.flags" showname="Flags: 0x0" size="1" pos="20" show="0x00" value="00">
      <field name="ip.flags.df" showname=".0.. = Don&#x27;t fragment" size="1" pos="20"
             show="False"/>
    </field>
  </proto>
  <proto name="fake-field-wrapper">
    <field name="tcp.segments" showname="2 Reassembled TCP Segments (40 bytes)" size="40"
           pos="0" show="" value="">
      <field name="tcp.segment" showname="Frame: 1" size="0" pos="0" show="1"/>
    </field>
  </proto>
  <proto name="http" showname="Hypertext Transfer Protocol" size="40" pos="0">
    <field name="http.host" showname="Host: example.com" size="17" pos="16" show="example.com"/>
  </proto>
</packet>
</pdml>
"""


def test_parse_pdml_structure() -> None:
    tree = parse_pdml(PDML, source_count=2)
    labels = [n["label"] for n in tree]
    assert labels == [
        "Frame 1: 60 bytes",
        "Internet Protocol Version 4, Src: 10.0.0.1",
        "2 Reassembled TCP Segments (40 bytes)",
        "Hypertext Transfer Protocol",
    ]
    frame, ip, segments, http = tree
    assert frame["proto"] is True
    # size="0" fields carry no byte range.
    assert "pos" not in frame["children"][0]
    src = ip["children"][0]
    assert src == {
        "id": src["id"],
        "label": "Source Address: 10.0.0.1",
        "name": "ip.src",
        "show": "10.0.0.1",
        "value": "0a000001",
        "pos": 26,
        "size": 4,
        "src": 0,
    }
    # hidden fields are dropped, text items keep their (unescaped) text
    names = [c.get("name") for c in ip["children"]]
    assert "ip.addr" not in names
    assert ip["children"][1]["label"] == "Text item <script>"
    assert ip["children"][2]["children"][0]["label"] == ".0.. = Don't fragment"
    # reassembly moves subsequent items to the next byte source
    assert segments["src"] == 1
    assert http["src"] == 1
    assert http["children"][0]["src"] == 1
    ids = []

    def walk(nodes: list[dict]) -> None:  # type: ignore[type-arg]
        for n in nodes:
            ids.append(n["id"])
            walk(n.get("children", []))

    walk(tree)
    assert len(ids) == len(set(ids))


def test_parse_pdml_clamps_sources() -> None:
    tree = parse_pdml(PDML, source_count=1)
    assert {n["src"] for n in tree} == {0}


def test_parse_pdml_errors() -> None:
    with pytest.raises(PdmlError):
        parse_pdml(b"<pdml><packet>")
    assert parse_pdml(b"<pdml></pdml>") == []


HEX_SINGLE = """\
0000  02 00 00 00 00 02 02 00 00 00 00 01 08 00 45 00   ..............E.
0010  00 28 00 08                                       .(..

"""

HEX_MULTI = """\
Frame (18 bytes):
0000  02 00 00 00 00 02 02 00 00 00 00 01 08 00 45 00   ..............E.
0010  41 42                                             AB
Reassembled TCP (3 bytes):
0000  48 54 54                                          HTT
"""


def test_parse_hexdump_single_source() -> None:
    (src,) = parse_hexdump(HEX_SINGLE)
    assert src.name == "Frame"
    assert src.data.hex() == "020000000002020000000001080045000028" + "0008"


def test_parse_hexdump_multi_source() -> None:
    frame, reassembled = parse_hexdump(HEX_MULTI)
    assert frame.name == "Frame"
    assert len(frame.data) == 18
    assert reassembled.name == "Reassembled TCP"
    assert bytes(reassembled.data) == b"HTT"
    # ASCII column that looks like hex must not be parsed as bytes
    assert frame.to_json()["hex"].endswith("4142")


# tshark 4.6 names the packet's own bytes "Packet" (4.2/4.4: "Frame").
HEX_MULTI_46 = HEX_MULTI.replace("Frame (18 bytes):", "Packet (18 bytes):")


def test_parse_hexdump_first_source_is_frame_in_every_version() -> None:
    assert HEX_MULTI_46.startswith("Packet (18 bytes):\n")
    for text in (HEX_MULTI, HEX_MULTI_46):
        assert [s.name for s in parse_hexdump(text)] == ["Frame", "Reassembled TCP"]
    assert parse_hexdump(HEX_MULTI_46)[0].data == parse_hexdump(HEX_MULTI)[0].data


def test_parse_hexdump_ignores_ascii_lookalikes() -> None:
    text = "0000  41 42 43 44 45 46 30 31 32 33 34 35 36 37 38 39   ABCDEF0123456789\n"
    (src,) = parse_hexdump(text)
    assert bytes(src.data) == b"ABCDEF0123456789"
