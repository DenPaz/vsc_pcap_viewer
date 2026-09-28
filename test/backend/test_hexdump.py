import pytest

from pcap_backend import hexdump
from pcap_backend.protocol import InvalidParamsError


def test_defaults_are_hex_offsets_ethernet_and_the_largest_packet() -> None:
    assert hexdump.text2pcap_options({}) == ["-o", "hex", "-l", "1", "-m", "262144"]


def test_input_options() -> None:
    options = hexdump.text2pcap_options(
        {
            "offsets": "none",
            "timestamp": "%H:%M:%S.%f",
            "direction": True,
            "asciiDump": True,
            "linkType": 101,
            "maxPacket": "1500",
            "interfaceName": "dump",
        }
    )
    assert options == [
        "-o", "none", "-t", "%H:%M:%S.%f", "-D", "-a", "-l", "101", "-m", "1500", "-N", "dump",
    ]  # fmt: skip


@pytest.mark.parametrize(
    ("params", "expected"),
    [
        ({"header": "ethernet", "ethertype": "0x86dd"}, ["-e", "0x86dd"]),
        ({"header": "ethernet", "ethertype": 2054}, ["-e", "0x806"]),
        ({"header": "ethernet"}, ["-e", "0x800"]),
        ({"header": "ip", "protocol": 47}, ["-i", "47"]),
        ({"header": "udp", "srcPort": 5060, "dstPort": "5061"}, ["-u", "5060,5061"]),
        ({"header": "tcp", "srcPort": 1, "dstPort": 80}, ["-T", "1,80"]),
        ({"header": "sctp", "srcPort": 30, "dstPort": 40, "tag": 34}, ["-s", "30,40,34"]),
        ({"header": "sctpData", "srcPort": 30, "dstPort": 40, "ppi": 46}, ["-S", "30,40,46"]),
        ({"header": "exportPdu", "dissector": "sip"}, ["-P", "sip"]),
        (
            {"header": "udp", "srcPort": 1, "dstPort": 2, "srcIp": "fe80::1", "dstIp": "fe80::2"},
            ["-u", "1,2", "-6", "fe80::1,fe80::2"],
        ),
        (
            {"header": "tcp", "srcIp": "10.0.0.1", "dstIp": "10.0.0.2"},
            ["-T", "0,0", "-4", "10.0.0.1,10.0.0.2"],
        ),
    ],
)
def test_dummy_headers(params: dict[str, object], expected: list[str]) -> None:
    options = hexdump.text2pcap_options(params)
    assert options[2 : 2 + len(expected)] == expected
    assert "-l" not in options  # text2pcap puts the dummy headers in Ethernet frames


@pytest.mark.parametrize(
    ("params", "message"),
    [
        ({"offsets": "binary"}, "offsets must be one of"),
        ({"header": "quic"}, "header must be one of"),
        ({"header": "udp", "srcPort": 70000}, "srcPort must be from 0 to 65535"),
        ({"header": "udp", "srcPort": "http"}, "srcPort must be a whole number"),
        ({"header": "udp", "srcPort": True}, "srcPort must be a whole number"),
        ({"header": "udp", "srcPort": 1.5}, "srcPort must be a whole number"),
        ({"header": "udp", "srcIp": "10.0.0.1"}, "must both be IP addresses"),
        ({"header": "udp", "srcIp": "10.0.0.1", "dstIp": "::1"}, "both be IPv4 or both IPv6"),
        ({"header": "ethernet", "srcIp": "10.0.0.1", "dstIp": "10.0.0.2"}, "need a dummy IP"),
        ({"header": "udp", "linkType": 101}, "needs the Ethernet link type"),
        ({"header": "exportPdu", "dissector": "sip;rm"}, "dissector must be"),
        ({"header": "exportPdu"}, "dissector must be"),
        ({"linkType": 70000}, "linkType must be from 0 to 65535"),
        ({"maxPacket": 0}, "maxPacket must be from 1"),
        ({"timestamp": "%H\n%M"}, "timestamp must be a single line"),
        ({"interfaceName": "x" * 65}, "interfaceName must be a single line"),
    ],
)
def test_invalid_options_are_rejected(params: dict[str, object], message: str) -> None:
    with pytest.raises(InvalidParamsError, match=message):
        hexdump.text2pcap_options(params)


def test_written_packets() -> None:
    stderr = "Input from: x\n\nRead 2 potential packets, wrote 2 packets (400 bytes).\n"
    assert hexdump.written_packets(stderr) == (2, 2)
    assert hexdump.written_packets("Read 1 potential packet, wrote 1 packet (3 bytes)") == (1, 1)
    assert hexdump.written_packets("text2pcap: something else") is None
