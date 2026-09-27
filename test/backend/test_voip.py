"""VoIP analysis: RTP streams, SIP calls, RTP stream analysis and audio."""

import itertools
import sys
import wave
from array import array
from pathlib import Path
from typing import Any

import pytest

from pcap_backend import voip
from pcap_backend.pcap_service import PcapService
from pcap_backend.protocol import InvalidParamsError, RequestContext

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures"
sys.path.insert(0, str(FIXTURES))
import generate  # noqa: E402 - the fixture generator's G.711 encoder and constants

# tshark 4.2's report for voip.pcap (the jitter columns are one space apart).
RTP_STREAMS_REPORT = """\
========================= RTP Streams ========================
   Start time      End time     Src IP addr  Port    Dest IP addr  Port       SSRC          Payload  Pkts         Lost   Min Delta(ms)  Mean Delta(ms)   Max Delta(ms)  Min Jitter(ms) Mean Jitter(ms)  Max Jitter(ms) Problems?
     1.021295      2.002918        10.0.0.1 40000        10.0.0.2 50000 0x11111111            g711U    49     1 (2.0%)          16.281          20.450          42.318           0.043           0.992           1.406 X
     1.021000      2.001000        10.0.0.2 50000        10.0.0.1 40000 0x22222222            g711U    50     0 (0.0%)          20.000          20.000          20.000           0.000           0.000           0.000
     3.000000      4.000000      2001:db8::1  5004     2001:db8::2  5006 0xDEADBEEF  RTPType-96, g729   10    -2 (-20.0%)          20.000          20.000          20.000           0.000           0.000           0.000
==============================================================
"""  # noqa: E501


def _sip_lines(*rows: list[str]) -> str:
    """-T fields lines of SIP_FIELDS from short rows (missing cells empty)."""
    width = len(voip.SIP_FIELDS)
    return "\n".join("\t".join(row + [""] * (width - len(row))) for row in rows)


def _sip(frame: int, time: float, src: str, dst: str, call_id: str, **kw: str) -> list[str]:
    cells = dict.fromkeys(voip.SIP_FIELDS, "")
    cells.update({
        "frame.number": str(frame), "frame.time_relative": str(time), "ip.src": src,
        "ip.dst": dst, "sip.Call-ID": call_id,
    })  # fmt: skip
    for key, value in kw.items():
        cells[{
            "method": "sip.Method", "code": "sip.Status-Code", "line": "sip.Status-Line",
            "cseq": "sip.CSeq.method", "from_user": "sip.from.user", "to_user": "sip.to.user",
            "sdp_addr": "sdp.connection_info.address", "sdp_port": "sdp.media.port",
        }[key]] = value  # fmt: skip
    return [cells[f] for f in voip.SIP_FIELDS]


def _zero_crossing_hz(samples: array[int], rate: int) -> float:
    crossings = sum(1 for a, b in itertools.pairwise(samples) if (a < 0) != (b < 0))
    return crossings / 2 / (len(samples) / rate)


# ---------------------------------------------------------------------- pure


def test_rtp_streams_report_is_parsed_whatever_the_column_spacing() -> None:
    first, second, v6 = voip.parse_rtp_streams(RTP_STREAMS_REPORT)
    assert first["src"] == "10.0.0.1" and first["srcPort"] == 40000
    assert (first["dst"], first["dstPort"], first["ssrc"]) == ("10.0.0.2", 50000, "0x11111111")
    assert (first["packets"], first["lost"], first["lostPercent"]) == (49, 1, 2.0)
    assert (first["maxDelta"], first["meanJitter"], first["maxJitter"]) == (42.318, 0.992, 1.406)
    assert first["problem"] is True and second["problem"] is False
    assert first["start"] == 1.021295 and first["payload"] == "g711U"
    assert first["filter"] == (
        "rtp.ssrc == 0x11111111 && ip.src == 10.0.0.1 && udp.srcport == 40000 && "
        "ip.dst == 10.0.0.2 && udp.dstport == 50000"
    )
    # IPv6, a payload name with spaces and more packets than expected (duplicates).
    assert v6["payload"] == "RTPType-96, g729" and v6["lost"] == -2
    assert v6["ssrc"] == "0xdeadbeef" and v6["filter"].startswith("rtp.ssrc == 0xdeadbeef && ipv6")


def test_stream_keys_from_the_client_are_checked() -> None:
    """The key goes into a display filter: nothing but addresses and numbers."""
    good = {"src": "10.0.0.1", "srcPort": 1, "dst": "::1", "dstPort": 2, "ssrc": "0x10"}
    assert voip.StreamKey.from_json(good).ssrc == 16
    for bad in (
        {**good, "src": "10.0.0.1 || frame"},
        {**good, "dst": 'a" or "b'},
        {**good, "srcPort": 70000},
        {**good, "ssrc": "0x1ffffffff"},
        {**good, "ssrc": "nope"},
        {key: value for key, value in good.items() if key != "dst"},
        "not an object",
    ):
        with pytest.raises(InvalidParamsError):
            voip.StreamKey.from_json(bad)


def test_sip_call_states() -> None:
    text = _sip_lines(
        _sip(1, 0.0, "a", "b", "c1", method="INVITE", from_user="alice", to_user="bob"),
        _sip(2, 0.1, "b", "a", "c1", code="180", line="SIP/2.0 180 Ringing", cseq="INVITE"),
        _sip(3, 0.5, "a", "b", "c1", method="CANCEL"),
        _sip(
            4, 0.6, "b", "a", "c1", code="487", line="SIP/2.0 487 Request Terminated", cseq="INVITE"
        ),
        _sip(5, 1.0, "a", "b", "c2", method="INVITE"),
        _sip(6, 1.1, "b", "a", "c2", code="200", line="SIP/2.0 200 OK", cseq="INVITE"),
        _sip(7, 2.0, "a", "r", "reg", method="REGISTER"),
        _sip(8, 3.0, "a", "b", 'odd"id\\', method="INVITE"),
    )
    cancelled, in_call, odd = voip.parse_sip_calls(text, [])
    assert cancelled["state"] == "Cancelled" and cancelled["from"] == "alice"
    assert cancelled["setup"] is None and cancelled["duration"] is None
    assert [m[4] for m in cancelled["messages"]] == [
        "INVITE", "180 Ringing", "CANCEL", "487 Request Terminated",
    ]  # fmt: skip
    assert in_call["state"] == "In call" and in_call["setup"] == pytest.approx(0.1)
    assert odd["state"] == "Calling"
    assert odd["filter"] == 'sip.Call-ID == "odd\\"id\\\\"', "quotes and backslashes escaped"


def test_g711_tables() -> None:
    assert voip.ULAW[0xFF] == 0 and voip.ULAW[0x7F] == 0
    assert voip.ULAW[0x00] == -32124 and voip.ULAW[0x80] == 32124
    assert voip.ALAW[0xD5] == 8 and voip.ALAW[0x55] == -8
    assert voip.ALAW[0xAA] == 32256 and voip.ALAW[0x2A] == -32256
    for sample in range(-32000, 32001, 997):
        decoded = voip.ULAW[generate.ulaw_encode(sample)]
        assert abs(decoded - sample) <= abs(sample) / 16 + 8, sample


def test_sequence_numbers_wrap_around() -> None:
    lines = [
        f"{i + 1}\t{100 + i * 0.02:.3f}\t{seq}\t{i * 160}\tFalse\t0"
        for i, seq in enumerate([65534, 65535, 0, 1, 3, 2])
    ]
    result = voip.analyse_stream(lines)
    statuses = [p[7] for p in result["points"]]
    assert statuses == [voip.OK, voip.OK, voip.OK, voip.OK, voip.SEQUENCE_GAP, voip.OUT_OF_ORDER]
    assert result["points"][4][8] == 1, "one packet missing before seq 3"
    assert result["summary"]["expected"] == 6 and result["summary"]["lost"] == 0


def test_audio_needs_g711_and_raw_payload_keeps_sequence_order() -> None:
    with pytest.raises(ValueError, match="payload type 18"):
        voip.decode_audio([(1, 0, 18, b"\x00" * 20)])
    packets = [(2, 160, 18, b"b"), (1, 0, 18, b"a"), (2, 160, 18, b"b"), (3, 320, 18, b"c")]
    assert voip.raw_payload(packets) == b"abc"
    # DTMF events in a G.711 stream are skipped, duplicates dropped.
    audio = voip.decode_audio([(1, 0, 0, b"\xff" * 160), (2, 160, 101, b"\x00" * 4),
                               (1, 0, 0, b"\xff" * 160), (3, 320, 0, b"\xff" * 160)])  # fmt: skip
    assert (audio.packets, audio.skipped, audio.silence) == (2, 1, 160)
    assert len(audio.samples) == 480


# ---------------------------------------------------------------------- with tshark


@pytest.fixture
def voip_open(service: PcapService, ctx: RequestContext) -> PcapService:
    service.open({"path": str(FIXTURES / "voip.pcap")}, ctx)
    return service


def _streams(svc: PcapService, ctx: RequestContext) -> dict[int, dict[str, Any]]:
    """The fixture's streams by source port (40000: alice's, 50000: bob's)."""
    return {s["srcPort"]: s for s in svc.voip_calls({}, ctx)["streams"]}


@pytest.mark.tshark
def test_calls_and_streams(voip_open: PcapService, ctx: RequestContext) -> None:
    result = voip_open.voip_calls({}, ctx)
    streams = {s["srcPort"]: i for i, s in enumerate(result["streams"])}
    alice = result["streams"][streams[40000]]
    assert (alice["packets"], alice["lost"], alice["payload"]) == (49, 1, "g711U")
    assert alice["maxJitter"] > 0 and alice["problem"] is True
    call, busy = result["calls"]
    assert (call["from"], call["to"], call["state"]) == (
        "alice@10.0.0.1", "bob@10.0.0.2", "Completed",
    )  # fmt: skip
    assert (call["caller"], call["callee"]) == (generate.ALICE, generate.BOB)
    assert call["setup"] == pytest.approx(1.0) and call["duration"] == pytest.approx(1.07)
    assert [m[4] for m in call["messages"]] == [
        "INVITE (SDP)", "100 Trying", "180 Ringing", "200 OK (SDP)", "ACK", "BYE", "200 OK",
    ]  # fmt: skip
    assert sorted(call["streams"]) == sorted(streams.values()), "both streams belong to it"
    assert (busy["state"], busy["reason"], busy["streams"]) == ("Rejected", "486 Busy Here", [])
    # The call's filter shows its signalling and its media.
    shown = voip_open.set_filter({"expr": call["filter"]}, ctx)
    assert shown["matchCount"] == 7 + 2 * generate.RTP_PACKETS - 1
    assert voip_open.voip_calls({}, ctx) is result, "cached"


@pytest.mark.tshark
def test_stream_analysis_matches_tshark(voip_open: PcapService, ctx: RequestContext) -> None:
    alice = _streams(voip_open, ctx)[40000]
    result = voip_open.rtp_stream({"stream": alice}, ctx)
    summary = result["summary"]
    assert (summary["packets"], summary["expected"], summary["lost"]) == (49, 50, 1)
    assert summary["maxJitter"] == pytest.approx(alice["maxJitter"], abs=0.002)
    assert summary["meanJitter"] == pytest.approx(alice["meanJitter"], abs=0.002)
    assert summary["maxDelta"] == pytest.approx(alice["maxDelta"], abs=0.002)
    (gap,) = [p for p in result["points"] if p[7] == voip.SEQUENCE_GAP]
    assert gap[2] == 1000 + generate.RTP_LOST + 1 and gap[8] == 1
    assert result["points"][0][6] == 1, "the first packet has the marker bit"
    assert result["filter"] == alice["filter"]


@pytest.mark.tshark
def test_saving_audio(voip_open: PcapService, ctx: RequestContext, tmp_path: Path) -> None:
    streams = _streams(voip_open, ctx)
    for port, tone in ((40000, generate.RTP_TONES[0]), (50000, generate.RTP_TONES[1])):
        dest = tmp_path / f"{port}.wav"
        result = voip_open.rtp_audio({"stream": streams[port], "dest": str(dest)}, ctx)
        assert result["codec"] == "G.711 µ-law" and result["seconds"] == pytest.approx(1.0)
        with wave.open(str(dest), "rb") as wav:
            assert (wav.getnchannels(), wav.getsampwidth(), wav.getframerate()) == (1, 2, 8000)
            samples = array("h", wav.readframes(wav.getnframes()))
        if sys.byteorder == "big":
            samples.byteswap()
        lost = port == 40000
        assert result["silence"] == pytest.approx(0.02 if lost else 0.0)
        # Only the lost packet's 20 ms are silent (the tone never crosses zero for that long).
        quiet = [i for i in range(0, len(samples), 160) if not any(samples[i : i + 160])]
        assert quiet == ([160 * generate.RTP_LOST] if lost else [])
        audible = array("h", samples[: 160 * generate.RTP_LOST])
        assert _zero_crossing_hz(audible, 8000) == pytest.approx(tone, rel=0.03)
    raw = voip_open.rtp_audio(
        {"stream": streams[40000], "dest": str(tmp_path / "a.raw"), "format": "raw"}, ctx
    )
    assert raw["bytes"] == (tmp_path / "a.raw").stat().st_size == 49 * 160


@pytest.mark.tshark
def test_bad_audio_requests(voip_open: PcapService, ctx: RequestContext, tmp_path: Path) -> None:
    stream = _streams(voip_open, ctx)[40000]
    with pytest.raises(InvalidParamsError, match="absolute"):
        voip_open.rtp_audio({"stream": stream, "dest": "relative.wav"}, ctx)
    with pytest.raises(InvalidParamsError, match="format"):
        voip_open.rtp_audio({"stream": stream, "dest": str(tmp_path / "x"), "format": "mp3"}, ctx)
    with pytest.raises(InvalidParamsError, match="open capture"):
        voip_open.rtp_audio({"stream": stream, "dest": str(FIXTURES / "voip.pcap")}, ctx)
    # A stream with no packets (wrong SSRC): nothing to save.
    ghost = {**stream, "ssrc": "0x12345678"}
    with pytest.raises(InvalidParamsError, match="no packets"):
        voip_open.rtp_audio({"stream": ghost, "dest": str(tmp_path / "g.wav")}, ctx)
    assert not (tmp_path / "g.wav").exists()


@pytest.mark.tshark
def test_heuristic_rtp_finds_streams_without_signalling(
    service: PcapService, ctx: RequestContext, tmp_path: Path
) -> None:
    """Without the SIP messages tshark only finds the RTP heuristically."""
    from scapy.utils import wrpcap  # noqa: PLC0415 - dev dependency, this test only

    media = [p for p in generate.voip_packets() if p.haslayer("RTP")]
    wrpcap(str(tmp_path / "rtp-only.pcap"), media)
    service.open({"path": str(tmp_path / "rtp-only.pcap")}, ctx)
    assert service.voip_calls({}, ctx)["streams"] == []
    found = service.voip_calls({"heuristic": True}, ctx)["streams"]
    assert sorted(s["srcPort"] for s in found) == [40000, 50000]
    assert all(s["heuristic"] for s in found)
    analysis = service.rtp_stream({"stream": found[0]}, ctx)
    assert analysis["summary"]["packets"] in (49, 50)
