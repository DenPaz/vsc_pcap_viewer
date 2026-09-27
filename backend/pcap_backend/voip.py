"""VoIP analysis: RTP streams, SIP calls, RTP stream analysis and G.711 audio.

* RTP streams come from tshark's ``-z rtp,streams`` report (packets, loss,
  delta and jitter per stream, as Wireshark computes them).
* SIP calls are built from one ``-T fields`` pass over the SIP messages:
  tshark has no call list report. A call is a Call-ID with an INVITE; its
  SDP offers/answers name the media endpoints that link RTP streams to it.
* The stream analysis follows one stream packet by packet (RFC 3550 jitter,
  sequence errors, skew), like Wireshark's RTP Stream Analysis.
* Audio: G.711 µ-law and A-law payloads are decoded to 16-bit PCM and
  written as a WAV file (stdlib ``wave``), with silence for lost packets.

Everything here is pure (text in, data out); the service runs tshark.
"""

import re
import sys
import wave
from array import array
from collections.abc import Iterable, Iterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, BinaryIO

from .protocol import InvalidParamsError
from .stats import _lines

# RTP timestamp clock rates of the static payload types (RFC 3551); dynamic
# types (96-127) use the SDP's rate, which we don't track: 8000 by default.
CLOCK_RATES = {
    0: 8000, 3: 8000, 4: 8000, 5: 8000, 6: 16000, 7: 8000, 8: 8000, 9: 8000,
    10: 44100, 11: 44100, 12: 8000, 13: 8000, 14: 90000, 15: 8000, 16: 11025,
    17: 22050, 18: 8000, 25: 90000, 26: 90000, 28: 90000, 31: 90000,
    32: 90000, 33: 90000, 34: 90000,
}  # fmt: skip
DEFAULT_CLOCK = 8000
PCMU, PCMA = 0, 8
# Longest silence inserted for missing audio; a bigger timestamp jump (a new
# talk spurt after a long pause, a reset) just continues the audio.
MAX_GAP_S = 10

# The per-packet analysis: [frame, time (s from the stream's first packet),
# seq, delta ms, jitter ms, skew ms, marker 0/1, status, packets missing before].
POINT_FIELDS = ["frame", "time", "seq", "delta", "jitter", "skew", "marker", "status", "gap"]
OK, SEQUENCE_GAP, OUT_OF_ORDER, PAYLOAD_CHANGED = 0, 1, 2, 3

SIP_FIELDS = [
    "frame.number",
    "frame.time_relative",
    "ip.src",
    "ipv6.src",
    "ip.dst",
    "ipv6.dst",
    "sip.Call-ID",
    "sip.Method",
    "sip.Status-Code",
    "sip.Status-Line",
    "sip.CSeq.method",
    "sip.from.user",
    "sip.from.host",
    "sip.to.user",
    "sip.to.host",
    "sdp.connection_info.address",
    "sdp.media.port",
]
RTP_FIELDS = [
    "frame.number",
    "frame.time_epoch",
    "rtp.seq",
    "rtp.timestamp",
    "rtp.marker",
    "rtp.p_type",
]
AUDIO_FIELDS = ["rtp.seq", "rtp.timestamp", "rtp.p_type", "rtp.payload"]
# The SIP pass joins repeated fields with this (Call-IDs may hold commas).
AGGREGATOR = "\x1e"

_STREAM_RE = re.compile(
    r"^\s*(?P<start>[\d.]+)\s+(?P<end>[\d.]+)\s+(?P<src>\S+)\s+(?P<sport>\d+)\s+"
    r"(?P<dst>\S+)\s+(?P<dport>\d+)\s+(?P<ssrc>0x[0-9A-Fa-f]+)\s+(?P<payload>.+?)\s+"
    r"(?P<packets>\d+)\s+(?P<lost>-?\d+)\s+\((?P<pct>-?[\d.]+)%\)\s*(?P<rest>.*)$"
)
# Report columns after "Lost" (their set depends on the tshark version).
_TAIL_KEYS = {
    "Min Delta(ms)": "minDelta",
    "Mean Delta(ms)": "meanDelta",
    "Max Delta(ms)": "maxDelta",
    "Min Jitter(ms)": "minJitter",
    "Mean Jitter(ms)": "meanJitter",
    "Max Jitter(ms)": "maxJitter",
}


# ---------------------------------------------------------------------- RTP streams


@dataclass(frozen=True, slots=True)
class StreamKey:
    """One RTP stream: its 5-tuple and SSRC (as the rtp,streams report has it)."""

    src: str
    src_port: int
    dst: str
    dst_port: int
    ssrc: int

    @classmethod
    def from_json(cls, raw: Any) -> StreamKey:
        if not isinstance(raw, dict):
            raise InvalidParamsError("stream must be an object")
        try:
            key = cls(
                str(raw["src"]),
                int(raw["srcPort"]),
                str(raw["dst"]),
                int(raw["dstPort"]),
                int(str(raw["ssrc"]), 0),
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise InvalidParamsError(f"bad stream: {exc}") from exc
        for addr in (key.src, key.dst):
            if not re.fullmatch(r"[0-9A-Fa-f.:]+", addr):
                raise InvalidParamsError(f"bad address {addr!r}")
        if not (0 <= key.src_port < 65536 and 0 <= key.dst_port < 65536 and 0 <= key.ssrc < 2**32):
            raise InvalidParamsError("stream ports or SSRC out of range")
        return key

    def to_json(self) -> dict[str, Any]:
        return {
            "src": self.src,
            "srcPort": self.src_port,
            "dst": self.dst,
            "dstPort": self.dst_port,
            "ssrc": f"0x{self.ssrc:08x}",
        }

    def filter(self) -> str:
        """A display filter for the stream's packets."""
        ip = "ipv6" if ":" in self.src else "ip"
        return (
            f"rtp.ssrc == 0x{self.ssrc:08x} && {ip}.src == {self.src} && "
            f"udp.srcport == {self.src_port} && {ip}.dst == {self.dst} && "
            f"udp.dstport == {self.dst_port}"
        )


def parse_rtp_streams(text: str) -> list[dict[str, Any]]:
    """Rows of tshark's ``-z rtp,streams`` report: the stream (``src``,
    ``srcPort``, ``dst``, ``dstPort``, ``ssrc``), ``start``/``end`` (seconds
    from the first packet), ``payload``, ``packets``, ``lost``, ``lostPercent``,
    the delta and jitter columns in ms, and ``problem`` (tshark's X)."""
    tail: list[str] = []
    streams: list[dict[str, Any]] = []
    for line in _lines(text):
        if "SSRC" in line and "Payload" in line and "Lost" in line:
            # (Some names are one space apart: "Min Jitter(ms) Mean Jitter(ms)".)
            tail = re.findall(r"[A-Z][a-z]+ [A-Za-z]+\(ms\)", line)
            continue
        m = _STREAM_RE.match(line)
        if m is None:
            continue
        rest = m["rest"].split()
        problem = bool(rest) and rest[-1] == "X"
        numbers = rest[:-1] if problem else rest
        key = StreamKey(m["src"], int(m["sport"]), m["dst"], int(m["dport"]), int(m["ssrc"], 16))
        row: dict[str, Any] = {
            **key.to_json(),
            "start": float(m["start"]),
            "end": float(m["end"]),
            "payload": m["payload"].strip(),
            "packets": int(m["packets"]),
            "lost": int(m["lost"]),
            "lostPercent": float(m["pct"]),
            "problem": problem,
            "filter": key.filter(),
        }
        for name, value in zip(tail, numbers, strict=False):
            if name in _TAIL_KEYS:
                try:
                    row[_TAIL_KEYS[name]] = float(value)
                except ValueError:
                    continue
        streams.append(row)
    return streams


# ---------------------------------------------------------------------- SIP calls


@dataclass(slots=True)
class _Call:
    call_id: str
    caller: str
    callee: str
    from_uri: str
    to_uri: str
    start: float
    state: str = "Calling"
    answered: float | None = None
    ended: float | None = None
    last: float = 0.0
    reason: str = ""
    messages: list[list[Any]] = field(default_factory=list)
    media: set[tuple[str, int]] = field(default_factory=set)


def _uri(user: str, host: str) -> str:
    return f"{user}@{host}" if user and host else user or host


def parse_sip_calls(text: str, streams: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """SIP calls (Call-IDs with an INVITE) from a ``-T fields`` pass with
    SIP_FIELDS (repeated fields joined with AGGREGATOR), in order of their
    first message: ``from``/``to`` (URIs),
    ``caller``/``callee`` (addresses of the first INVITE), ``state``
    (Calling, Ringing, In call, Completed, Rejected, Cancelled), ``start``,
    ``setup`` (INVITE → answer, s), ``duration`` (answer → BYE or the last
    message, s), ``messages`` [[frame, time, src, dst, label]], ``streams``
    (indexes into ``streams`` whose endpoints the call's SDP named) and a
    ``filter`` for the call's signalling and media."""
    calls: dict[str, _Call] = {}
    first_seen: list[str] = []
    for line in _lines(text):
        cells = line.split("\t")
        if len(cells) < len(SIP_FIELDS):
            continue
        frame, rel, src4, src6, dst4, dst6, call_id, method, code = cells[:9]
        status_line, cseq_method, from_user, from_host, to_user, to_host = cells[9:15]
        sdp_addr, sdp_port = cells[15:17]
        if not call_id or not frame.isdigit():
            continue
        call_id = call_id.split(AGGREGATOR)[0]
        try:
            time = float(rel)
        except ValueError:
            continue
        src, dst = src4 or src6, dst4 or dst6
        call = calls.get(call_id)
        if call is None:
            if method != "INVITE":
                first_seen.append(call_id)  # (REGISTER, OPTIONS…: not calls)
                continue
            call = calls[call_id] = _Call(
                call_id, src, dst, _uri(from_user, from_host), _uri(to_user, to_host), time
            )
        call.last = time
        if method:
            label = method
            _request(call, method, time)
        else:
            label = status_line.removeprefix("SIP/2.0 ").strip() or code
            _response(call, code, cseq_method, label, time)
        if sdp_port:
            label += " (SDP)"
            addrs = [a for a in sdp_addr.split(AGGREGATOR) if a]
            for port in sdp_port.split(AGGREGATOR):
                if port.isdigit() and addrs:
                    call.media.add((addrs[-1], int(port)))
        call.messages.append([int(frame), time, src, dst, label])
    return [_call_json(i, call, streams) for i, call in enumerate(calls.values())]


def _request(call: _Call, method: str, time: float) -> None:
    if method == "BYE" and call.state in ("In call", "Calling", "Ringing"):
        call.state = "Completed" if call.answered is not None else "Cancelled"
        call.ended = time
    elif method == "CANCEL" and call.answered is None:
        call.state, call.ended = "Cancelled", time


def _response(call: _Call, code: str, cseq_method: str, label: str, time: float) -> None:
    if cseq_method != "INVITE" or not code.isdigit():
        return
    status = int(code)
    if status in (180, 183) and call.state == "Calling":
        call.state = "Ringing"
    elif 200 <= status < 300 and call.answered is None and call.state in ("Calling", "Ringing"):
        call.state, call.answered = "In call", time
    elif status >= 300 and call.answered is None:  # (a final failure)
        if call.state != "Cancelled":
            call.state = "Rejected"
        call.reason, call.ended = label, time


def _call_json(index: int, call: _Call, streams: list[dict[str, Any]]) -> dict[str, Any]:
    linked = [
        i
        for i, s in enumerate(streams)
        if (s["dst"], s["dstPort"]) in call.media or (s["src"], s["srcPort"]) in call.media
    ]
    end = call.ended if call.ended is not None else call.last
    if linked:
        end = max(end, *(streams[i]["end"] for i in linked))
    quoted = call.call_id.replace("\\", "\\\\").replace('"', '\\"')
    parts = [f'sip.Call-ID == "{quoted}"', *(f"({streams[i]['filter']})" for i in linked)]
    return {
        "id": index,
        "callId": call.call_id,
        "from": call.from_uri,
        "to": call.to_uri,
        "caller": call.caller,
        "callee": call.callee,
        "state": call.state,
        "reason": call.reason,
        "start": call.start,
        "setup": round(call.answered - call.start, 6) if call.answered is not None else None,
        "duration": round(end - call.answered, 6) if call.answered is not None else None,
        "messages": call.messages,
        "streams": linked,
        "filter": " || ".join(parts),
    }


# ---------------------------------------------------------------------- stream analysis


def _rows(text: str | Iterable[str], width: int) -> Iterator[list[str]]:
    for line in _lines(text) if isinstance(text, str) else text:
        cells = line.split("\t")
        if len(cells) >= width and cells[0]:
            yield cells[:width]


def _flag(cell: str) -> int:
    return 1 if cell in ("1", "True", "true") else 0


class _Extended:
    """Unwraps a 16-bit sequence number or 32-bit timestamp into a
    monotonic counter (RFC 3550 A.1), accepting late (older) values."""

    def __init__(self, bits: int) -> None:
        self.mod = 1 << bits
        self.half = self.mod >> 1
        self.cycles = 0
        self.max: int | None = None

    def __call__(self, value: int) -> int:
        if self.max is None:
            self.max = value
            return value
        diff = (value - self.max) % self.mod
        if diff < self.half:  # newer (or equal)
            if value < self.max:
                self.cycles += self.mod
            self.max = value
            return self.cycles + value
        # Older: in the previous cycle if it is "ahead" of max numerically.
        return self.cycles + value - (self.mod if value > self.max else 0)


class _StreamAnalysis:
    """The running state of analyse_stream (Wireshark's tap-rtp-analysis)."""

    def __init__(self) -> None:
        self.points: list[list[Any]] = []
        self.seq_ext, self.ts_ext = _Extended(16), _Extended(32)
        self.clock = DEFAULT_CLOCK
        self.payload_types: list[int] = []
        self.first_time = self.prev_time = 0.0
        self.first_ts = self.prev_transit = 0.0
        self.base_seq = self.max_seq = 0
        self.jitter = self.max_jitter = self.jitter_sum = 0.0
        self.max_delta = self.max_skew = 0.0
        self.max_delta_frame = self.errors = 0

    def packet(self, frame: int, arrival: float, seq: int, ts: int, marker: int, pt: int) -> None:
        eseq, ets = self.seq_ext(seq), self.ts_ext(ts)
        if pt not in self.payload_types:
            self.payload_types.append(pt)
        if not self.points:
            self.clock = CLOCK_RATES.get(pt, DEFAULT_CLOCK)
            self.first_time = self.prev_time = arrival
            self.first_ts = ets
            self.prev_transit = arrival * self.clock - ets
            self.base_seq = self.max_seq = eseq
            self.points.append([frame, 0.0, seq, 0.0, 0.0, 0.0, marker, OK, 0])
            return
        status, gap = self._sequence(eseq)
        if pt != self.payload_types[0] and status == OK:
            status = PAYLOAD_CHANGED
        if status != OK:
            self.errors += 1
        delta = (arrival - self.prev_time) * 1000
        transit = arrival * self.clock - ets
        self.jitter += (abs(transit - self.prev_transit) - self.jitter) / 16
        self.prev_transit, self.prev_time = transit, arrival
        jitter_ms = self.jitter * 1000 / self.clock
        skew = (ets - self.first_ts) * 1000 / self.clock - (arrival - self.first_time) * 1000
        if delta > self.max_delta:
            self.max_delta, self.max_delta_frame = delta, frame
        self.max_jitter = max(self.max_jitter, jitter_ms)
        self.max_skew = max(self.max_skew, abs(skew))
        self.jitter_sum += jitter_ms
        self.points.append([
            frame, round(arrival - self.first_time, 6), seq, round(delta, 3),
            round(jitter_ms, 3), round(skew, 3), marker, status, gap,
        ])  # fmt: skip

    def _sequence(self, eseq: int) -> tuple[int, int]:
        """(status, packets missing before) of a packet's extended sequence number."""
        if eseq == self.max_seq + 1:
            self.max_seq = eseq
            return OK, 0
        if eseq > self.max_seq:
            gap = eseq - self.max_seq - 1
            self.max_seq = eseq
            return SEQUENCE_GAP, gap
        return OUT_OF_ORDER, 0  # (late or duplicated)

    def summary(self) -> dict[str, Any]:
        received = len(self.points)
        expected = self.max_seq - self.base_seq + 1 if self.points else 0
        lost = expected - received
        return {
            "packets": received,
            "expected": expected,
            "lost": lost,
            "lostPercent": round(100 * lost / expected, 2) if expected else 0.0,
            "sequenceErrors": self.errors,
            "maxDelta": round(self.max_delta, 3),
            "maxDeltaFrame": self.max_delta_frame,
            "maxJitter": round(self.max_jitter, 3),
            "meanJitter": round(self.jitter_sum / (received - 1), 3) if received > 1 else 0.0,
            "maxSkew": round(self.max_skew, 3),
            "clockRate": self.clock,
            "payloadTypes": self.payload_types,
            "duration": self.points[-1][1] if self.points else 0.0,
        }


def analyse_stream(text: str | Iterable[str]) -> dict[str, Any]:
    """Per-packet analysis of one stream from a ``-T fields`` pass with
    RTP_FIELDS (its text or lines, in arrival order): ``points`` (see
    POINT_FIELDS) and a ``summary``: packets, expected, lost, lostPercent,
    sequenceErrors, maxDelta/maxDeltaFrame, maxJitter, meanJitter, maxSkew
    (ms), clockRate, payloadTypes, duration (s). Jitter is RFC 3550's running
    estimate, as Wireshark computes it."""
    analysis = _StreamAnalysis()
    for cells in _rows(text, len(RTP_FIELDS)):
        try:
            frame, arrival = int(cells[0]), float(cells[1])
            seq, ts, pt = int(cells[2]), int(cells[3]), int(cells[5])
        except ValueError:
            continue
        analysis.packet(frame, arrival, seq, ts, _flag(cells[4]), pt)
    return {"fields": POINT_FIELDS, "points": analysis.points, "summary": analysis.summary()}


# ---------------------------------------------------------------------- audio


def _ulaw(byte: int) -> int:
    byte = ~byte & 0xFF
    magnitude = ((((byte & 0x0F) << 3) + 0x84) << ((byte >> 4) & 0x07)) - 0x84
    return -magnitude if byte & 0x80 else magnitude


def _alaw(byte: int) -> int:
    byte ^= 0x55
    exponent, mantissa = (byte >> 4) & 0x07, byte & 0x0F
    magnitude = (
        (mantissa << 4) + 8 if exponent == 0 else ((mantissa << 4) + 0x108) << (exponent - 1)
    )
    return magnitude if byte & 0x80 else -magnitude


# 256-entry decoding tables (ITU-T G.711), 16-bit linear samples.
ULAW = array("h", (_ulaw(b) for b in range(256)))
ALAW = array("h", (_alaw(b) for b in range(256)))
CODECS = {PCMU: ("G.711 µ-law", ULAW), PCMA: ("G.711 A-law", ALAW)}


def _payload(cell: str) -> bytes:
    try:
        return bytes.fromhex(cell.replace(":", ""))
    except ValueError:
        return b""


def audio_packets(text: str | Iterable[str]) -> Iterator[tuple[int, int, int, bytes]]:
    """(seq, timestamp, payload type, payload) of a ``-T fields`` pass with
    AUDIO_FIELDS (its text or lines)."""
    for cells in _rows(text, len(AUDIO_FIELDS)):
        try:
            yield int(cells[0]), int(cells[1]), int(cells[2]), _payload(cells[3])
        except ValueError:
            continue


def raw_payload(packets: Iterable[tuple[int, int, int, bytes]]) -> bytes:
    """The payloads in sequence order, duplicates dropped (for codecs we
    can't decode: tools such as ffmpeg or sox read the raw bytes)."""
    seq_ext = _Extended(16)
    ordered: dict[int, bytes] = {}
    for seq, _ts, _pt, payload in packets:
        ordered.setdefault(seq_ext(seq), payload)
    return b"".join(ordered[k] for k in sorted(ordered))


@dataclass(slots=True)
class Audio:
    """Decoded audio of a stream: 16-bit mono PCM at ``rate``."""

    samples: array[int]
    rate: int
    codec: str
    packets: int
    silence: int  # samples inserted for missing packets
    skipped: int  # packets of another payload type (e.g. DTMF events)


def decode_audio(packets: Iterable[tuple[int, int, int, bytes]]) -> Audio:
    """Decode a G.711 stream in sequence order, placing each packet at its
    timestamp: missing packets become silence (up to MAX_GAP_S), duplicates
    are dropped. The stream's first G.711 payload type decides the codec;
    packets of other types are skipped. Raises ValueError when no packet is
    G.711 (other codecs can only be saved as raw payload)."""
    seq_ext, ts_ext = _Extended(16), _Extended(32)
    ordered: dict[int, tuple[int, int, bytes]] = {}
    codec_pt: int | None = None
    other_types: set[int] = set()
    skipped = 0
    for seq, ts, pt, payload in packets:
        eseq, ets = seq_ext(seq), ts_ext(ts)
        if codec_pt is None and pt in CODECS:
            codec_pt = pt
        if pt != codec_pt:
            skipped += 1
            other_types.add(pt)
            continue
        ordered.setdefault(eseq, (ets, pt, payload))
    if codec_pt is None:
        types = ", ".join(str(t) for t in sorted(other_types)) or "none"
        raise ValueError(
            f"only G.711 µ-law and A-law (payload types 0 and 8) can be played; "
            f"this stream has payload type {types}"
        )
    name, table = CODECS[codec_pt]
    rate = CLOCK_RATES[codec_pt]
    samples = array("h")
    silence = 0
    start: int | None = None
    for eseq in sorted(ordered):
        ets, _pt, payload = ordered[eseq]
        if start is None:
            start = ets
        offset = ets - start
        missing = offset - len(samples)
        if 0 < missing <= MAX_GAP_S * rate:
            samples.extend(array("h", bytes(2 * missing)))
            silence += missing
        elif missing < 0 and -missing >= len(payload):
            continue  # (all of it already played: a duplicate)
        samples.extend(table[b] for b in payload)
    return Audio(samples, rate, name, len(ordered), silence, skipped)


def write_wav(audio: Audio, out: BinaryIO | Path) -> None:
    """Write ``audio`` as a 16-bit mono WAV file (little-endian samples)."""
    data = array("h", audio.samples)
    if sys.byteorder == "big":
        data.byteswap()
    target = str(out) if isinstance(out, Path) else out
    with wave.open(target, "wb") as wav:
        wav.setnchannels(1)
        wav.setsampwidth(2)
        wav.setframerate(audio.rate)
        wav.writeframes(data.tobytes())
