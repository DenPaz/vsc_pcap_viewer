"""Generate the small synthetic capture files used by the test suites.

Usage (from the repository root)::

    uv run python test/fixtures/generate.py            # regenerate committed fixtures
    uv run python test/fixtures/generate.py --large 1000000 /tmp/big.pcap
    uv run python test/fixtures/generate.py --tls-keylog /tmp/tls.pcap /tmp/tls-keys.log

The committed fixtures are deterministic (fixed timestamps, addresses and
sequence numbers) so that tests can assert on exact values. ``formats/`` holds
the same packets in the other file types the viewer opens (compressed, snoop,
ERF, Bluetooth logs, generic extensions); those writers use only the standard
library, so their bytes never depend on a Wireshark version.
"""

import argparse
import gzip
import random
import ssl
import struct
from pathlib import Path

from scapy.layers.dns import DNS, DNSQR, DNSRR
from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.layers.l2 import ARP, Ether
from scapy.packet import Packet, Raw
from scapy.utils import wrpcap, wrpcapng

HERE = Path(__file__).resolve().parent
BASE_TS = 1_700_000_000.0  # 2023-11-14T22:13:20Z

CLIENT_MAC = "02:00:00:00:00:01"
SERVER_MAC = "02:00:00:00:00:02"


def _stamp(packets: list[Packet], start: float = BASE_TS, step: float = 0.001) -> list[Packet]:
    for i, pkt in enumerate(packets):
        pkt.time = start + i * step
    return packets


class _TcpSession:
    """Minimal TCP conversation builder that keeps sequence numbers consistent."""

    def __init__(self, client: str, server: str, sport: int, dport: int) -> None:
        self.client, self.server, self.sport, self.dport = client, server, sport, dport
        self.cseq, self.sseq = 1000, 5000
        self.packets: list[Packet] = []

    def _c(self, flags: str, payload: bytes = b"") -> None:
        pkt = (
            Ether(src=CLIENT_MAC, dst=SERVER_MAC)
            / IP(src=self.client, dst=self.server, id=len(self.packets) + 1)
            / TCP(
                sport=self.sport,
                dport=self.dport,
                flags=flags,
                seq=self.cseq,
                ack=self.sseq if "A" in flags else 0,
            )
        )
        if payload:
            pkt = pkt / Raw(payload)
        self.packets.append(pkt)
        self.cseq += len(payload) + (1 if ("S" in flags or "F" in flags) else 0)

    def _s(self, flags: str, payload: bytes = b"") -> None:
        pkt = (
            Ether(src=SERVER_MAC, dst=CLIENT_MAC)
            / IP(src=self.server, dst=self.client, id=len(self.packets) + 1)
            / TCP(sport=self.dport, dport=self.sport, flags=flags, seq=self.sseq, ack=self.cseq)
        )
        if payload:
            pkt = pkt / Raw(payload)
        self.packets.append(pkt)
        self.sseq += len(payload) + (1 if ("S" in flags or "F" in flags) else 0)

    def handshake(self) -> None:
        self.cseq -= 1  # SYN consumes the initial sequence number
        self._c("S")
        self.sseq -= 1
        self._s("SA")
        self._c("A")

    def client_send(self, data: bytes) -> None:
        self._c("PA", data)
        self._s("A")

    def server_send(self, *chunks: bytes) -> None:
        for chunk in chunks:
            self._s("PA", chunk)
        self._c("A")

    def close(self) -> None:
        self._c("FA")
        self._s("FA")
        self._c("A")


def http_packets() -> list[Packet]:
    s = _TcpSession("192.168.1.10", "93.184.216.34", 50000, 80)
    s.handshake()
    s.client_send(
        b"GET /index.html HTTP/1.1\r\nHost: example.com\r\nUser-Agent: pcap-viewer-test\r\n"
        b"Accept: */*\r\n\r\n"
    )
    body = b"<html><body>" + b"Hello, PCAP Viewer! " * 20 + b"</body></html>"
    headers = (
        b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n"
        + f"Content-Length: {len(body)}\r\n\r\n".encode()
    )
    response = headers + body
    # Split the response over two segments so tshark has to reassemble it.
    s.server_send(response[:200], response[200:])
    s.close()
    return _stamp(s.packets)


def dns_packets() -> list[Packet]:
    pkts: list[Packet] = []
    names = ["example.com", "wireshark.org", "nonexistent.invalid"]
    for i, name in enumerate(names):
        qid = 0x1000 + i
        q = (
            Ether(src=CLIENT_MAC, dst=SERVER_MAC)
            / IP(src="192.168.1.10", dst="8.8.8.8")
            / UDP(sport=40000 + i, dport=53)
            / DNS(id=qid, rd=1, qd=DNSQR(qname=name, qtype="A"))
        )
        if name.endswith(".invalid"):
            answer = DNS(id=qid, qr=1, rd=1, ra=1, rcode=3, qd=DNSQR(qname=name, qtype="A"))
        else:
            answer = DNS(
                id=qid,
                qr=1,
                rd=1,
                ra=1,
                qd=DNSQR(qname=name, qtype="A"),
                an=DNSRR(rrname=name, type="A", ttl=300, rdata=f"93.184.216.{34 + i}"),
            )
        r = (
            Ether(src=SERVER_MAC, dst=CLIENT_MAC)
            / IP(src="8.8.8.8", dst="192.168.1.10")
            / UDP(sport=53, dport=40000 + i)
            / answer
        )
        pkts += [q, r]
    return _stamp(pkts, step=0.01)


def udp_custom_packets() -> list[Packet]:
    """UDP/9999 traffic decoded by backend/dissectors/example.lua."""
    pkts: list[Packet] = []
    for i in range(6):
        msg_type = 1 + (i % 3)
        payload = struct.pack("!BBH", 1, msg_type, i) + f"message-{i}".encode()
        pkts.append(
            Ether(src=CLIENT_MAC, dst=SERVER_MAC)
            / IP(src="10.0.0.1", dst="10.0.0.2")
            / UDP(sport=12345, dport=9999)
            / Raw(payload)
        )
    return _stamp(pkts, step=0.1)


def tls_packets() -> list[Packet]:
    """A TCP handshake followed by a hand-built TLS 1.2 ClientHello with SNI."""
    sni = b"secure.example.com"
    server_name = struct.pack("!BH", 0, len(sni)) + sni
    sni_ext = (
        struct.pack("!HH", 0x0000, len(server_name) + 2)
        + struct.pack("!H", len(server_name))
        + server_name
    )
    extensions = sni_ext
    body = (
        b"\x03\x03"  # client_version TLS 1.2
        + bytes(range(32))  # random
        + b"\x00"  # session id length
        + struct.pack("!H", 4)
        + b"\xc0\x2f\x00\x9c"  # cipher suites
        + b"\x01\x00"  # compression methods: null
        + struct.pack("!H", len(extensions))
        + extensions
    )
    handshake = b"\x01" + struct.pack("!I", len(body))[1:] + body
    record = b"\x16\x03\x01" + struct.pack("!H", len(handshake)) + handshake
    s = _TcpSession("192.168.1.10", "93.184.216.34", 50443, 443)
    s.handshake()
    s.client_send(record)
    return _stamp(s.packets)


def mixed_packets() -> list[Packet]:
    extra: list[Packet] = [
        Ether(src=CLIENT_MAC, dst="ff:ff:ff:ff:ff:ff")
        / ARP(op=1, hwsrc=CLIENT_MAC, psrc="192.168.1.10", pdst="192.168.1.1"),
        Ether(src=CLIENT_MAC, dst=SERVER_MAC)
        / IP(src="192.168.1.10", dst="192.168.1.1")
        / ICMP(type=8, id=1, seq=1)
        / Raw(b"ping"),
        Ether(src=SERVER_MAC, dst=CLIENT_MAC)
        / IP(src="192.168.1.1", dst="192.168.1.10")
        / ICMP(type=0, id=1, seq=1)
        / Raw(b"ping"),
    ]
    pkts = extra + dns_packets() + http_packets() + udp_custom_packets()
    return _stamp(pkts, step=0.002)


def large_capture(count: int, dest: Path) -> None:
    """Write a big synthetic capture for manual performance testing (not committed).

    Builds a few hundred template packets with scapy, then writes pcap records
    directly so that millions of packets take seconds rather than minutes.
    """
    rng = random.Random(42)
    templates: list[bytes] = []
    for i in range(512):
        src = f"10.{rng.randrange(256)}.{rng.randrange(256)}.{rng.randrange(1, 255)}"
        if i % 3 == 0:
            pkt = (
                Ether()
                / IP(src=src, dst="10.0.0.1")
                / UDP(sport=rng.randrange(1024, 65535), dport=53)
                / DNS(id=i, qd=DNSQR(qname=f"host{i}.example.com"))
            )
        else:
            pkt = (
                Ether()
                / IP(src=src, dst="10.0.0.1")
                / TCP(sport=rng.randrange(1024, 65535), dport=80, flags="PA", seq=i)
                / Raw(b"x" * rng.randrange(0, 200))
            )
        templates.append(bytes(pkt))
    with dest.open("wb") as fh:
        fh.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        for i in range(count):
            data = templates[i % len(templates)]
            sec, usec = divmod(int(BASE_TS) * 1_000_000 + i * 100, 1_000_000)
            fh.write(struct.pack("<IIII", sec, usec, len(data), len(data)))
            fh.write(data)


# --------------------------------------------------------------------------- other formats

FORMATS = HERE / "formats"
BT_EPOCH_US = 0x00DCDDB30F2F8000  # btsnoop timestamps count microseconds from 0 AD


def _records(packets: list[Packet]) -> list[tuple[float, bytes]]:
    return [(float(p.time), bytes(p)) for p in packets]


def _xxh32(data: bytes, seed: int = 0) -> int:
    """xxHash32 (needed for the LZ4 frame header checksum)."""
    p1, p2, p3, p4, p5 = 2654435761, 2246822519, 3266489917, 668265263, 374761393
    mask = 0xFFFFFFFF

    def rotl(x: int, r: int) -> int:
        return ((x << r) | (x >> (32 - r))) & mask

    i, n = 0, len(data)
    if n >= 16:
        v = [(seed + p1 + p2) & mask, (seed + p2) & mask, seed, (seed - p1) & mask]
        while i + 16 <= n:
            for k in range(4):
                lane = struct.unpack_from("<I", data, i + 4 * k)[0]
                v[k] = (rotl((v[k] + lane * p2) & mask, 13) * p1) & mask
            i += 16
        h = (rotl(v[0], 1) + rotl(v[1], 7) + rotl(v[2], 12) + rotl(v[3], 18)) & mask
    else:
        h = (seed + p5) & mask
    h = (h + n) & mask
    while i + 4 <= n:
        h = (rotl((h + struct.unpack_from("<I", data, i)[0] * p3) & mask, 17) * p4) & mask
        i += 4
    while i < n:
        h = (rotl((h + data[i] * p5) & mask, 11) * p1) & mask
        i += 1
    h ^= h >> 15
    h = (h * p2) & mask
    h ^= h >> 13
    h = (h * p3) & mask
    return h ^ (h >> 16)


def lz4_frame(data: bytes) -> bytes:
    """An LZ4 frame holding ``data`` in stored (uncompressed) blocks: valid for any
    LZ4 reader without needing an LZ4 compressor here."""
    descriptor = bytes([0x60, 0x40])  # version 1, independent blocks; 64 KiB max block
    out = bytearray(struct.pack("<I", 0x184D2204) + descriptor)
    out.append((_xxh32(descriptor) >> 8) & 0xFF)
    for i in range(0, len(data), 64 * 1024):
        block = data[i : i + 64 * 1024]
        out += struct.pack("<I", 0x80000000 | len(block)) + block  # high bit: stored
    out += struct.pack("<I", 0)  # end mark
    return bytes(out)


def snoop_file(records: list[tuple[float, bytes]]) -> bytes:
    """RFC 1761 snoop, Ethernet."""
    out = bytearray(b"snoop\0\0\0" + struct.pack(">II", 2, 4))
    for ts, data in records:
        pad = -len(data) % 4
        sec, usec = divmod(round(ts * 1_000_000), 1_000_000)
        out += struct.pack(">IIIIII", len(data), len(data), 24 + len(data) + pad, 0, sec, usec)
        out += data + b"\0" * pad
    return bytes(out)


def erf_file(records: list[tuple[float, bytes]]) -> bytes:
    """Endace ERF, type 2 (Ethernet) records with the 2-byte Ethernet pad."""
    out = bytearray()
    for ts, data in records:
        sec, frac = divmod(round(ts * 2**32), 2**32)
        body = b"\0\0" + data
        pad = -(16 + len(body)) % 8
        rlen = 16 + len(body) + pad
        out += struct.pack("<Q", (sec << 32) | frac)
        out += struct.pack(">BBHHH", 2, 0x04, rlen, 0, len(data))  # 0x04: varying length
        out += body + b"\0" * pad
    return bytes(out)


# HCI traffic for the Bluetooth logs: Reset and Read BD_ADDR, each with its
# Command Complete event. (H4 packet type, HCI bytes.)
HCI_PACKETS: list[tuple[int, bytes]] = [
    (0x01, bytes.fromhex("030c00")),
    (0x04, bytes.fromhex("0e0401030c00")),
    (0x01, bytes.fromhex("091000")),
    (0x04, bytes.fromhex("0e0a01091000665544332211")),
]


def packetlogger_file() -> bytes:
    """Apple PacketLogger (.pklg): length, timestamp, type (0 command, 1 event), HCI."""
    out = bytearray()
    for i, (h4, hci) in enumerate(HCI_PACKETS):
        kind = 0x00 if h4 == 0x01 else 0x01
        out += struct.pack(">IIIB", 9 + len(hci), int(BASE_TS), i * 1000, kind) + hci
    return bytes(out)


def btsnoop_file() -> bytes:
    """btsnoop version 1, HCI UART (H4) datalink 1002."""
    out = bytearray(b"btsnoop\0" + struct.pack(">II", 1, 1002))
    for i, (h4, hci) in enumerate(HCI_PACKETS):
        data = bytes([h4]) + hci
        flags = 0b10 | (0 if h4 == 0x01 else 1)  # command/event; sent/received
        ts = BT_EPOCH_US + int(BASE_TS) * 1_000_000 + i * 1000
        out += struct.pack(">IIIIq", len(data), len(data), flags, 0, ts) + data
    return bytes(out)


def zstd_compress(data: bytes) -> bytes:
    """``compression.zstd`` is optional in CPython builds: Pythons compiled without
    the libzstd headers (e.g. pyenv without libzstd-dev) lack ``_zstd``, so it is
    imported only for the .zst fixtures, and ``--large`` works without it."""
    try:
        from compression import zstd  # noqa: PLC0415 - optional module, see above
    except ImportError as exc:
        raise SystemExit(
            f"This Python has no zstd support ({exc}), which the .zst fixtures need. "
            "Rebuild it with the libzstd headers (e.g. 'sudo apt install libzstd-dev', "
            "then 'pyenv install --force 3.14'), or use a uv-managed Python: "
            "'uv venv --python 3.14 --python-preference only-managed' then 'uv sync'."
        ) from exc
    return zstd.compress(data)


def format_fixtures() -> None:
    """Every extra file type the viewer registers for, from the base fixtures."""
    FORMATS.mkdir(exist_ok=True)
    pcap = (HERE / "http.pcap").read_bytes()
    pcapng = (HERE / "mixed.pcapng").read_bytes()
    files = {
        # Default editor: unambiguous capture files.
        "http.pcap.gz": gzip.compress(pcap, mtime=0),
        "mixed.pcapng.gz": gzip.compress(pcapng, mtime=0),
        "http.pcap.zst": zstd_compress(pcap),
        "mixed.pcapng.zst": zstd_compress(pcapng),
        "http.pcap.lz4": lz4_frame(pcap),
        "mixed.pcapng.lz4": lz4_frame(pcapng),
        "mixed.ntar": pcapng,  # pcapng's old extension
        "trace.pcap1": (HERE / "dns.pcap").read_bytes(),  # tcpdump -C rotation
        "http.snoop": snoop_file(_records(http_packets())),
        "http.erf": erf_file(_records(http_packets())),
        "hci.pklg": packetlogger_file(),
        "hci.btsnoop": btsnoop_file(),
        # "Reopen Editor With…" only: generic extensions that are sometimes captures.
        "capture.1": pcap,
        "capture.log": pcapng,
        "capture.dmp": pcap,
        "capture.trc": snoop_file(_records(http_packets())),
        # A raw ASN.1 BER file: tshark reads it as one frame. SEQUENCE { 5, "hello" }.
        "capture.ber": bytes.fromhex("300a020105040568656c6c6f"),
        # Not a capture at all: exercises the "unsupported format" message.
        "notes.log": b"2023-11-14 22:13:20 INFO this is a text log, not a capture\n",
    }
    for name, data in files.items():
        (FORMATS / name).write_bytes(data)


TLS_PSK = bytes.fromhex("00112233445566778899aabbccddeeff")


def _psk_context(server: bool, keylog: Path | None) -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER if server else ssl.PROTOCOL_TLS_CLIENT)
    ctx.minimum_version = ctx.maximum_version = ssl.TLSVersion.TLSv1_2
    ctx.set_ciphers("PSK-AES128-GCM-SHA256")
    if server:
        ctx.set_psk_server_callback(lambda _identity: TLS_PSK)
    else:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        ctx.set_psk_client_callback(lambda _hint: ("pcap-viewer", TLS_PSK))
        ctx.keylog_filename = str(keylog)
    return ctx


def tls_keylog_capture(dest: Path, keylog: Path) -> None:
    """A TLS 1.2 session carrying one HTTP request and response on port 443,
    plus the key log file (SSLKEYLOGFILE format) that decrypts it.

    Not committed: TLS randoms differ on every run. Both ends run in memory
    (``ssl.MemoryBIO``) with a pre-shared key, so no certificate is needed;
    the records they exchange become TCP segments.
    """
    keylog.unlink(missing_ok=True)
    c_in, c_out, s_in, s_out = (ssl.MemoryBIO() for _ in range(4))
    client = _psk_context(False, keylog).wrap_bio(c_in, c_out, server_side=False)
    server = _psk_context(True, None).wrap_bio(s_in, s_out, server_side=True)
    session = _TcpSession("192.168.1.10", "93.184.216.34", 50443, 443)
    session.handshake()

    def pump() -> None:
        if data := c_out.read():
            session.client_send(data)
            s_in.write(data)
        if data := s_out.read():
            session.server_send(data)
            c_in.write(data)

    done = [False, False]
    for _ in range(20):
        for i, end in enumerate((client, server)):
            if not done[i]:
                try:
                    end.do_handshake()
                    done[i] = True
                except ssl.SSLWantReadError:
                    pass
        pump()
        if all(done):
            break
    client.write(b"GET /secret.html HTTP/1.1\r\nHost: example.com\r\n\r\n")
    pump()
    server.read(4096)
    body = b"<html>decrypted with the key log</html>"
    server.write(b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n")
    server.write(f"Content-Length: {len(body)}\r\n\r\n".encode() + body)
    pump()
    client.read(4096)
    session.close()
    wrpcap(str(dest), _stamp(session.packets))


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--large", nargs=2, metavar=("COUNT", "DEST"))
    parser.add_argument("--tls-keylog", nargs=2, metavar=("DEST", "KEYLOG"))
    args = parser.parse_args()
    if args.large:
        large_capture(int(args.large[0]), Path(args.large[1]))
        return
    if args.tls_keylog:
        tls_keylog_capture(Path(args.tls_keylog[0]), Path(args.tls_keylog[1]))
        return
    wrpcap(str(HERE / "http.pcap"), http_packets())
    wrpcap(str(HERE / "dns.pcap"), dns_packets())
    wrpcap(str(HERE / "udp_custom.pcap"), udp_custom_packets())
    wrpcap(str(HERE / "tls.pcap"), tls_packets())
    wrpcapng(str(HERE / "mixed.pcapng"), mixed_packets())
    # A truncated file to exercise malformed-capture handling.
    data = (HERE / "http.pcap").read_bytes()
    (HERE / "truncated.pcap").write_bytes(data[: len(data) - 30])
    format_fixtures()
    print(f"fixtures written to {HERE}")


if __name__ == "__main__":
    main()
