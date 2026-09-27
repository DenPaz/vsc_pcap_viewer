"""A stand-in for dumpcap, so live capture can be tested without capture rights.

Run it as ``PCAP_VIEWER_DUMPCAP='["python", ".../fake_dumpcap.py"]'``. It knows
the few dumpcap options the backend uses:

* ``-D -M``: two interfaces, fake0 and a loopback;
* ``-i IF -f FILTER -d``: rejects a filter containing "invalid" (the way
  dumpcap does: a message on stderr, exit code 0);
* ``-w -`` (``-c N``, ``-a duration:S``): "captures" the packets of a pcapng
  file (``FAKE_DUMPCAP_SOURCE``, default ``mixed.pcapng``), one block every
  ``FAKE_DUMPCAP_DELAY`` seconds (0.05), then stays idle until stopped
  (SIGINT, a kill, the packet count or the duration) and prints dumpcap's
  statistics, with ``FAKE_DUMPCAP_DROPS`` dropped packets (0).

``FAKE_DUMPCAP_FAIL`` makes it fail like dumpcap without permission, with
that message. Standard library only.
"""

import os
import struct
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
_PACKET_BLOCKS = {2, 3, 6}


def _blocks(data: bytes) -> list[tuple[int, bytes]]:
    out = []
    pos, endian = 0, "<"
    while pos + 12 <= len(data):
        if struct.unpack_from("<I", data, pos)[0] == 0x0A0D0D0A:
            (magic,) = struct.unpack_from("<I", data, pos + 8)
            endian = "<" if magic == 0x1A2B3C4D else ">"
        kind, total = struct.unpack_from(endian + "II", data, pos)
        out.append((kind, data[pos : pos + total]))
        pos += total
    return out


def _option(args: list[str], name: str) -> str | None:
    return args[args.index(name) + 1] if name in args[:-1] else None


def _stats(interface: str, packets: int) -> None:
    drops = int(os.environ.get("FAKE_DUMPCAP_DROPS", "0"))
    sys.stderr.write(
        f"\rPackets captured: {packets}\n"
        f"Packets received/dropped on interface '{interface}': {packets + drops}/{drops} "
        f"(pcap:0/dumpcap:{drops}/flushed:0/ps_ifdrop:0) (100.0%)\n"
    )
    sys.stderr.flush()


def capture(args: list[str]) -> int:
    interface = _option(args, "-i") or "fake0"
    sys.stderr.write(f"Capturing on '{interface}'\n")
    sys.stderr.flush()
    fail = os.environ.get("FAKE_DUMPCAP_FAIL")
    if fail:
        sys.stderr.write(f"dumpcap: {fail}\n")
        return 2
    if interface == "nosuch":
        sys.stderr.write('dumpcap: There is no device named "nosuch".\n(No such device exists)\n')
        return 1
    source = Path(os.environ.get("FAKE_DUMPCAP_SOURCE") or HERE / "mixed.pcapng")
    delay = float(os.environ.get("FAKE_DUMPCAP_DELAY", "0.05"))
    count = _option(args, "-c")
    limit = int(count) if count else None
    duration = next((float(a.split(":", 1)[1]) for a in args if a.startswith("duration:")), None)
    started = time.monotonic()
    out = sys.stdout.buffer
    packets = 0
    try:
        for kind, block in _blocks(source.read_bytes()):
            is_packet = kind in _PACKET_BLOCKS
            if is_packet:
                if limit is not None and packets >= limit:
                    break
                time.sleep(delay)
                if duration is not None and time.monotonic() - started >= duration:
                    break
                packets += 1
            out.write(block)
            out.flush()
        while (limit is None or packets < limit) and (
            duration is None or time.monotonic() - started < duration
        ):
            time.sleep(0.05)  # idle, like a quiet interface
    except KeyboardInterrupt:
        pass
    except BrokenPipeError:
        return 1
    _stats(interface, packets)
    return 0


def main() -> int:
    args = sys.argv[1:]
    if "-D" in args:
        sys.stdout.write("1. fake0\t\tFake Ethernet\t0\t10.0.0.1,fe80::1\tnetwork\t\n")
        sys.stdout.write("2. lo\t\tLoopback\t0\t127.0.0.1\tloopback\t\n")
        return 0
    if "-d" in args:
        interface = _option(args, "-i") or "fake0"
        expr = _option(args, "-f") or ""
        sys.stderr.write(f"Capturing on '{interface}'\n")
        if "invalid" in expr:
            sys.stderr.write(
                f"dumpcap: Invalid capture filter \"{expr}\" for interface '{interface}'.\n\n"
                "That string isn't a valid capture filter (can't parse filter expression: "
                "syntax error).\nSee the User's Guide for a description of the capture filter "
                "syntax.\n"
            )
        else:
            sys.stdout.write("(000) ret      #262144\n")
        return 0
    return capture(args)


if __name__ == "__main__":
    sys.exit(main())
