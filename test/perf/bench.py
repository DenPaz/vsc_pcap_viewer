"""Rough performance check of the backend against a large capture.

Usage::

    uv run python test/fixtures/generate.py --large 1000000 test/fixtures/large-1m.pcap
    uv run python test/perf/bench.py test/fixtures/large-1m.pcap

Reports wall time for each operation and the backend's peak RSS (tshark runs
as a child process and is reported separately).
"""

import argparse
import resource
import sys
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any

from pcap_backend.pcap_service import PcapService
from pcap_backend.protocol import RequestContext


def timed(label: str, fn: Callable[[], Any]) -> Any:
    start = time.perf_counter()
    result = fn()
    print(f"{label:<44} {time.perf_counter() - start:8.2f} s")
    return result


def rss_mb(who: int) -> float:
    kb = resource.getrusage(who).ru_maxrss
    return kb / 1024 if sys.platform != "darwin" else kb / (1024 * 1024)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("capture", type=Path)
    parser.add_argument("--filter", default="udp.dstport == 53")
    parser.add_argument(
        "--no-tcp-analysis",
        action="store_true",
        help="pass -o tcp.analyze_sequence_numbers:FALSE (the synthetic capture replays "
        "the same flows, which makes tshark's TCP analysis super-linear)",
    )
    args = parser.parse_args()

    svc = PcapService()
    ctx = RequestContext()
    prefs = {"tcp.analyze_sequence_numbers": False} if args.no_tcp_analysis else {}
    info = timed(
        "open (index pass)", lambda: svc.open({"path": str(args.capture), "prefs": prefs}, ctx)
    )
    frames = info["frames"]
    print(f"  frames={frames:,} size={info['size'] / 1e6:.0f} MB warnings={info['warnings']}")
    timed("list_packets offset=0 limit=200", lambda: svc.list_packets({"limit": 200}, ctx))
    timed(
        "list_packets middle page",
        lambda: svc.list_packets({"offset": frames // 2, "limit": 200}, ctx),
    )
    t0 = time.perf_counter()
    for i in range(1000):
        svc.list_packets({"offset": (i * 997) % max(1, frames - 200), "limit": 60}, ctx)
    print(f"{'1000 random scroll pages (60 rows)':<44} {time.perf_counter() - t0:8.2f} s")
    res = timed(f"set_filter {args.filter!r}", lambda: svc.set_filter({"expr": args.filter}, ctx))
    print(f"  matched={res['matchCount']:,}")
    timed(
        "set_filter (cached re-apply after clear)",
        lambda: (svc.set_filter({"expr": ""}, ctx), svc.set_filter({"expr": args.filter}, ctx)),
    )
    timed(
        "sort by Length desc (first page)",
        lambda: svc.list_packets({"limit": 200, "sort": {"field": "frame.len", "desc": True}}, ctx),
    )
    timed("packet_detail frame 10", lambda: svc.packet_detail({"number": 10}, ctx))
    timed("packet_detail last frame", lambda: svc.packet_detail({"number": frames}, ctx))
    print(
        f"peak RSS backend: {rss_mb(resource.RUSAGE_SELF):.0f} MB, "
        f"largest child (tshark): {rss_mb(resource.RUSAGE_CHILDREN):.0f} MB"
    )
    svc.shutdown()


if __name__ == "__main__":
    main()
