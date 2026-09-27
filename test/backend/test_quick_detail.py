"""Quick (approximate) packet detail: dissect only a window of packets before
the one asked for (cut out with editcap) and renumber the tree."""

import subprocess
from pathlib import Path
from typing import Any

import pytest

from pcap_backend import pcap_service, pdml, procs
from pcap_backend import tshark as ts
from pcap_backend.cancellation import CancelledError
from pcap_backend.pcap_service import PcapService
from pcap_backend.protocol import InvalidParamsError, RequestContext
from pcap_backend.tshark import ToolNotFoundError

# Fields whose values must match the exact view when the referenced frame is in the window.
COMPARED = (
    "frame.number",
    "frame.time_relative",
    "http.request_in",
    "tcp.analysis.acks_frame",
    "tcp.segment",
)


def _fields(
    tree: list[dict[str, Any]], out: list[tuple[str, str]] | None = None
) -> list[tuple[str, str]]:
    out = [] if out is None else out
    for node in tree:
        if node.get("name") in COMPARED:
            out.append((node["name"], node["show"]))
        _fields(node.get("children", []), out)
    return out


def test_renumber_tree() -> None:
    tree: list[dict[str, Any]] = [
        {"label": "Frame 5: 74 bytes on wire", "name": "frame", "proto": True, "children": [
            {"label": "Time since reference or first frame: 0.004000000 seconds",
             "name": "frame.time_relative", "show": "0.004000000"},
            {"label": "Frame Number: 5", "name": "frame.number", "show": "5"},
        ]},
        {"label": "Hypertext Transfer Protocol", "name": "http", "proto": True, "children": [
            {"label": "Request in frame: 2", "name": "http.request_in", "show": "2"},
            {"label": "Not a frame: 2", "name": "http.content_length", "show": "2"},
            {"label": "Out of window: 7", "name": "http.response_in", "show": "7"},
        ]},
        {"label": "2 Reassembled TCP Segments (491 bytes): #4(200), #5(291)", "name": "tcp.segments",
         "children": [{"label": "Frame: 4, payload: 0-199 (200 bytes)", "name": "tcp.segment", "show": "4"}]},
    ]  # fmt: skip
    framenum = {"http.request_in", "http.response_in", "tcp.segment"}
    pdml.renumber_tree(
        tree, offset=1000, window=5, is_framenum=framenum.__contains__, time_relative="12.5"
    )
    frame, http, segments = tree
    assert frame["label"] == "Frame 1005: 74 bytes on wire"
    assert frame["children"][0] == {
        "label": "Time since reference or first frame: 12.5 seconds",
        "name": "frame.time_relative",
        "show": "12.5",
    }
    assert (
        frame["children"][1]["show"] == "1005"
        and frame["children"][1]["label"] == "Frame Number: 1005"
    )
    assert [(n["show"], n["label"]) for n in http["children"]] == [
        ("1002", "Request in frame: 1002"),
        ("2", "Not a frame: 2"),  # not FT_FRAMENUM
        ("7", "Out of window: 7"),  # beyond the window: left alone
    ]
    assert segments["label"] == "2 Reassembled TCP Segments (491 bytes): #1004(200), #1005(291)"
    assert segments["children"][0]["label"] == "Frame: 1004, payload: 0-199 (200 bytes)"


@pytest.mark.tshark
@pytest.mark.parametrize("warm_catalog", [False, True], ids=["name-hints", "catalogue"])
@pytest.mark.parametrize(("number", "window"), [(7, 5), (11, 10), (9, 3)])
def test_quick_detail_matches_the_exact_one(
    opened: PcapService, ctx: RequestContext, number: int, window: int, warm_catalog: bool
) -> None:
    if warm_catalog:
        opened.field_index({"prefix": "tcp", "limit": 1}, ctx)
    quick = opened.packet_detail({"number": number, "mode": "quick", "window": window}, ctx)
    exact = opened.packet_detail({"number": number}, ctx)
    first = number - window + 1
    assert quick["approximate"] is True and quick["window"] == [first, number]
    assert "approximate" not in exact
    assert quick["tree"][0]["label"].startswith(f"Frame {number}:")
    # Every frame reference inside the window reads as in the exact view.
    in_window = [(n, v) for n, v in _fields(exact["tree"]) if not v.isdigit() or int(v) >= first]
    assert _fields(quick["tree"]) == in_window
    assert quick["sources"] == exact["sources"]


@pytest.mark.tshark
def test_quick_detail_loses_references_before_the_window(
    opened: PcapService, ctx: RequestContext
) -> None:
    # Packet 7 (HTTP response) refers to its request in packet 4.
    exact = dict(_fields(opened.packet_detail({"number": 7}, ctx)["tree"]))
    opened._details.clear()
    quick = dict(
        _fields(opened.packet_detail({"number": 7, "mode": "quick", "window": 2}, ctx)["tree"])
    )
    assert exact["http.request_in"] == "4" and "http.request_in" not in quick


@pytest.mark.tshark
def test_quick_detail_uses_the_exact_one_when_it_is_as_cheap(
    opened: PcapService, ctx: RequestContext
) -> None:
    whole = opened.packet_detail({"number": 5, "mode": "quick", "window": 10}, ctx)
    assert "approximate" not in whole, "the window starts at frame 1: that is the exact detail"
    assert opened._details.get(5) is whole
    exact = opened.packet_detail({"number": 9}, ctx)
    assert opened.packet_detail({"number": 9, "mode": "quick", "window": 3}, ctx) is exact  # cached


@pytest.mark.tshark
def test_quick_detail_is_cached_and_leaves_no_files(
    opened: PcapService, ctx: RequestContext
) -> None:
    first = opened.packet_detail({"number": 11, "mode": "quick", "window": 4}, ctx)
    assert opened.packet_detail({"number": 11, "mode": "quick", "window": 4}, ctx) is first
    work_dir = opened._work_dir
    assert work_dir is not None and not list(work_dir.glob("quick-*"))


@pytest.mark.tshark
def test_quick_detail_without_editcap(
    opened: PcapService, ctx: RequestContext, monkeypatch: pytest.MonkeyPatch
) -> None:
    real = pcap_service.find_tool

    def find_tool(exe: str, *args: Any, **kwargs: Any) -> Path:
        if exe == "editcap":
            raise ToolNotFoundError(exe, [])
        return real(exe, *args, **kwargs)

    monkeypatch.setattr(pcap_service, "find_tool", find_tool)
    res = opened.packet_detail({"number": 11, "mode": "quick", "window": 4}, ctx)
    assert res == {"number": 11, "unavailable": "editcap (part of Wireshark) was not found"}


@pytest.mark.tshark
def test_quick_detail_params_and_cancel(opened: PcapService) -> None:
    ctx = RequestContext()
    for bad in (
        {"mode": "fast"},
        {"mode": "quick", "window": 1},
        {"mode": "quick", "window": 5001},
    ):
        with pytest.raises(InvalidParamsError):
            opened.packet_detail({"number": 11, **bad}, ctx)
    ctx.token.cancel()
    with pytest.raises(CancelledError):
        opened.packet_detail({"number": 11, "mode": "quick", "window": 4}, ctx)
    assert opened._work_dir is not None and not list(opened._work_dir.glob("quick-*"))


@pytest.mark.tshark
@pytest.mark.parametrize(
    ("mode", "cancel_at"), [("quick", "editcap"), ("quick", "tshark"), ("exact", "tshark")]
)
def test_cancel_race_leaves_no_pipe_open(
    opened: PcapService, monkeypatch: pytest.MonkeyPatch, mode: str, cancel_at: str
) -> None:
    """The request is cancelled as a child starts (before editcap, or between
    the two parallel tshark runs), and every child has already exited and
    been reaped when its runner looks, which is the race that leaked pipes.
    When the request fails, every child is reaped with its pipes closed."""
    ctx = RequestContext()
    started: list[subprocess.Popen[bytes]] = []
    real_popen = ts._popen

    def popen(argv: Any, env: Any = None, stdin: Any = None) -> subprocess.Popen[bytes]:
        proc = real_popen(argv, env, stdin)
        started.append(proc)
        if cancel_at in Path(argv[0]).name:
            # Killed first: nothing reads its stdout yet, and a child blocked on
            # a full pipe (a few KiB on Windows) would never exit.
            procs.kill_process(proc)
            proc.wait()
            ctx.token.cancel()
        return proc

    monkeypatch.setattr(ts, "_popen", popen)
    with pytest.raises(CancelledError):
        opened.packet_detail({"number": 11, "mode": mode, "window": 4}, ctx)
    assert started
    for proc in started:
        assert proc.returncode is not None
        assert all(p is None or p.closed for p in (proc.stdin, proc.stdout, proc.stderr))
    assert len(ts.PROCESSES) == 0
    assert opened._work_dir is not None and not list(opened._work_dir.glob("quick-*"))
