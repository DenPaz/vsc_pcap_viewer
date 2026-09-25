"""JSON-RPC protocol tests: in-process with fake handlers, and end-to-end over stdio."""

from __future__ import annotations

import io
import json
import os
import queue
import subprocess
import sys
import threading
import time
from pathlib import Path
from typing import Any

import pytest

from pcap_backend.cancellation import CancelledError
from pcap_backend.protocol import InvalidParamsError, RequestContext
from pcap_backend.server import JsonRpcServer

BACKEND_DIR = Path(__file__).resolve().parents[2] / "backend"


class _Capture(io.RawIOBase):
    def __init__(self) -> None:
        self.lines: queue.Queue[dict[str, Any]] = queue.Queue()
        self._buf = b""

    def writable(self) -> bool:
        return True

    def write(self, b: Any) -> int:
        self._buf += bytes(b)
        while b"\n" in self._buf:
            line, self._buf = self._buf.split(b"\n", 1)
            self.lines.put(json.loads(line))
        return len(b)

    def next(self, timeout: float = 5) -> dict[str, Any]:
        return self.lines.get(timeout=timeout)


def _server(methods: dict[str, Any]) -> tuple[JsonRpcServer, _Capture]:
    out = _Capture()
    return JsonRpcServer(io.BytesIO(), out, methods), out  # type: ignore[arg-type]


def _send(server: JsonRpcServer, msg: dict[str, Any] | str) -> None:
    raw = msg if isinstance(msg, str) else json.dumps(msg)
    server.handle_line(raw.encode())


def test_request_response_and_errors() -> None:
    def echo(params: dict[str, Any], _ctx: RequestContext) -> Any:
        if "bad" in params:
            raise InvalidParamsError("bad param", {"why": 1})
        if "boom" in params:
            raise RuntimeError("kaboom")
        return {"echo": params}

    server, out = _server({"echo": echo})
    _send(server, {"jsonrpc": "2.0", "id": 1, "method": "echo", "params": {"x": 1}})
    assert out.next() == {"jsonrpc": "2.0", "id": 1, "result": {"echo": {"x": 1}}}
    _send(server, {"id": 2, "method": "echo", "params": {"bad": 1}})
    assert out.next()["error"] == {"code": -32602, "message": "bad param", "data": {"why": 1}}
    _send(server, {"id": 3, "method": "echo", "params": {"boom": 1}})
    err = out.next()["error"]
    assert err["code"] == -32603
    assert "kaboom" in err["message"]
    _send(server, {"id": 4, "method": "nope"})
    assert out.next()["error"]["code"] == -32601
    _send(server, "{not json")
    assert out.next()["error"]["code"] == -32700
    _send(server, {"id": 5, "method": "echo", "params": [1, 2]})
    assert out.next()["error"]["code"] == -32602
    _send(server, {"id": 6, "method": "ping"})
    assert out.next()["result"] == {"pong": True}
    server.shutdown()


def test_progress_and_cancel() -> None:
    started = threading.Event()

    def slow(_params: dict[str, Any], ctx: RequestContext) -> Any:
        ctx.progress({"fraction": 0.5})
        started.set()
        while True:
            ctx.token.raise_if_cancelled()
            time.sleep(0.01)

    server, out = _server({"slow": slow})
    _send(server, {"id": "a", "method": "slow"})
    progress = out.next()
    assert progress == {
        "jsonrpc": "2.0",
        "method": "progress",
        "params": {"requestId": "a", "method": "slow", "fraction": 0.5},
    }
    assert started.wait(5)
    _send(server, {"id": 99, "method": "cancel", "params": {"requestId": "a"}})
    replies = {m["id"]: m for m in (out.next(), out.next())}
    assert replies[99]["result"] == {"ok": True}
    assert replies["a"]["error"]["code"] == -32800
    _send(server, {"id": 100, "method": "cancel", "params": {"requestId": "a"}})
    assert out.next()["result"] == {"ok": False}
    server.shutdown()


def test_shutdown_cancels_inflight() -> None:
    def forever(_params: dict[str, Any], ctx: RequestContext) -> Any:
        while True:
            if ctx.token.cancelled:
                raise CancelledError
            time.sleep(0.01)

    server, out = _server({"forever": forever})
    _send(server, {"id": 1, "method": "forever"})
    time.sleep(0.05)
    server.shutdown()
    assert out.next()["error"]["code"] == -32800


class _Client:
    """Minimal stdio JSON-RPC client driving ``python -m pcap_backend``."""

    def __init__(self) -> None:
        env = {**os.environ, "PYTHONPATH": str(BACKEND_DIR)}
        self.proc = subprocess.Popen(
            [sys.executable, "-m", "pcap_backend"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            env=env,
        )
        self._id = 0
        self.notifications: list[dict[str, Any]] = []

    def call(self, method: str, **params: Any) -> dict[str, Any]:
        self._id += 1
        msg = {"jsonrpc": "2.0", "id": self._id, "method": method, "params": params}
        assert self.proc.stdin is not None and self.proc.stdout is not None
        self.proc.stdin.write(json.dumps(msg).encode() + b"\n")
        self.proc.stdin.flush()
        while True:
            line = self.proc.stdout.readline()
            assert line, "backend exited"
            reply = json.loads(line)
            if reply.get("id") == self._id:
                return reply
            self.notifications.append(reply)

    def close(self) -> int:
        assert self.proc.stdin is not None
        self.proc.stdin.close()
        return self.proc.wait(timeout=10)


@pytest.mark.tshark
def test_end_to_end_over_stdio(fixtures: Path) -> None:
    client = _Client()
    try:
        init = client.call("initialize")["result"]
        assert "TShark" in init["version"]
        info = client.call("open", path=str(fixtures / "dns.pcap"))["result"]
        assert info["frames"] == 6
        assert client.call("set_filter", expr="dns.flags.rcode == 3")["result"]["matchCount"] == 1
        rows = client.call("list_packets", offset=0, limit=10)["result"]["rows"]
        assert [r["number"] for r in rows] == [6]
        detail = client.call("packet_detail", number=6)["result"]
        assert any(n.get("name") == "dns" for n in detail["tree"])
        bad = client.call("set_filter", expr="dns.qry.name ==")
        assert bad["error"]["code"] == -32010
        assert any(n["method"] == "progress" for n in client.notifications)
    finally:
        assert client.close() == 0
