"""Newline-delimited JSON-RPC 2.0 server over stdio.

* Requests: ``{"jsonrpc": "2.0", "id": 1, "method": "open", "params": {...}}``
* Responses: ``{"jsonrpc": "2.0", "id": 1, "result": ...}``
  or ``{"jsonrpc": "2.0", "id": 1, "error": {code, message, data?}}``
* Notifications from the server (no ``id``):
  ``{"jsonrpc": "2.0", "method": "progress", "params": {"requestId": 1, ...}}``
* ``cancel`` (``{"requestId": 1}``) is handled on the reader thread so it can
  interrupt a long-running request; the cancelled request answers with code -32800.

Requests run on a thread pool so ``cancel`` and cheap calls are never stuck
behind a long tshark pass. stdout carries protocol messages only; all logging
goes to stderr.
"""

import argparse
import json
import logging
import signal
import sys
import threading
import traceback
from collections.abc import Callable, Mapping
from concurrent.futures import ThreadPoolExecutor
from typing import IO, Any

from .cancellation import CancelledError, CancelToken
from .pcap_service import PcapService, rpc_methods
from .protocol import (
    INTERNAL_ERROR,
    INVALID_PARAMS,
    INVALID_REQUEST,
    METHOD_NOT_FOUND,
    PARSE_ERROR,
    REQUEST_CANCELLED,
    TSHARK_FAILED,
    TSHARK_NOT_FOUND,
    RequestContext,
    RpcError,
)
from .tshark import PROCESSES, ConfigError, ToolError, ToolNotFoundError

log = logging.getLogger("pcap_backend")

Handler = Callable[[dict[str, Any], RequestContext], Any]
RequestId = int | str


class JsonRpcServer:
    def __init__(
        self,
        reader: IO[bytes],
        writer: IO[bytes],
        methods: Mapping[str, Handler],
        max_workers: int = 4,
    ) -> None:
        self._reader = reader
        self._writer = writer
        self._methods = dict(methods)
        self._write_lock = threading.Lock()
        self._inflight: dict[RequestId, CancelToken] = {}
        self._inflight_lock = threading.Lock()
        self._pool = ThreadPoolExecutor(max_workers=max_workers, thread_name_prefix="rpc")

    # ------------------------------------------------------------------ output

    def _send(self, message: Mapping[str, Any]) -> None:
        data = json.dumps(message, ensure_ascii=False, separators=(",", ":")) + "\n"
        with self._write_lock:
            try:
                self._writer.write(data.encode("utf-8"))
                self._writer.flush()
            except BrokenPipeError, ValueError, OSError:
                log.debug("client went away; dropping message")

    def notify(self, method: str, params: Mapping[str, Any]) -> None:
        self._send({"jsonrpc": "2.0", "method": method, "params": params})

    def _respond(self, req_id: RequestId, result: Any) -> None:
        self._send({"jsonrpc": "2.0", "id": req_id, "result": result})

    def _error(self, req_id: RequestId | None, code: int, message: str, data: Any = None) -> None:
        err: dict[str, Any] = {"code": code, "message": message}
        if data is not None:
            err["data"] = data
        self._send({"jsonrpc": "2.0", "id": req_id, "error": err})

    # ------------------------------------------------------------------ input

    def serve_forever(self) -> None:
        for raw in self._reader:
            line = raw.strip()
            if line:
                self.handle_line(line)
        self.shutdown()

    def handle_line(self, line: bytes) -> None:
        try:
            msg = json.loads(line)
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            self._error(None, PARSE_ERROR, f"parse error: {exc}")
            return
        if not isinstance(msg, dict) or not isinstance(msg.get("method"), str):
            self._error(_id_of(msg), INVALID_REQUEST, "invalid request")
            return
        req_id = msg.get("id")
        method: str = msg["method"]
        params = msg.get("params") or {}
        if not isinstance(params, dict):
            self._error(req_id, INVALID_PARAMS, "params must be an object")
            return
        if req_id is not None and not isinstance(req_id, int | str):
            self._error(None, INVALID_REQUEST, "id must be a number or string")
            return

        if method == "cancel":
            ok = self.cancel(params.get("requestId"))
            if req_id is not None:
                self._respond(req_id, {"ok": ok})
            return
        if method == "ping":
            if req_id is not None:
                self._respond(req_id, {"pong": True})
            return

        handler = self._methods.get(method)
        if handler is None:
            if req_id is not None:
                self._error(req_id, METHOD_NOT_FOUND, f"method not found: {method}")
            return
        token = CancelToken()
        if req_id is not None:
            with self._inflight_lock:
                if req_id in self._inflight:
                    self._error(req_id, INVALID_REQUEST, f"duplicate request id {req_id!r}")
                    return
                self._inflight[req_id] = token
        self._pool.submit(self._run, req_id, method, handler, params, token)

    def cancel(self, req_id: object) -> bool:
        if not isinstance(req_id, int | str):
            return False
        with self._inflight_lock:
            token = self._inflight.get(req_id)
        if token is None:
            return False
        token.cancel()
        return True

    def _run(
        self,
        req_id: RequestId | None,
        method: str,
        handler: Handler,
        params: dict[str, Any],
        token: CancelToken,
    ) -> None:
        def progress(payload: Mapping[str, Any]) -> None:
            if req_id is not None and not token.cancelled:
                self.notify("progress", {"requestId": req_id, "method": method, **payload})

        ctx = RequestContext(token=token, progress=progress)
        try:
            token.raise_if_cancelled()
            result = handler(params, ctx)
            token.raise_if_cancelled()
            if req_id is not None:
                self._respond(req_id, result)
        except CancelledError as exc:
            if req_id is not None:
                self._error(req_id, REQUEST_CANCELLED, str(exc) or "request cancelled")
        except RpcError as exc:
            if req_id is not None:
                self._error(req_id, exc.code, exc.message, exc.data)
        except ToolNotFoundError as exc:
            if req_id is not None:
                self._error(
                    req_id, TSHARK_NOT_FOUND, str(exc), {"tool": exc.tool, "searched": exc.searched}
                )
        except ToolError as exc:
            if req_id is not None:
                self._error(
                    req_id,
                    TSHARK_FAILED,
                    str(exc),
                    {"stderr": exc.stderr, "returncode": exc.returncode},
                )
        except ConfigError as exc:
            if req_id is not None:
                self._error(req_id, INVALID_PARAMS, str(exc))
        except Exception as exc:
            log.error("unhandled error in %s:\n%s", method, traceback.format_exc())
            if req_id is not None:
                self._error(req_id, INTERNAL_ERROR, f"{type(exc).__name__}: {exc}")
        finally:
            if req_id is not None:
                with self._inflight_lock:
                    self._inflight.pop(req_id, None)

    def shutdown(self) -> None:
        with self._inflight_lock:
            tokens = list(self._inflight.values())
        for token in tokens:
            token.cancel()
        PROCESSES.kill_all()
        self._pool.shutdown(wait=True, cancel_futures=True)


def _id_of(msg: object) -> RequestId | None:
    if isinstance(msg, dict):
        rid = msg.get("id")
        if isinstance(rid, int | str):
            return rid
    return None


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="pcap_backend", description=__doc__)
    parser.add_argument("--log-level", default="INFO")
    parser.add_argument("--max-cached-frames", type=int, default=5_000_000)
    args = parser.parse_args(argv)
    logging.basicConfig(
        stream=sys.stderr,
        level=args.log_level.upper(),
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )

    service = PcapService(max_cached_frames=args.max_cached_frames)
    server = JsonRpcServer(sys.stdin.buffer, sys.stdout.buffer, rpc_methods(service))

    def on_signal(signum: int, _frame: object) -> None:
        log.info("signal %s: shutting down", signum)
        PROCESSES.kill_all()
        service.shutdown()
        sys.exit(0)

    for sig in (signal.SIGTERM, signal.SIGINT):
        signal.signal(sig, on_signal)

    log.info("pcap backend ready (python %s)", sys.version.split()[0])
    try:
        server.serve_forever()
    finally:
        service.shutdown()
        PROCESSES.kill_all()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
