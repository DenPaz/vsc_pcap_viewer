"""JSON-RPC error types and the per-request context handed to service methods."""

from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from typing import Any

from .cancellation import CancelToken

# Standard JSON-RPC 2.0 codes.
PARSE_ERROR = -32700
INVALID_REQUEST = -32600
METHOD_NOT_FOUND = -32601
INVALID_PARAMS = -32602
INTERNAL_ERROR = -32603
# LSP-style cancellation code.
REQUEST_CANCELLED = -32800
# Application codes.
TSHARK_NOT_FOUND = -32001
TSHARK_FAILED = -32002
NOT_OPEN = -32003
INVALID_FILTER = -32010
UNSUPPORTED_FORMAT = -32011


class RpcError(Exception):
    code = INTERNAL_ERROR

    def __init__(self, message: str, data: Mapping[str, Any] | None = None) -> None:
        super().__init__(message)
        self.message = message
        self.data = dict(data) if data else None


class InvalidParamsError(RpcError):
    code = INVALID_PARAMS


class NotOpenError(RpcError):
    code = NOT_OPEN

    def __init__(self) -> None:
        super().__init__("no capture file is open")


class FilterError(RpcError):
    code = INVALID_FILTER


class UnsupportedFormatError(RpcError):
    """The file is not a capture tshark can read."""

    code = UNSUPPORTED_FORMAT


ProgressFn = Callable[[Mapping[str, Any]], None]


def _no_progress(_payload: Mapping[str, Any]) -> None:
    return None


@dataclass(slots=True)
class RequestContext:
    token: CancelToken = field(default_factory=CancelToken)
    progress: ProgressFn = _no_progress


def param[T](params: Mapping[str, Any], name: str, kind: type[T], default: T | None = None) -> T:
    """Fetch and type-check a request parameter."""
    if name not in params or params[name] is None:
        if default is None:
            raise InvalidParamsError(f"missing parameter '{name}'")
        return default
    value = params[name]
    # bool is an int subclass; never accept it where a number is expected.
    if kind in (int, float) and isinstance(value, bool):
        raise InvalidParamsError(f"parameter '{name}' must be {kind.__name__}")
    if kind is float and isinstance(value, int):
        return float(value)  # type: ignore[return-value]
    if not isinstance(value, kind):
        raise InvalidParamsError(f"parameter '{name}' must be {kind.__name__}")
    return value


def str_list(params: Mapping[str, Any], name: str) -> list[str]:
    value = params.get(name) or []
    if not isinstance(value, list) or not all(isinstance(v, str) for v in value):
        raise InvalidParamsError(f"parameter '{name}' must be a list of strings")
    return value
