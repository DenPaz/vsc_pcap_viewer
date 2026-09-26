"""Step definitions for the Gherkin acceptance scenarios in ``features/``.

Scenarios drive :class:`~pcap_backend.pcap_service.PcapService` directly with
real tshark; the ``@tshark`` feature tag becomes a pytest marker, so they skip
when tshark is missing (see ``test/backend/conftest.py``).
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import pytest
from pytest_bdd import given, parsers, then, when

from pcap_backend.cancellation import CancelledError
from pcap_backend.pcap_service import BASE_COLUMNS, PcapService
from pcap_backend.protocol import FilterError, RequestContext, RpcError
from pcap_backend.tshark import PROCESSES, ConfigError

ROOT = Path(__file__).resolve().parents[3]
FIXTURES = ROOT / "test" / "fixtures"
TITLE_TO_INDEX = {c.title: i for i, c in enumerate(BASE_COLUMNS)}
TITLE_TO_FIELD = {c.title: c.field for c in BASE_COLUMNS}


def items(text: str) -> list[str]:
    """Split ``a, b and c`` / ``"a" and "b"`` into ``["a", "b", "c"]``."""
    parts = re.split(r",\s*|\s+and\s+", text.strip())
    return [p.strip().strip('"') for p in parts if p.strip()]


def numbers(text: str) -> list[int]:
    return [int(p) for p in items(text)]


@dataclass
class World:
    service: PcapService
    ctx: RequestContext = field(default_factory=RequestContext)
    lua: list[str] = field(default_factory=list)
    decode_as: list[str] = field(default_factory=list)
    columns: list[str] = field(default_factory=list)
    info: dict[str, Any] | None = None
    filter_result: dict[str, Any] | None = None
    page: dict[str, Any] | None = None
    detail: dict[str, Any] | None = None
    validation: dict[str, Any] | None = None
    suggestions: dict[str, Any] | None = None
    error: Exception | None = None

    def call(self, fn: Any, params: dict[str, Any]) -> Any:
        """Run a service method, remembering (instead of raising) expected errors."""
        self.error = None
        try:
            return fn(params, self.ctx)
        except (RpcError, ConfigError, CancelledError) as exc:
            self.error = exc
            return None

    def rows(self, offset: int = 0, limit: int = 1000, **extra: Any) -> dict[str, Any]:
        page: dict[str, Any] = self.service.list_packets(
            {"offset": offset, "limit": limit, **extra}, self.ctx
        )
        return page


@pytest.fixture
def world(service: PcapService) -> World:
    return World(service)


# ---------------------------------------------------------------------- given


@given(parsers.parse("the custom columns {columns}"))
def given_columns(world: World, columns: str) -> None:
    world.columns = items(columns)


@given(parsers.parse('the Decode As rule "{rule}"'))
def given_decode_as(world: World, rule: str) -> None:
    world.decode_as.append(rule)


@given(parsers.parse('the Lua dissector "{path}"'))
def given_lua(world: World, path: str, request: pytest.FixtureRequest) -> None:
    if "lua" in request.node.keywords and hasattr(os, "geteuid") and os.geteuid() == 0:
        pytest.skip("tshark disables Lua dissectors when running as root")
    world.lua.append(str(ROOT / path))


@given(parsers.parse('the capture "{name}" is open'))
def given_open(world: World, name: str) -> None:
    open_capture(world, name)
    assert world.error is None, world.error


@given(parsers.parse('the display filter "{expr}" is applied'))
def given_filter(world: World, expr: str) -> None:
    world.filter_result = world.call(world.service.set_filter, {"expr": expr})
    assert world.error is None, world.error


# ---------------------------------------------------------------------- when


@when(parsers.parse('I open the capture "{name}"'))
def open_capture(world: World, name: str) -> None:
    params = {
        "path": str(FIXTURES / name),
        "lua": world.lua,
        "decodeAs": world.decode_as,
        "columns": world.columns,
    }
    world.info = world.call(world.service.open, params)


@when(parsers.parse('I apply the display filter "{expr}"'))
def apply_filter(world: World, expr: str) -> None:
    world.filter_result = world.call(world.service.set_filter, {"expr": expr})


@when(parsers.parse('I apply the display filter "{expr}" and cancel it'))
def apply_cancelled_filter(world: World, expr: str) -> None:
    world.ctx = RequestContext()
    world.ctx.token.cancel()
    world.filter_result = world.call(world.service.set_filter, {"expr": expr})
    world.ctx = RequestContext()


@when("I clear the display filter")
def clear_filter(world: World) -> None:
    world.filter_result = world.call(world.service.set_filter, {"expr": ""})


@when(parsers.parse('I validate the display filter "{expr}"'))
def validate(world: World, expr: str) -> None:
    world.validation = world.service.validate_filter({"expr": expr}, world.ctx)


@when(parsers.re(r"I request (?P<limit>\d+) packets? starting at row (?P<offset>\d+)$"))
def request_page(world: World, limit: str, offset: str) -> None:
    world.page = world.rows(int(offset), int(limit))


@when(
    parsers.re(
        r"I request (?P<limit>\d+) packets? starting at row (?P<offset>\d+) "
        r"with the custom columns (?P<columns>.+)$"
    )
)
def request_page_with_columns(world: World, limit: str, offset: str, columns: str) -> None:
    world.page = world.rows(int(offset), int(limit), columns=items(columns))


@when(parsers.parse('I sort by "{title}" {direction}'))
def sort_by(world: World, title: str, direction: str) -> None:
    assert direction in ("ascending", "descending")
    sort = {"field": TITLE_TO_FIELD[title], "desc": direction == "descending"}
    world.page = world.rows(sort=sort)


@when(parsers.parse("I select packet {number:d}"))
def select_packet(world: World, number: int) -> None:
    world.detail = world.call(world.service.packet_detail, {"number": number})


# ---------------------------------------------------------------------- then: capture


@then(parsers.parse("the capture has {count:d} packets"))
def capture_has(world: World, count: int) -> None:
    assert world.error is None, world.error
    assert world.info is not None
    assert world.info["frames"] == count


@then(parsers.parse('the link type is "{link}"'))
def link_type(world: World, link: str) -> None:
    assert world.info is not None
    assert world.info["linkType"] == link


@then(parsers.parse("the capture starts at {epoch:f}"))
def starts_at(world: World, epoch: float) -> None:
    assert world.info is not None
    assert world.info["startTime"] == pytest.approx(epoch)


@then("there are no warnings")
def no_warnings(world: World) -> None:
    assert world.info is not None
    assert world.info["warnings"] == []


@then(parsers.parse('a warning mentions "{text}"'))
def warning_mentions(world: World, text: str) -> None:
    assert world.error is None, world.error
    assert world.info is not None
    assert any(text in w for w in world.info["warnings"]), world.info["warnings"]


@then(parsers.parse('the request fails with "{text}"'))
def request_fails(world: World, text: str) -> None:
    assert world.error is not None, "expected the request to fail"
    assert text in str(world.error)


@then(parsers.parse('the columns end with "{fld}"'))
def columns_end_with(world: World, fld: str) -> None:
    assert world.info is not None
    assert world.info["columns"][-1]["field"] == fld


# ---------------------------------------------------------------------- then: list


def _cell(world: World, row: int, title: str) -> str:
    page = world.page or world.rows()
    cell: str = page["rows"][row - 1]["cells"][TITLE_TO_INDEX[title]]
    return cell


@then(parsers.parse('the "{title}" column of row {row:d} is "{value}"'))
def column_of_row(world: World, title: str, row: int, value: str) -> None:
    assert _cell(world, row, title) == value


@then(parsers.parse('the "{title}" column of row {row:d} starts with "{prefix}"'))
def column_of_row_starts(world: World, title: str, row: int, prefix: str) -> None:
    assert _cell(world, row, title).startswith(prefix)


@then(parsers.parse('the "{title}" column of rows {first:d} to {last:d} is {values}'))
def column_of_rows(world: World, title: str, first: int, last: int, values: str) -> None:
    assert [_cell(world, r, title) for r in range(first, last + 1)] == items(values)


@then(parsers.parse("the rows are frames {frames}"))
def rows_are(world: World, frames: str) -> None:
    assert world.page is not None
    assert [r["number"] for r in world.page["rows"]] == numbers(frames)


@then("no rows are returned")
def no_rows(world: World) -> None:
    assert world.page is not None
    assert world.page["rows"] == []


@then(parsers.parse("the custom column values are {values}"))
def custom_values(world: World, values: str) -> None:
    assert world.page is not None
    expected = items(values)
    assert world.page["rows"][0]["cells"][-len(expected) :] == expected


# ---------------------------------------------------------------------- then: filters


@then(parsers.parse("{count:d} packets are displayed"))
def packets_displayed(world: World, count: int) -> None:
    assert world.rows(limit=0)["total"] == count


@then(parsers.parse("the displayed frames are {frames}"))
def displayed_frames(world: World, frames: str) -> None:
    assert [r["number"] for r in world.rows()["rows"]] == numbers(frames)


@then("the filter is rejected with an error")
def filter_rejected(world: World) -> None:
    assert isinstance(world.error, FilterError), world.error
    assert world.error.message


@then(parsers.re(r"the filter is (?P<result>valid|invalid)$"))
def filter_validity(world: World, result: str) -> None:
    assert world.validation is not None
    assert world.validation["valid"] is (result == "valid"), world.validation


@then(parsers.parse('applying the display filter "{expr}" displays {count:d} packets'))
def filter_displays(world: World, expr: str, count: int) -> None:
    assert world.service.set_filter({"expr": expr}, world.ctx)["matchCount"] == count


@then("the request is cancelled")
def request_cancelled(world: World) -> None:
    assert isinstance(world.error, CancelledError), world.error


@then("no tshark process is left running")
def no_processes() -> None:
    assert len(PROCESSES) == 0


# ---------------------------------------------------------------------- then: detail


def _find(nodes: list[dict[str, Any]], name: str) -> dict[str, Any] | None:
    for n in nodes:
        if n.get("name") == name:
            return n
        found = _find(n.get("children", []), name)
        if found:
            return found
    return None


def _bytes_of(world: World, node: dict[str, Any]) -> bytes:
    assert world.detail is not None
    data = bytes.fromhex(world.detail["sources"][node["src"]]["hex"])
    return data[node["pos"] : node["pos"] + node["size"]]


@then(parsers.parse("the protocol tree is {protocols}"))
def protocol_tree(world: World, protocols: str) -> None:
    assert world.error is None, world.error
    assert world.detail is not None
    assert [n.get("name") for n in world.detail["tree"]] == items(protocols)


@then(parsers.parse("the packet has the byte sources {names}"))
def byte_sources(world: World, names: str) -> None:
    assert world.detail is not None
    assert [s["name"] for s in world.detail["sources"]] == items(names)


@then(parsers.parse('the field "{name}" covers the bytes {hexbytes}'))
def field_bytes(world: World, name: str, hexbytes: str) -> None:
    assert world.detail is not None
    node = _find(world.detail["tree"], name)
    assert node is not None, f"no field {name}"
    assert _bytes_of(world, node) == bytes.fromhex(hexbytes.replace(" ", ""))


@then(parsers.parse('the "{name}" protocol is in the byte source "{source}"'))
def protocol_in_source(world: World, name: str, source: str) -> None:
    assert world.detail is not None
    node = _find(world.detail["tree"], name)
    assert node is not None
    assert world.detail["sources"][node["src"]]["name"] == source


@then(parsers.parse('the "{name}" protocol bytes start with "{text}"'))
def protocol_bytes_start(world: World, name: str, text: str) -> None:
    assert world.detail is not None
    node = _find(world.detail["tree"], name)
    assert node is not None
    data = bytes.fromhex(world.detail["sources"][node["src"]]["hex"])
    assert data[node["pos"] :].startswith(text.encode())


# ---------------------------------------------------------------------- autocomplete


@given(parsers.parse('I open the capture "{name}"'))
def given_open_with_options(world: World, name: str) -> None:
    open_capture(world, name)
    assert world.error is None, world.error


@when(parsers.re(r'I ask for (?:(?P<limit>\d+) )?filter suggestions for "(?P<prefix>[^"]*)"$'))
def ask_suggestions(world: World, prefix: str, limit: str | None) -> None:
    world.suggestions = world.service.field_index(
        {"prefix": prefix, "limit": int(limit) if limit else 50}, world.ctx
    )


def _suggested(world: World, kind: str) -> list[dict[str, str]]:
    assert world.suggestions is not None
    entries: list[dict[str, str]] = world.suggestions[kind]
    return entries


@then(
    parsers.re(r'the field suggestions include "(?P<name>[^"]+)"(?: of type "(?P<ftype>[^"]+)")?$')
)
def field_suggested(world: World, name: str, ftype: str | None) -> None:
    match = [f for f in _suggested(world, "fields") if f["name"] == name]
    assert match, [f["name"] for f in _suggested(world, "fields")]
    if ftype:
        assert match[0]["type"] == ftype


@then(parsers.parse('the protocol suggestions include "{name}"'))
def protocol_suggested(world: World, name: str) -> None:
    assert name in [p["name"] for p in _suggested(world, "protocols")]


@then(parsers.parse('every suggestion starts with "{prefix}"'))
def all_start_with(world: World, prefix: str) -> None:
    names = [e["name"] for e in _suggested(world, "fields") + _suggested(world, "protocols")]
    assert names
    assert all(n.lower().startswith(prefix.lower()) for n in names), names


@then("the first field suggestion has a description")
def first_has_description(world: World) -> None:
    assert _suggested(world, "fields")[0]["desc"]


@then(parsers.parse("there are {count:d} field suggestions"))
def field_count(world: World, count: int) -> None:
    assert len(_suggested(world, "fields")) == count


@then("the suggestions are marked as truncated")
def truncated(world: World) -> None:
    assert world.suggestions is not None
    assert world.suggestions["truncated"] is True


@then(parsers.parse("the rejected columns are {columns}"))
def rejected_columns(world: World, columns: str) -> None:
    assert world.page is not None
    assert world.page["rejectedColumns"] == items(columns)
