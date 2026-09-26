"""Step definitions for the Gherkin acceptance scenarios in ``features/``.

Scenarios drive :class:`~pcap_backend.pcap_service.PcapService` directly with
real tshark; the ``@tshark`` feature tag becomes a pytest marker, so they skip
when tshark is missing (see ``test/backend/conftest.py``).
"""

import json
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import pytest
from pytest_bdd import given, parsers, then, when

from pcap_backend.cancellation import CancelledError
from pcap_backend.pcap_service import BASE_COLUMNS, PcapService
from pcap_backend.protocol import FilterError, RequestContext, RpcError, UnsupportedFormatError
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
    followed: dict[str, Any] | None = None
    table: dict[str, Any] | None = None
    check: dict[str, Any] | None = None
    choices: dict[str, Any] | None = None
    exported: dict[str, Any] | None = None
    progress: list[dict[str, Any]] = field(default_factory=list)
    sort: dict[str, Any] | None = None
    found: dict[str, Any] | None = None
    time_ref: int | None = None
    time_format: str | None = None
    coloring: dict[str, Any] | None = None
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
    world.progress = []
    world.ctx.progress = lambda p: world.progress.append(dict(p))
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
    world.sort = sort
    extra: dict[str, Any] = {"timeFormat": world.time_format} if world.time_format else {}
    world.page = world.rows(sort=sort, **extra)


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


@then(parsers.re(r"the open progress is (?P<kind>estimated|indeterminate)$"))
def open_progress(world: World, kind: str) -> None:
    assert world.error is None, world.error
    index = [p for p in world.progress if p.get("phase") == "index"]
    assert index[-1]["fraction"] == 1.0  # done
    during = [p["fraction"] for p in index[:-1]]
    assert during, "no progress was reported while indexing"
    if kind == "estimated":
        assert all(isinstance(f, float) and 0 < f < 1 for f in during), during
    else:
        assert all(f is None for f in during), during


@then(parsers.re(r'the request fails because "(?P<name>[^"]+)" is not a capture file$'))
def not_a_capture(world: World, name: str) -> None:
    assert isinstance(world.error, UnsupportedFormatError), world.error
    assert str(world.error) == f"{name} is not a capture file that tshark can read"
    assert world.error.data and "TShark understands" in world.error.data["stderr"]


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


# ---------------------------------------------------------------------- follow stream


@when(parsers.parse('I follow the "{proto}" stream of packet {frame:d}'))
def follow_from_packet(world: World, proto: str, frame: int) -> None:
    world.followed = world.call(world.service.follow_stream, {"proto": proto, "frame": frame})


@when(parsers.parse('I follow "{proto}" stream number {stream:d}'))
def follow_by_number(world: World, proto: str, stream: int) -> None:
    world.followed = world.call(world.service.follow_stream, {"proto": proto, "stream": stream})


def _followed(world: World) -> dict[str, Any]:
    assert world.error is None, world.error
    assert world.followed is not None
    return world.followed


def _direction_bytes(world: World, direction: int) -> bytes:
    segments = _followed(world)["segments"]
    return b"".join(bytes.fromhex(s["hex"]) for s in segments if s["dir"] == direction)


@then(parsers.parse('the followed stream is number {stream:d} between "{a}" and "{b}"'))
def followed_stream_is(world: World, stream: int, a: str, b: str) -> None:
    followed = _followed(world)
    assert followed["stream"] == stream
    assert followed["nodes"] == [a, b]


@then(parsers.parse("the client sent {c2s:d} bytes and the server sent {s2c:d} bytes"))
def follow_byte_counts(world: World, c2s: int, s2c: int) -> None:
    assert _followed(world)["bytes"] == [c2s, s2c]
    assert len(_direction_bytes(world, 0)) == c2s
    assert len(_direction_bytes(world, 1)) == s2c


@then(parsers.re(r'the (?P<side>client|server) data starts with "(?P<text>[^"]+)"$'))
def follow_data_starts(world: World, side: str, text: str) -> None:
    assert _direction_bytes(world, 0 if side == "client" else 1).startswith(text.encode())


@then(parsers.parse('the stream filter is "{flt}"'))
def follow_filter(world: World, flt: str) -> None:
    assert _followed(world)["filter"] == flt


@then("the followed stream is empty")
def follow_empty(world: World) -> None:
    assert _followed(world)["segments"] == []


@then(parsers.parse('the follow hint mentions "{text}"'))
def follow_hint(world: World, text: str) -> None:
    assert text in _followed(world).get("hint", "")


# ---------------------------------------------------------------------- statistics


@when(
    parsers.re(
        r'I request the "(?P<kind>\w+)" statistics'
        r'(?: for "(?P<typ>\w+)")?'
        r"(?: with interval (?P<interval>[\d.]+))?"
        r'(?: limited to "(?P<flt>[^"]*)")?$'
    )
)
def request_stats(
    world: World, kind: str, typ: str | None, interval: str | None, flt: str | None
) -> None:
    params: dict[str, Any] = {"kind": kind}
    if typ:
        params["type"] = typ
    if interval:
        params["interval"] = float(interval)
    if flt is not None:
        params["filter"] = flt
    world.table = world.call(world.service.stats, params)


def _table(world: World) -> dict[str, Any]:
    assert world.error is None, world.error
    assert world.table is not None
    return world.table


def _stats_cell(world: World, row: dict[str, Any], label: str) -> Any:
    labels = [c["label"] for c in _table(world)["columns"]]
    return row["cells"][labels.index(label)]


@then(parsers.re(r"the statistics have (?P<count>\d+) rows?$"))
def stats_row_count(world: World, count: str) -> None:
    assert len(_table(world)["rows"]) == int(count)


@then(parsers.re(r"row (?P<n>\d+) has (?P<pairs>.+)$"))
def stats_row_has(world: World, n: str, pairs: str) -> None:
    row = _table(world)["rows"][int(n) - 1]
    for label, value in re.findall(r'"([^"]+)" (?:"([^"]*)"|\d+)', pairs):
        expected: Any = value
        if not value:  # numeric: re-read the number after the label
            m = re.search(rf'"{re.escape(label)}" (\d+)', pairs)
            assert m
            expected = int(m.group(1))
        assert _stats_cell(world, row, label) == expected, (label, row)


@then(parsers.parse('row {n:d} filters on "{flt}"'))
def stats_row_filter(world: World, n: int, flt: str) -> None:
    assert _table(world)["rows"][n - 1].get("filter") == flt


@then(parsers.parse('the statistics include "{proto}" at depth {depth:d} with {packets:d} packets'))
def phs_includes(world: World, proto: str, depth: int, packets: int) -> None:
    rows = [r for r in _table(world)["rows"] if r["cells"][0] == proto]
    assert rows, proto
    assert rows[0]["depth"] == depth
    assert _stats_cell(world, rows[0], "Packets") == packets


@then(parsers.parse('every row has {value:d} "{label}"'))
def every_row_has(world: World, value: int, label: str) -> None:
    assert all(_stats_cell(world, r, label) == value for r in _table(world)["rows"])


@then(
    parsers.parse(
        'the expert row "{summary}" has severity "{severity}", count {count:d} and frames {frames}'
    )
)
def expert_row(world: World, summary: str, severity: str, count: int, frames: str) -> None:
    rows = [r for r in _table(world)["rows"] if _stats_cell(world, r, "Summary") == summary]
    assert rows, summary
    row = rows[0]
    assert _stats_cell(world, row, "Severity") == severity
    assert _stats_cell(world, row, "Count") == count
    assert row["frames"] == numbers(frames)
    assert row["frame"] == numbers(frames)[0]


@then(parsers.parse('the property "{key}" is "{value}"'))
def property_is(world: World, key: str, value: str) -> None:
    rows = {r["cells"][0]: r["cells"][1] for r in _table(world)["rows"]}
    assert rows.get(key) == value, rows


# ---------------------------------------------------------------------- dissector check / Decode As


@given("a Lua dissector with a syntax error")
def given_bad_lua(world: World, tmp_path: Path, request: pytest.FixtureRequest) -> None:
    if hasattr(os, "geteuid") and os.geteuid() == 0:
        pytest.skip("tshark disables Lua dissectors when running as root")
    script = tmp_path / "broken.lua"
    script.write_text('local p = Proto("broken"\n')
    world.lua.append(str(script))


@when("I check the dissectors")
def check_dissectors(world: World) -> None:
    world.check = world.call(world.service.check_dissectors, {"lua": world.lua})


@then(parsers.parse('a dissector error mentions "{text}" for that script'))
def dissector_error(world: World, text: str) -> None:
    assert world.error is None, world.error
    assert world.check is not None
    matches = [e for e in world.check["errors"] if text in e["message"]]
    assert matches, world.check
    assert matches[0].get("script") == world.lua[-1]


@then("there are no dissector errors")
def no_dissector_errors(world: World) -> None:
    assert world.check is not None
    assert world.check["errors"] == []


@then(parsers.parse('a dissector warning mentions "{text}"'))
def dissector_warning(world: World, text: str) -> None:
    assert world.check is not None
    assert any(text in w for w in world.check["warnings"]), world.check


@when("I ask which layers can be decoded as another protocol")
def ask_layers(world: World) -> None:
    world.choices = world.call(world.service.decode_as_options, {})


@when(parsers.parse('I ask which protocols "{layer}" can be decoded as'))
def ask_protocols(world: World, layer: str) -> None:
    world.choices = world.call(world.service.decode_as_options, {"layer": layer})


@then(parsers.re(r'the choices include "(?P<name>[^"]+)"(?: described as "(?P<desc>[^"]+)")?$'))
def choices_include(world: World, name: str, desc: str | None) -> None:
    assert world.error is None, world.error
    assert world.choices is not None
    found = [c for c in world.choices["choices"] if c["name"] == name]
    assert found, name
    if desc:
        assert found[0]["desc"] == desc


# ---------------------------------------------------------------------- export


def _export(world: World, tmp_path: Path, kind: str, name: str, **extra: Any) -> None:
    params = {"kind": kind, "dest": str(tmp_path / name), **extra}
    world.exported = world.call(world.service.export, params)


@when(parsers.re(r"I export (?P<which>the displayed|all) packets as (?P<fmt>pcapng|pcap)$"))
def export_capture(world: World, tmp_path: Path, which: str, fmt: str) -> None:
    extra = {"filter": ""} if which == "all" else {}
    _export(world, tmp_path, fmt, f"export.{fmt}", **extra)


@when("I export the displayed packets over the open capture")
def export_over_capture(world: World) -> None:
    assert world.info is not None
    world.exported = world.call(
        world.service.export, {"kind": "pcapng", "dest": world.info["path"]}
    )


@when(parsers.re(r"I export the packet list as (?P<fmt>CSV|JSON)$"))
def export_list(world: World, tmp_path: Path, fmt: str) -> None:
    _export(world, tmp_path, fmt.lower(), f"list.{fmt.lower()}")


@when(parsers.parse("I export the bytes of packet {number:d}"))
def export_bytes(world: World, tmp_path: Path, number: int) -> None:
    _export(world, tmp_path, "bytes", "packet.bin", number=number)


def _exported_path(world: World) -> Path:
    assert world.error is None, world.error
    assert world.exported is not None
    return Path(world.exported["path"])


_MAGIC = {"pcapng": bytes.fromhex("0a0d0d0a"), "pcap": bytes.fromhex("d4c3b2a1")}


@then(
    parsers.re(r"the exported capture is a (?P<fmt>pcapng|pcap) file with (?P<count>\d+) packets?$")
)
def exported_capture(world: World, fmt: str, count: str) -> None:
    path = _exported_path(world)
    assert path.read_bytes()[:4] == _MAGIC[fmt]
    # Re-open the export with the backend itself: an independent frame count.
    other = PcapService()
    try:
        info = other.open({"path": str(path)}, RequestContext())
    finally:
        other.shutdown()
    assert info["frames"] == int(count)


@then(parsers.parse("the export reports {count:d} packets"))
def export_reports(world: World, count: int) -> None:
    assert world.exported is not None
    assert world.exported["packets"] == count


@then(parsers.parse("the exported CSV has the columns {titles}"))
def exported_csv_columns(world: World, titles: str) -> None:
    header = _exported_path(world).read_text(encoding="utf-8").split("\n")[0]
    assert header == ",".join(f'"{t}"' for t in items(titles))


@then(parsers.parse("the exported CSV has {count:d} rows"))
def exported_csv_rows(world: World, count: int) -> None:
    lines = _exported_path(world).read_text(encoding="utf-8").strip().split("\n")
    assert len(lines) - 1 == count


@then(parsers.parse("the exported JSON lists the frames {frames}"))
def exported_json_frames(world: World, frames: str) -> None:
    data = json.loads(_exported_path(world).read_text(encoding="utf-8"))
    assert [r["number"] for r in data] == numbers(frames)


@then(parsers.parse("the exported file has {count:d} bytes"))
def exported_bytes(world: World, count: int) -> None:
    assert _exported_path(world).stat().st_size == count


@then("the export is refused")
def export_refused(world: World) -> None:
    assert isinstance(world.error, RpcError), world.error


# ---------------------------------------------------------------------- coloring


def _set_coloring(world: World, filters: list[str]) -> None:
    rules = [{"filter": f, "background": "#e0e0ff"} for f in filters]
    world.coloring = world.call(world.service.set_coloring, {"rules": rules})
    assert world.error is None, world.error


@given(parsers.parse("the coloring rules {filters} are set"))
def given_coloring(world: World, filters: str) -> None:
    _set_coloring(world, items(filters))


@when(parsers.parse("I set the coloring rules {filters}"))
def when_coloring(world: World, filters: str) -> None:
    _set_coloring(world, items(filters))


@when("I clear the coloring rules")
def clear_coloring(world: World) -> None:
    _set_coloring(world, [])


def _colors_by_protocol(world: World, protocol: str) -> set[int | None]:
    page = world.rows()
    colors = {r.get("color") for r in page["rows"] if r["cells"][4] == protocol}
    assert colors, f"no {protocol} packets"
    return colors


@then(parsers.re(r'the "(?P<protocol>[^"]+)" packets are colored by rule (?P<rule>\d+)$'))
def colored_by(world: World, protocol: str, rule: str) -> None:
    assert _colors_by_protocol(world, protocol) == {int(rule) - 1}


@then(parsers.re(r'the "(?P<protocol>[^"]+)" packets are not colored$'))
def not_colored(world: World, protocol: str) -> None:
    assert _colors_by_protocol(world, protocol) == {None}


@then(parsers.parse("coloring rule {rule:d} is reported as invalid"))
def rule_invalid(world: World, rule: int) -> None:
    assert world.coloring is not None
    assert str(rule - 1) in world.coloring["errors"], world.coloring


@then("no packet is colored")
def none_colored(world: World) -> None:
    assert all("color" not in r for r in world.rows()["rows"])


# ---------------------------------------------------------------------- navigation

FIND_MODES = {"display filter": "filter", "string": "string", "hex bytes": "hex"}


@when(
    parsers.re(
        r"I find the (?P<direction>next|previous) packet matching the "
        r'(?P<mode>display filter|string|hex bytes) "(?P<value>[^"]*)"'
        r"(?P<case> case-sensitively)?(?: after packet (?P<start>\d+))?$"
    )
)
def find_packet(
    world: World, direction: str, mode: str, value: str, case: str | None, start: str | None
) -> None:
    params: dict[str, Any] = {
        "mode": FIND_MODES[mode],
        "value": value,
        "caseSensitive": bool(case),
        "direction": direction,
    }
    if start:
        params["from"] = int(start)
    world.found = world.call(world.service.find_packet, params)


@when(
    parsers.re(
        r"I step to the (?P<direction>next|previous) packet in the conversation "
        r"of packet (?P<frame>\d+)$"
    )
)
def step_conversation(world: World, direction: str, frame: str) -> None:
    world.found = world.call(
        world.service.neighbor_frame, {"frame": int(frame), "direction": direction}
    )


@then(parsers.parse("the found packet is {frame:d}"))
def found_packet(world: World, frame: int) -> None:
    assert world.error is None, world.error
    assert world.found is not None and world.found["frame"] == frame, world.found


@then("no packet is found")
def nothing_found(world: World) -> None:
    assert world.error is None, world.error
    assert world.found is not None and world.found["frame"] is None, world.found


@then("the search wrapped around")
def search_wrapped(world: World) -> None:
    assert world.found is not None and world.found.get("wrapped") is True


@given(parsers.parse("packet {frame:d} is the time reference"))
def time_reference(world: World, frame: int) -> None:
    world.time_ref = frame


@given(parsers.parse('I show times as "{fmt}"'))
@when(parsers.parse('I show times as "{fmt}"'))
def show_times(world: World, fmt: str) -> None:
    world.time_format = fmt
    extra: dict[str, Any] = {"timeFormat": fmt, "timeRef": world.time_ref}
    if world.sort:
        extra["sort"] = world.sort
    world.page = world.rows(**extra)


def _time_of(world: World, frame: int) -> str:
    assert world.page is not None
    rows = {r["number"]: r["cells"][TITLE_TO_INDEX["Time"]] for r in world.page["rows"]}
    return rows[frame]


@then(parsers.parse('the time of packet {frame:d} is "{time}"'))
def time_of(world: World, frame: int, time: str) -> None:
    assert _time_of(world, frame) == time


@then(parsers.parse("the times are {times}"))
def times_are(world: World, times: str) -> None:
    assert world.page is not None
    assert [r["cells"][TITLE_TO_INDEX["Time"]] for r in world.page["rows"]] == items(times)


@given(parsers.parse("packets {frames} are marked"))
def packets_marked(world: World, frames: str) -> None:
    world.service.mark_packets({"frames": numbers(frames), "mark": True}, world.ctx)


@when(parsers.re(r"I export the marked packets as (?P<fmt>pcapng|pcap)$"))
def export_marked(world: World, tmp_path: Path, fmt: str) -> None:
    _export(world, tmp_path, fmt, f"marked.{fmt}", marked=True)
