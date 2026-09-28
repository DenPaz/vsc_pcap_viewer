"""Step definitions for the Gherkin acceptance scenarios in ``features/``.

Scenarios drive :class:`~pcap_backend.pcap_service.PcapService` directly with
real tshark; the ``@tshark`` feature tag becomes a pytest marker, so they skip
when tshark is missing (see ``test/backend/conftest.py``).
"""

import itertools
import json
import os
import re
import sys
import time
import wave
from array import array
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import pytest
from pytest_bdd import given, parsers, then, when

from pcap_backend.cancellation import CancelledError
from pcap_backend.pcap_service import BASE_COLUMNS, PcapService
from pcap_backend.protocol import FilterError, RequestContext, RpcError, UnsupportedFormatError
from pcap_backend.tshark import PROCESSES, ConfigError, ToolError

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
    cache_dir: Path | None = None
    tls: tuple[Path, Path] | None = None  # a TLS capture and its key log file
    events: list[dict[str, Any]] = field(default_factory=list)  # backend notifications
    coloring: dict[str, Any] | None = None
    names: dict[str, bool] | None = None  # name resolution switches (None: tshark's own)
    objects: list[dict[str, Any]] | None = None
    save_dir: Path | None = None
    voip: dict[str, Any] | None = None  # voip_calls' result
    saved: Path | None = None  # a file saved by a step
    release: Any = None  # slow_index's event: lets a held index pass finish
    saved_frames: int = 0  # rows of the unfinished saved index
    error: Exception | None = None

    def call(self, fn: Any, params: dict[str, Any]) -> Any:
        """Run a service method, remembering (instead of raising) expected errors."""
        self.error = None
        try:
            return fn(params, self.ctx)
        except (RpcError, ConfigError, CancelledError, ToolError) as exc:
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


@given("saved indexes are kept")
def cache_on(world: World, tmp_path: Path) -> None:
    world.cache_dir = tmp_path / "index-cache"


@given("saved indexes are not kept")
def cache_off(world: World) -> None:
    world.cache_dir = None


@given(parsers.re(r'the capture "(?P<name>[^"]+)" was opened before$'))
def opened_before(world: World, name: str) -> None:
    open_capture(world, name)
    assert world.error is None, world.error
    if world.cache_dir is not None:
        for _ in range(100):  # the index is saved in the background
            if list(world.cache_dir.glob("*/meta.json")):
                break
            time.sleep(0.05)


@when(parsers.re(r'I open the capture "(?P<name>[^"]+)" again$'))
def open_again(world: World, name: str) -> None:
    open_capture(world, name)


@when(
    parsers.re(
        r'I open the capture "(?P<name>[^"]+)" again with the preference '
        r'"(?P<pref>[^"]+)" set to "(?P<value>[^"]*)"$'
    )
)
def open_again_with_pref(world: World, name: str, pref: str, value: str) -> None:
    open_capture(world, name, {pref: value})


@given("a TLS capture and the key log file that decrypts it")
def given_tls(world: World, tls_keylog: tuple[Path, Path]) -> None:
    world.tls = tls_keylog


@when(
    parsers.re(
        r"I open the TLS capture"
        r'(?: with (?:(?P<its>its key log file)|the key log file "(?P<other>[^"]+)"))?$'
    )
)
def open_tls(world: World, its: str | None, other: str | None) -> None:
    assert world.tls is not None
    capture, keylog = world.tls
    prefs = None
    if its or other:
        prefs = {"tls.keylog_file": str(keylog if its else capture.parent / str(other))}
    open_capture(world, str(capture), prefs)


@given("the TLS capture was opened before with its key log file")
def tls_opened_before(world: World) -> None:
    open_tls(world, "its key log file", None)
    assert world.error is None, world.error
    assert world.cache_dir is not None
    for _ in range(100):  # the index is saved in the background
        if list(world.cache_dir.glob("*/meta.json")):
            break
        time.sleep(0.05)


@when("the key log file gets more keys")
def more_keys(world: World) -> None:
    assert world.tls is not None
    with world.tls[1].open("a") as fh:
        fh.write(f"CLIENT_RANDOM {'ab' * 32} {'cd' * 48}\n")


@then("it opens from the saved index")
def from_saved(world: World) -> None:
    assert world.error is None, world.error
    assert world.info is not None and world.info.get("fromCache") is True


@then("it is indexed again")
def indexed_again(world: World) -> None:
    assert world.error is None, world.error
    assert world.info is not None and "fromCache" not in world.info
    assert any(p.get("phase") == "indexing" for p in world.progress), "an index pass ran"


# ---------------------------------------------------------------------- resuming an index


@given("the index pass is slow")
def index_pass_is_slow(world: World, request: pytest.FixtureRequest) -> None:
    """``slow_index``: the pass shows 3 packets, then crawls and holds after 8
    until indexing is allowed to finish (or the capture is closed)."""
    world.release = request.getfixturevalue("slow_index")


def _open_streaming(world: World, name: str) -> None:
    world.events = []
    world.service.notify = lambda method, p: world.events.append({"method": method, **p})
    open_capture(world, name, stream=True)
    assert world.error is None, world.error


@given(parsers.re(r'the capture "(?P<name>[^"]+)" was closed while it was being indexed$'))
def closed_mid_index(world: World, name: str) -> None:
    _open_streaming(world, name)
    assert world.info is not None and world.info["indexing"] is True
    world.service.close()


@then(parsers.re(r"an unfinished index of fewer than (?P<count>\d+) packets is saved$"))
def unfinished_index_saved(world: World, count: str) -> None:
    assert world.cache_dir is not None
    (meta,) = world.cache_dir.glob("*/meta.json")
    entry = json.loads(meta.read_text())
    assert entry["complete"] is False
    assert 0 < entry["frames"] < int(count)
    world.saved_frames = entry["frames"]


@when(parsers.re(r'I open the capture "(?P<name>[^"]+)" again as a stream$'))
def open_again_streaming(world: World, name: str) -> None:
    _open_streaming(world, name)


@then("the packets indexed before are shown at once, while the capture is read again")
def shown_at_once(world: World) -> None:
    assert world.info is not None and world.info["indexing"] is True
    assert world.info["resumedAt"] == world.saved_frames == world.info["frames"]
    assert len(world.rows()["rows"]) == world.saved_frames


@when("indexing finishes")
def indexing_finishes(world: World) -> None:
    world.release.set()
    _until(lambda: _index_end(world) is not None)
    end = _index_end(world)
    assert end is not None and end["event"] == "done", end
    world.info = end["info"]


@then("indexing caught up with the packets shown before, then went on")
def caught_up_then_indexed(world: World) -> None:
    phases = [
        e["phase"] for e in world.events if e.get("method") == "index" and e["event"] == "progress"
    ]
    assert "catching-up" in phases and "indexing" in phases, phases
    assert phases.index("catching-up") < phases.index("indexing")
    assert "indexing" not in phases[: phases.index("catching-up")]


@then("the packet list is the same as after a full index")
def same_as_full_index(world: World) -> None:
    fresh = PcapService()
    try:
        assert world.info is not None
        fresh.open({"path": world.info["path"], "columns": world.columns}, RequestContext())
        expected = fresh.list_packets({"offset": 0, "limit": 1000}, RequestContext())["rows"]
    finally:
        fresh.shutdown()
    assert world.rows()["rows"] == expected


@then("the saved index is finished")
def saved_index_finished(world: World) -> None:
    assert world.cache_dir is not None
    world.service.close()
    (meta,) = world.cache_dir.glob("*/meta.json")
    entry = json.loads(meta.read_text())
    assert entry["complete"] is True
    assert world.info is not None and entry["frames"] == world.info["frames"]


@given(parsers.parse('the display filter "{expr}" is applied'))
def given_filter(world: World, expr: str) -> None:
    world.filter_result = world.call(world.service.set_filter, {"expr": expr})
    assert world.error is None, world.error


# ---------------------------------------------------------------------- when


@when(parsers.re(r'I open the capture "(?P<name>[^"]+)"$'))
def open_capture(
    world: World, name: str, prefs: dict[str, Any] | None = None, **extra: Any
) -> None:
    params: dict[str, Any] = {
        "path": str(FIXTURES / name),
        "lua": world.lua,
        "decodeAs": world.decode_as,
        "columns": world.columns,
    }
    if prefs:
        params["prefs"] = prefs
    if world.names is not None:
        params["names"] = world.names
    if world.cache_dir is not None:
        params["cache"] = {"dir": str(world.cache_dir)}
    params.update(extra)
    world.progress = []
    world.ctx.progress = lambda p: world.progress.append(dict(p))
    world.info = world.call(world.service.open, params)


@when(parsers.parse('I apply the display filter "{expr}"'))
def apply_filter(world: World, expr: str) -> None:
    world.filter_result = world.call(world.service.set_filter, {"expr": expr})


@when(parsers.re(r'I apply the display filter "(?P<expr>[^"]+)" as a stream$'))
def apply_streaming_filter(world: World, expr: str) -> None:
    world.events = []
    world.service.notify = lambda method, p: world.events.append({"method": method, **p})
    world.filter_result = world.call(world.service.set_filter, {"expr": expr, "stream": True})


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
    index = [p for p in world.progress if p.get("phase") == "indexing"]
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


@then(parsers.re(r"the filter finishes with (?P<count>\d+) matches$"))
def filter_finishes(world: World, count: str) -> None:
    assert world.error is None, world.error
    result = world.filter_result
    assert result is not None
    matches = result["matchCount"]
    if result.get("filtering"):  # the rest arrives as a "filter" notification
        for _ in range(200):
            done = [e for e in world.events if e["method"] == "filter" and e["event"] == "done"]
            if done:
                break
            time.sleep(0.05)
        assert done and done[-1]["filterId"] == result["filterId"], world.events
        matches = done[-1]["matchCount"]
    assert matches == int(count)


@then(
    parsers.re(
        r'applying the display filter "(?P<expr>[^"]+)" uses the saved result '
        r"and displays (?P<count>\d+) packets$"
    )
)
def filter_from_saved(world: World, expr: str, count: str, monkeypatch: pytest.MonkeyPatch) -> None:
    def no_pass(*_args: Any) -> Any:
        raise AssertionError("the saved filter result should be used")

    monkeypatch.setattr(PcapService, "_run_filter", no_pass)
    result = world.service.set_filter({"expr": expr, "stream": True}, world.ctx)
    assert result["matchCount"] == int(count) and "filtering" not in result


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


@when(
    parsers.re(
        r"I request the quick view of packet (?P<number>\d+) "
        r"with a window of (?P<window>\d+) packets$"
    )
)
def quick_view(world: World, number: str, window: str) -> None:
    params = {"number": int(number), "mode": "quick", "window": int(window)}
    world.detail = world.call(world.service.packet_detail, params)


@then(parsers.re(r"the detail is approximate, dissected from packet (?P<first>\d+)$"))
def detail_approximate(world: World, first: str) -> None:
    assert world.detail is not None
    assert world.detail.get("approximate") is True
    assert world.detail["window"] == [int(first), world.detail["number"]]


@then(parsers.re(r'the field "(?P<name>[^"]+)" shows "(?P<value>[^"]*)"$'))
def field_shows(world: World, name: str, value: str) -> None:
    assert world.detail is not None
    node = _find(world.detail["tree"], name)
    assert node is not None, name
    assert node.get("show") == value


@then(parsers.re(r'the tree has no field "(?P<name>[^"]+)"$'))
def no_field(world: World, name: str) -> None:
    assert world.detail is not None
    assert _find(world.detail["tree"], name) is None


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


@given(parsers.re(r'I open the capture "(?P<name>[^"]+)"$'))
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


@then(parsers.re(r'the statistics include "(?P<proto>[^"]+)" with (?P<packets>\d+) packets$'))
def phs_includes(world: World, proto: str, packets: str) -> None:
    rows = [r for r in _table(world)["rows"] if r["cells"][0] == proto]
    assert rows, proto
    assert _stats_cell(world, rows[0], "Packets") == int(packets)


@then(parsers.re(r"the top level of the hierarchy covers (?P<packets>\d+) packets$"))
def phs_top_level(world: World, packets: str) -> None:
    """Depth 0 is eth in tshark 4.2 and a "frame" row above it in 4.6."""
    top = [r for r in _table(world)["rows"] if r["depth"] == 0]
    assert top and sum(_stats_cell(world, r, "Packets") for r in top) == int(packets)


@then(
    parsers.re(
        r'the statistics include "(?P<proto>[^"]+)" one level below "(?P<parent>[^"]+)" '
        r"with (?P<packets>\d+) packets$"
    )
)
def phs_below(world: World, proto: str, parent: str, packets: str) -> None:
    """Depth-independent: tshark 4.6 adds a level above ip (dns: depth 4, was 3)."""
    rows = _table(world)["rows"]
    i = next((i for i, r in enumerate(rows) if r["cells"][0] == proto), None)
    assert i is not None, proto
    depth = rows[i]["depth"]
    up = next(r for r in reversed(rows[:i]) if r["depth"] < depth)  # the parent row
    assert (up["cells"][0], up["depth"]) == (parent, depth - 1)
    assert _stats_cell(world, rows[i], "Packets") == int(packets)


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


def _stats_row(world: World, topic: str, parent: str | None) -> dict[str, Any]:
    """The row whose first cell is ``topic`` (and whose nearest ancestor row,
    by depth, is ``parent`` when given)."""
    rows = _table(world)["rows"]
    for i, row in enumerate(rows):
        if row["cells"][0] != topic:
            continue
        if parent is None:
            return row
        depth = row.get("depth", 0)
        up = next((r for r in reversed(rows[:i]) if r.get("depth", 0) < depth), None)
        if up is not None and up["cells"][0] == parent:
            return row
    raise AssertionError(f"no row {topic!r} below {parent!r}")


@then(
    parsers.re(
        r'the statistics row "(?P<topic>[^"]+)"(?: below "(?P<parent>[^"]+)")? '
        r'has "(?P<label>[^"]+)" (?P<value>\d+)$'
    )
)
def stats_named_row_has(
    world: World, topic: str, parent: str | None, label: str, value: str
) -> None:
    assert _stats_cell(world, _stats_row(world, topic, parent), label) == int(value)


@then(
    parsers.re(
        r'the filter of the statistics row "(?P<topic>[^"]+)"(?: below "(?P<parent>[^"]+)")? '
        r"matches (?P<count>\d+) packets?$"
    )
)
def stats_row_filter_matches(world: World, topic: str, parent: str | None, count: str) -> None:
    row = _stats_row(world, topic, parent)
    assert row.get("filter"), row
    found = world.service.count_matches({"filter": row["filter"]}, RequestContext())
    assert found["count"] == int(count), (row["filter"], found)


@then(
    parsers.re(r'the service response time is for "(?P<protocol>\w+)", out of (?P<available>.+)$')
)
def srt_protocol(world: World, protocol: str, available: str) -> None:
    table = _table(world)
    assert (table["type"], table["available"]) == (protocol, items(available))


# ---------------------------------------------------------------------- dissector check / Decode As


@given("a Lua dissector with a syntax error")
def given_bad_lua(world: World, tmp_path: Path) -> None:
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


@when(parsers.re(r'I open the capture "(?P<name>[^"]+)" with the coloring rules (?P<filters>.+)$'))
def open_with_coloring(world: World, name: str, filters: str) -> None:
    rules = [{"filter": f} for f in items(filters)]
    open_capture(world, name, coloring={"rules": rules})
    assert world.error is None, world.error
    assert world.info is not None
    world.coloring = world.info.get("coloring")


@then("the colors came with the packet list")
def colors_with_open(world: World) -> None:
    assert world.coloring is not None, "the index pass evaluated the rules"
    assert world.rows()["coloringId"] == world.coloring["coloringId"]


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


# ---------------------------------------------------------------------- name resolution

_NAME_SWITCHES = {
    "MAC addresses": "mac",
    "network addresses": "network",
    "the capture's DNS answers": "capturedDns",
    "transport ports": "transport",
}


@given(parsers.re(r"name resolution of (?P<kinds>.+)$"))
def given_names(world: World, kinds: str) -> None:
    world.names = {_NAME_SWITCHES[k]: True for k in items(kinds)}


@given("no name resolution")
def given_no_names(world: World) -> None:
    world.names = {}


@then(
    parsers.re(
        r'the address behind the "(?P<title>Source|Destination)" column '
        r'of row (?P<row>\d+) is "(?P<value>[^"]+)"$'
    )
)
def address_behind(world: World, title: str, row: str, value: str) -> None:
    page = world.page or world.rows()
    r = page["rows"][int(row) - 1]
    assert r["addresses"][0 if title == "Source" else 1] == value


@then(parsers.re(r"no address is sent for row (?P<row>\d+)$"))
def no_address(world: World, row: str) -> None:
    page = world.page or world.rows()
    assert "addresses" not in page["rows"][int(row) - 1]


@then(parsers.re(r'the details of packet (?P<number>\d+) mention "(?P<text>[^"]+)"$'))
def details_mention(world: World, number: str, text: str) -> None:
    tree = world.service.packet_detail({"number": int(number)}, world.ctx)["tree"]

    def labels(nodes: list[dict[str, Any]]) -> list[str]:
        return [n["label"] for n in nodes] + [
            x for n in nodes for x in labels(n.get("children", []))
        ]

    assert any(text in label for label in labels(tree)), text


@then(
    parsers.re(
        r'the statistics column "(?P<label>[^"]+)" includes "(?P<value>[^"]+)" '
        r'but not "(?P<other>[^"]+)"$'
    )
)
def stats_column_includes(world: World, label: str, value: str, other: str) -> None:
    column = [_stats_cell(world, row, label) for row in _table(world)["rows"]]
    assert value in column and other not in column, column


# ---------------------------------------------------------------------- export objects


@given(parsers.re(r'the folder for saved objects already has a file "(?P<name>[^"]+)"$'))
def save_dir_has(world: World, name: str, tmp_path: Path) -> None:
    world.save_dir = tmp_path / "objects"
    world.save_dir.mkdir(exist_ok=True)
    (world.save_dir / name).write_text("already here")


@when("I list the exported objects")
def list_objects(world: World) -> None:
    result = world.call(world.service.export_objects, {})
    world.objects = result["objects"] if result else None


@when("I save every object into the folder")
def save_all_objects(world: World) -> None:
    assert world.objects is not None and world.save_dir is not None
    ids = [o["id"] for o in world.objects]
    world.call(world.service.save_objects, {"ids": ids, "dir": str(world.save_dir)})
    assert world.error is None, world.error


def _object(world: World, name: str) -> dict[str, Any]:
    assert world.error is None, world.error
    assert world.objects is not None
    return next(o for o in world.objects if o["name"] == name)


@then(parsers.re(r"the objects are (?P<names>.+)$"))
def objects_are(world: World, names: str) -> None:
    assert world.error is None, world.error
    assert [o["name"] for o in world.objects or []] == items(names)


@then("there are no objects")
def no_objects(world: World) -> None:
    assert world.error is None, world.error
    assert world.objects == []


@then(
    parsers.re(
        r'the object "(?P<name>[^"]+)" came in packet (?P<frame>\d+)'
        r'(?: from "(?P<host>[^"]+)" as "(?P<ctype>[^"]+)")?$'
    )
)
def object_came_in(
    world: World, name: str, frame: str, host: str | None, ctype: str | None
) -> None:
    obj = _object(world, name)
    assert obj["frame"] == int(frame)
    if host is not None:
        assert (obj["host"], obj["contentType"]) == (host, ctype)


@then(parsers.re(r"the folder has (?P<names>.+)$"))
def folder_has(world: World, names: str) -> None:
    assert world.save_dir is not None
    assert sorted(p.name for p in world.save_dir.iterdir()) == sorted(items(names))


# ---------------------------------------------------------------------- packet comments


@given(parsers.re(r'a copy of the capture "(?P<name>[^"]+)" is open$'))
def given_copy_open(world: World, name: str, tmp_path: Path) -> None:
    copy = tmp_path / name
    copy.write_bytes((FIXTURES / name).read_bytes())
    world.info = world.call(world.service.open, {"path": str(copy)})
    assert world.error is None, world.error
    world.save_dir = tmp_path


def _comments(world: World, frames: list[int]) -> dict[str, str]:
    res = world.service.packet_comments({"frames": frames}, world.ctx)
    found: dict[str, str] = res["comments"]
    return found


@then(parsers.re(r'packet (?P<n>\d+) has the comment "(?P<text>[^"]*)"$'))
def packet_has_comment(world: World, n: str, text: str) -> None:
    assert _comments(world, [int(n)]).get(n) == text.replace("\\n", "\n")


@then(parsers.re(r"packet (?P<n>\d+) has no comment$"))
def packet_has_no_comment(world: World, n: str) -> None:
    assert n not in _comments(world, [int(n)])


@when(parsers.re(r'I set the comment of packet (?P<n>\d+) to "(?P<text>[^"]*)"$'))
def set_comment(world: World, n: str, text: str) -> None:
    edits = dict(world.service._comment_edits)
    edits[int(n)] = text or None
    world.call(world.service.set_comments, {"edits": {str(k): v for k, v in edits.items()}})
    assert world.error is None, world.error


@when(parsers.re(r"I delete the comment of packet (?P<n>\d+)$"))
def delete_comment(world: World, n: str) -> None:
    set_comment(world, n, "")


@when(parsers.re(r"I save the comments (?P<where>into the capture|as a new file)$"))
def save_comments(world: World, where: str) -> None:
    assert world.save_dir is not None
    params: dict[str, Any] = (
        {"inPlace": True}
        if where == "into the capture"
        else {"dest": str(world.save_dir / "saved.pcapng")}
    )
    world.exported = world.call(world.service.save_comments, params)


@then(parsers.re(r"the saved file has comments on packets (?P<frames>.+)$"))
def saved_file_comments(world: World, frames: str) -> None:
    from pcap_backend import comments  # noqa: PLC0415

    assert world.error is None, world.error
    assert world.exported is not None
    saved = comments.read_comments(Path(world.exported["path"]))
    assert sorted(saved) == numbers(frames)


@then(parsers.re(r'saving the comments into the capture is refused with "(?P<text>[^"]+)"$'))
def save_refused(world: World, text: str) -> None:
    world.call(world.service.save_comments, {"inPlace": True, "edits": {"1": "x"}})
    assert world.error is not None and text in str(world.error)


# ---------------------------------------------------------------------- flow and TCP graphs


@when("I request the flow graph")
def request_flow_graph(world: World) -> None:
    world.table = world.call(world.service.flow_graph, {"offset": 0, "limit": 500})


@then(parsers.re(r"the flow graph has (?P<packets>\d+) packets between (?P<nodes>\d+) endpoints$"))
def flow_graph_counts(world: World, packets: str, nodes: str) -> None:
    assert world.error is None, world.error
    assert world.table is not None
    assert world.table["total"] == int(packets)
    assert len(world.table["nodes"]) + world.table["more"] == int(nodes)


@then(parsers.re(r"the first endpoints of the flow graph are (?P<names>.+)$"))
def flow_graph_first_nodes(world: World, names: str) -> None:
    assert world.table is not None
    expected = items(names)
    assert world.table["nodes"][: len(expected)] == expected


@when(parsers.re(r"I request the TCP stream graph of packet (?P<n>\d+)$"))
def request_tcp_graph(world: World, n: str) -> None:
    world.table = world.call(world.service.tcp_graph, {"frame": int(n)})


@then(
    parsers.re(
        r'the TCP stream graph shows stream (?P<stream>\d+) between "(?P<a>[^"]+)" '
        r'and "(?P<b>[^"]+)" with (?P<count>\d+) packets$'
    )
)
def tcp_graph_shows(world: World, stream: str, a: str, b: str, count: str) -> None:
    assert world.error is None, world.error
    assert world.table is not None
    assert world.table["stream"] == int(stream)
    assert world.table["endpoints"] == [a, b]
    assert len(world.table["points"]) == int(count)


# ---------------------------------------------------------------------- live capture


def _until(check: Any, timeout: float = 20) -> None:
    deadline = time.monotonic() + timeout
    while not check():
        assert time.monotonic() < deadline, "timed out"
        time.sleep(0.02)


def _index_end(world: World) -> dict[str, Any] | None:
    return next(
        (e for e in world.events if e.get("method") == "index" and e["event"] != "progress"),
        None,
    )


def _stand_in(world: World, monkeypatch: pytest.MonkeyPatch, **env: str) -> None:
    import sys  # noqa: PLC0415

    monkeypatch.setenv(
        "PCAP_VIEWER_DUMPCAP", json.dumps([sys.executable, str(FIXTURES / "fake_dumpcap.py")])
    )
    monkeypatch.setenv("FAKE_DUMPCAP_DELAY", "0.05")
    for key, value in env.items():
        monkeypatch.setenv(key, value)
    world.service.notify = lambda method, params: world.events.append({"method": method, **params})


@given(parsers.re(r'a stand-in dumpcap that replays "(?P<name>[^"]+)"$'))
def stand_in_dumpcap(world: World, monkeypatch: pytest.MonkeyPatch, name: str) -> None:
    _stand_in(world, monkeypatch, FAKE_DUMPCAP_SOURCE=str(FIXTURES / name))


@given("a stand-in dumpcap without permission to capture")
def stand_in_denied(world: World, monkeypatch: pytest.MonkeyPatch) -> None:
    _stand_in(
        world,
        monkeypatch,
        FAKE_DUMPCAP_FAIL="You don't have permission to capture on that device "
        "(socket: Operation not permitted)",
    )


@when(
    parsers.re(
        r'I start capturing on "(?P<iface>[^"]+)"'
        r'(?: with the capture filter "(?P<flt>[^"]*)")?'
        r"(?: stopping after (?P<packets>\d+) packets)?$"
    )
)
def start_capturing(
    world: World, tmp_path: Path, iface: str, flt: str | None, packets: str | None
) -> None:
    params: dict[str, Any] = {
        "dest": str(tmp_path / "live.pcapng"),
        "interfaces": [iface],
        "filter": flt or "",
    }
    if packets:
        params["limits"] = {"packets": int(packets)}
    world.info = world.call(world.service.capture_start, params)


@then("the capture is running")
def capture_running(world: World) -> None:
    assert world.error is None, world.error
    assert world.info is not None and world.info["capture"]["running"] is True
    assert world.info["indexing"] is True


@then("packets appear in the list while capturing")
def packets_appear(world: World) -> None:
    _until(lambda: world.rows(limit=50)["total"] >= 5)
    assert _index_end(world) is None, "still capturing"


@when("I stop the capture")
def stop_capture(world: World) -> None:
    assert world.service.capture_stop({}, world.ctx) == {"stopped": True}


@then("the capture stops with a complete file")
def capture_complete(world: World) -> None:
    _until(lambda: _index_end(world) is not None)
    end = _index_end(world)
    assert end is not None and end["event"] == "done", end
    stopped = next(
        e for e in world.events if e.get("method") == "capture" and e["event"] == "stopped"
    )
    assert end["info"]["frames"] == stopped["packets"] >= 5
    assert end["info"]["capture"]["running"] is False


@then("sorting works again")
def sorting_works(world: World) -> None:
    page = world.rows(limit=5, sort={"field": "frame.len", "desc": True})
    lengths = [int(r["cells"][TITLE_TO_INDEX["Length"]]) for r in page["rows"]]
    assert lengths == sorted(lengths, reverse=True)


@then(parsers.re(r"the capture stops by itself with (?P<count>\d+) packets$"))
def capture_stops_itself(world: World, count: str) -> None:
    assert world.error is None, world.error
    _until(lambda: _index_end(world) is not None)
    end = _index_end(world)
    assert end is not None and end["info"]["frames"] == int(count)


@then(
    parsers.re(
        r'the capture filter "(?P<flt>[^"]*)" is (?P<result>valid|invalid) for "(?P<iface>[^"]+)"$'
    )
)
def capture_filter_check(world: World, flt: str, result: str, iface: str) -> None:
    res = world.service.validate_capture_filter({"filter": flt, "interface": iface}, world.ctx)
    assert res["valid"] is (result == "valid"), res


# ---------------------------------------------------------------------- capture editing


@given(parsers.re(r'the capture "(?P<name>[^"]+)" merged with itself is open$'))
def open_doubled(world: World, tmp_path: Path, name: str) -> None:
    import subprocess  # noqa: PLC0415

    from pcap_backend.tshark import find_tool  # noqa: PLC0415

    doubled = tmp_path / f"doubled-{name}"
    source = FIXTURES / name
    subprocess.run(
        [str(find_tool("mergecap")), "-w", str(doubled), str(source), str(source)], check=True
    )
    world.info = world.call(world.service.open, {"path": str(doubled)})
    assert world.error is None, world.error


def _edit(world: World, tmp_path: Path, **params: Any) -> None:
    world.exported = world.call(
        world.service.edit_capture, {"dest": str(tmp_path / "edited.pcapng"), **params}
    )
    assert world.error is None, world.error


@when(parsers.re(r'I shift the capture\'s time by "(?P<offset>[^"]+)"$'))
def shift_time(world: World, tmp_path: Path, offset: str) -> None:
    _edit(world, tmp_path, operation="timeShift", offset=offset)


@when(parsers.re(r'I keep the packets "(?P<frames>[^"]+)"$'))
def keep_packets(world: World, tmp_path: Path, frames: str) -> None:
    _edit(world, tmp_path, operation="keep", frames=frames)


@when("I remove the duplicate packets")
def remove_duplicates(world: World, tmp_path: Path) -> None:
    _edit(world, tmp_path, operation="dedup")


@when(parsers.re(r"I split the capture every (?P<n>\d+) packets$"))
def split_capture(world: World, tmp_path: Path, n: str) -> None:
    out = tmp_path / "pieces"
    out.mkdir()
    world.exported = world.call(
        world.service.edit_capture, {"operation": "split", "packets": int(n), "dir": str(out)}
    )
    assert world.error is None, world.error


@then(parsers.re(r"the edited capture has (?P<count>\d+) packets$"))
def edited_count(world: World, count: str) -> None:
    assert world.exported is not None and world.exported["packets"] == int(count)


@then(parsers.re(r"the edited capture starts at (?P<epoch>[\d.]+)$"))
def edited_start(world: World, epoch: str) -> None:
    assert world.exported is not None
    info = world.service.open({"path": world.exported["path"]}, world.ctx)
    assert info["startTime"] == pytest.approx(float(epoch), abs=1e-6)


@then(parsers.re(r"(?P<count>\d+) duplicates were removed$"))
def duplicates_removed(world: World, count: str) -> None:
    assert world.exported is not None and world.exported["removed"] == int(count)


@then(parsers.re(r"it is split into files of (?P<counts>.+) packets$"))
def split_into(world: World, counts: str) -> None:
    from pcap_backend import comments  # noqa: PLC0415

    assert world.exported is not None
    files = [Path(p) for p in world.exported["files"]]
    assert [comments.packet_count(p) for p in files] == numbers(counts)


# ---------------------------------------------------------------------- AI tools


@when(parsers.re(r'I count the packets matching "(?P<expr>[^"]*)"$'))
def count_matching(world: World, expr: str) -> None:
    world.found = world.call(world.service.count_matches, {"filter": expr})


@then(parsers.re(r"(?P<count>\d+) of (?P<total>\d+) packets match$"))
def counted(world: World, count: str, total: str) -> None:
    assert world.error is None, world.error
    assert world.found is not None
    assert (world.found["count"], world.found["total"]) == (int(count), int(total))


# ---------------------------------------------------------------------- VoIP


def _voip(world: World) -> dict[str, Any]:
    if world.voip is None:
        world.voip = world.service.voip_calls({}, world.ctx)
    return world.voip


def _rtp_stream(world: World, source: str) -> dict[str, Any]:
    addr, port = source.rsplit(":", 1)
    return next(s for s in _voip(world)["streams"] if (s["src"], s["srcPort"]) == (addr, int(port)))


@when("I list the VoIP calls")
def list_voip_calls(world: World) -> None:
    world.voip = None
    _voip(world)


@then(parsers.re(r"there are (?P<calls>\d+) SIP calls and (?P<streams>\d+) RTP streams$"))
def voip_counts(world: World, calls: str, streams: str) -> None:
    result = _voip(world)
    assert (len(result["calls"]), len(result["streams"])) == (int(calls), int(streams))


@then(
    parsers.re(
        r'call (?P<n>\d+) goes from "(?P<frm>[^"]+)" to "(?P<to>[^"]+)" and is (?P<state>[\w ]+?)'
        r'(?: with "(?P<reason>[^"]+)")?$'
    )
)
def call_is(world: World, n: str, frm: str, to: str, state: str, reason: str | None) -> None:
    call = _voip(world)["calls"][int(n) - 1]
    assert (call["from"], call["to"], call["state"]) == (frm, to, state)
    assert call["reason"] == (reason or "")


@then(parsers.re(r"call (?P<n>\d+) has the messages (?P<labels>.+)$"))
def call_messages(world: World, n: str, labels: str) -> None:
    call = _voip(world)["calls"][int(n) - 1]
    assert [m[4] for m in call["messages"]] == items(labels)


@then(parsers.re(r"call (?P<n>\d+) has both RTP streams$"))
def call_streams(world: World, n: str) -> None:
    result = _voip(world)
    assert sorted(result["calls"][int(n) - 1]["streams"]) == list(range(len(result["streams"])))


@then(
    parsers.re(
        r'the RTP stream from "(?P<source>[^"]+)" has (?P<packets>\d+) packets '
        r"and (?P<lost>\d+) lost$"
    )
)
def stream_counts(world: World, source: str, packets: str, lost: str) -> None:
    stream = _rtp_stream(world, source)
    assert (stream["packets"], stream["lost"]) == (int(packets), int(lost))


@when(parsers.re(r'I analyse the RTP stream from "(?P<source>[^"]+)"$'))
def analyse_rtp_stream(world: World, source: str) -> None:
    world.table = world.service.rtp_stream({"stream": _rtp_stream(world, source)}, world.ctx)
    world.table["report"] = _rtp_stream(world, source)


@then(
    parsers.re(
        r"the analysis counts (?P<packets>\d+) of (?P<expected>\d+) packets "
        r"with (?P<lost>\d+) lost$"
    )
)
def analysis_counts(world: World, packets: str, expected: str, lost: str) -> None:
    assert world.table is not None
    summary = world.table["summary"]
    assert (summary["packets"], summary["expected"], summary["lost"]) == (
        int(packets), int(expected), int(lost),
    )  # fmt: skip


@then("its maximum and mean jitter are those of tshark's RTP streams report")
def analysis_jitter(world: World) -> None:
    assert world.table is not None
    summary, report = world.table["summary"], world.table["report"]
    assert summary["maxJitter"] == pytest.approx(report["maxJitter"], abs=0.002)
    assert summary["meanJitter"] == pytest.approx(report["meanJitter"], abs=0.002)


@then(parsers.re(r"packet (?P<frame>\d+) comes after (?P<gap>\d+) lost packets?$"))
def analysis_gap(world: World, frame: str, gap: str) -> None:
    assert world.table is not None
    flagged = [(p[0], p[8]) for p in world.table["points"] if p[7] == 1]
    assert flagged == [(int(frame), int(gap))]


@when(parsers.re(r'I save the audio of the RTP stream from "(?P<source>[^"]+)"$'))
def save_rtp_audio(world: World, source: str, tmp_path: Path) -> None:
    world.saved = tmp_path / "audio.wav"
    world.service.rtp_audio(
        {"stream": _rtp_stream(world, source), "dest": str(world.saved)}, world.ctx
    )


@then(
    parsers.re(
        r"the file is (?P<seconds>\d+) seconds? of (?P<rate>\d+) Hz WAV audio "
        r"with a (?P<tone>\d+) Hz tone$"
    )
)
def wav_tone(world: World, seconds: str, rate: str, tone: str) -> None:
    assert world.saved is not None
    with wave.open(str(world.saved), "rb") as wav:
        assert wav.getframerate() == int(rate)
        samples = array("h", wav.readframes(wav.getnframes()))
    if sys.byteorder == "big":
        samples.byteswap()
    assert len(samples) == int(seconds) * int(rate)
    crossings = sum(1 for a, b in itertools.pairwise(samples) if (a < 0) != (b < 0))
    assert crossings / 2 / int(seconds) == pytest.approx(int(tone), rel=0.02)


@when(parsers.re(r'I apply the filter of the RTP stream from "(?P<source>[^"]+)"$'))
def apply_stream_filter(world: World, source: str) -> None:
    world.filter_result = world.call(
        world.service.set_filter, {"expr": _rtp_stream(world, source)["filter"]}
    )
