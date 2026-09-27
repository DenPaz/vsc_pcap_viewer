"""Export and coloring: pure helpers plus integration tests against tshark."""

import csv
import io
import json
import subprocess
from pathlib import Path

import pytest

from pcap_backend import coloring
from pcap_backend.export import PacketListWriter, atomic_output, check_destination, csv_cell
from pcap_backend.pcap_service import PcapService
from pcap_backend.protocol import FilterError, InvalidParamsError, RequestContext
from pcap_backend.tshark import find_tool

# ---------------------------------------------------------------------- pure helpers


def test_check_destination_refuses_the_open_capture(tmp_path: Path) -> None:
    capture = tmp_path / "a.pcap"
    capture.write_bytes(b"x")
    (tmp_path / "sub").mkdir()
    with pytest.raises(InvalidParamsError, match="open capture"):
        check_destination(str(capture), capture)
    with pytest.raises(InvalidParamsError, match="open capture"):
        check_destination(str(tmp_path / "sub" / ".." / "a.pcap"), capture)
    with pytest.raises(InvalidParamsError, match="absolute"):
        check_destination("relative.pcapng", capture)
    with pytest.raises(InvalidParamsError, match="does not exist"):
        check_destination(str(tmp_path / "missing" / "out.pcapng"), capture)
    with pytest.raises(InvalidParamsError, match="folder"):
        check_destination(str(tmp_path / "sub"), capture)
    assert check_destination(str(tmp_path / "out.pcapng"), capture) == tmp_path / "out.pcapng"


def test_atomic_output_only_replaces_on_success(tmp_path: Path) -> None:
    dest = tmp_path / "out.csv"
    dest.write_text("old")

    def fail_midway() -> None:
        with atomic_output(dest) as tmp:
            tmp.write_text("partial")
            raise RuntimeError

    with pytest.raises(RuntimeError):
        fail_midway()
    assert dest.read_text() == "old"
    assert list(tmp_path.iterdir()) == [dest]
    with atomic_output(dest) as tmp:
        tmp.write_text("new")
    assert dest.read_text() == "new"
    assert list(tmp_path.iterdir()) == [dest]


def test_csv_cell_neutralises_formulas() -> None:
    assert csv_cell("=HYPERLINK(1)") == "'=HYPERLINK(1)"
    assert csv_cell("+1") == "'+1"
    assert csv_cell("@SUM(A1)") == "'@SUM(A1)"
    assert csv_cell("-cmd") == "'-cmd"
    assert csv_cell("-1.5") == "-1.5"
    assert csv_cell("GET / HTTP/1.1") == "GET / HTTP/1.1"


def test_packet_list_writer_csv_and_json() -> None:
    rows = [["1", "0.000000", "a,b", "=x"], ["2", "1.5", 'say "hi"', ""]]
    out = io.StringIO()
    w = PacketListWriter(out, "csv", ["No.", "Time", "Info", "Host"], [], [])
    w.write(rows)
    w.close()
    parsed = list(csv.reader(io.StringIO(out.getvalue())))
    assert parsed == [["No.", "Time", "Info", "Host"], ["1", "0.000000", "a,b", "'=x"], ["2", "1.5", 'say "hi"', ""]]  # fmt: skip
    assert out.getvalue().startswith('"No.","Time"')

    out = io.StringIO()
    w = PacketListWriter(out, "json", [], ["number", "time", "info", "http.host"], [True, True, False, False])  # fmt: skip
    w.write(rows)
    w.close()
    assert json.loads(out.getvalue()) == [
        {"number": 1, "time": 0.0, "info": "a,b", "http.host": "=x"},
        {"number": 2, "time": 1.5, "info": 'say "hi"', "http.host": ""},
    ]
    empty = io.StringIO()
    PacketListWriter(empty, "json", [], ["number"], [True]).close()
    assert json.loads(empty.getvalue()) == []


def test_parse_rule_validation() -> None:
    rule = coloring.parse_rule({"filter": " tcp \n && udp ", "background": "#A0B0C0"})
    assert rule == coloring.ColorRule("tcp && udp", "#000000", "#a0b0c0")
    assert coloring.parse_rule({"filter": ""}) == "rule has no filter"
    assert "@" in str(coloring.parse_rule({"filter": 'sip.from contains "@"'}))
    assert "foreground" in str(coloring.parse_rule({"filter": "tcp", "foreground": "red"}))
    assert coloring.parse_rule("tcp") == "rule must be an object"


def test_colorfilters_text_names_rules_by_index() -> None:
    rules: list[coloring.ColorRule | str] = [
        coloring.ColorRule("dns", "#000000", "#ffffff"),
        "bad rule",
        coloring.ColorRule("tcp", "#ff0000", "#0000ff"),
    ]
    assert coloring.colorfilters_text(rules) == (
        "@0@dns@[0,0,0][65535,65535,65535]\n@2@tcp@[65535,0,0][0,0,65535]\n"
    )


def test_parse_compile_errors() -> None:
    stderr = (
        'tshark: Disabling color filter: Could not compile "3" in colorfilters file "/t/c".\n'
        '"foo.bar" is neither a field nor a protocol name.\n'
    )
    assert coloring.parse_compile_errors(stderr) == {
        3: '"foo.bar" is neither a field nor a protocol name.'
    }


def test_personal_config_dir(tmp_path: Path) -> None:
    out = f"Temp:\t/tmp\nPersonal configuration:\t{tmp_path}\nGlobal configuration:\t/usr\n"
    assert coloring.personal_config_dir(out) == tmp_path
    assert coloring.personal_config_dir("Personal configuration:\t/does/not/exist\n") is None


def test_prepare_config_dir_copies_personal_files(tmp_path: Path) -> None:
    personal = tmp_path / "personal"
    personal.mkdir()
    (personal / "preferences").write_text("x")
    (personal / "colorfilters").write_text("theirs")
    (personal / "profiles").mkdir()
    target = tmp_path / "target"
    target.mkdir()
    coloring.prepare_config_dir(target, [coloring.ColorRule("dns", "#000000", "#ffffff")], personal)
    assert sorted(p.name for p in target.iterdir()) == ["colorfilters", "preferences"]
    assert (target / "colorfilters").read_text().startswith("@0@dns@")


# ---------------------------------------------------------------------- integration


def _count(tshark_file: Path) -> int:
    out = subprocess.run(
        [str(find_tool("tshark")), "-r", str(tshark_file), "-T", "fields", "-e", "frame.number"],
        capture_output=True,
        check=True,
    ).stdout
    return len(out.split())


@pytest.mark.tshark
def test_export_filtered_pcapng(opened: PcapService, ctx: RequestContext, tmp_path: Path) -> None:
    opened.set_filter({"expr": "http"}, ctx)
    events: list[dict[str, object]] = []
    ctx.progress = lambda p: events.append(dict(p))
    dest = tmp_path / "http only.pcapng"
    res = opened.export({"kind": "pcapng", "dest": str(dest)}, ctx)
    assert res["ok"] and res["path"] == str(dest)
    assert res["packets"] == 2 and res["filter"] == "http"
    assert res["size"] == dest.stat().st_size > 0
    assert dest.read_bytes()[:4] == bytes.fromhex("0a0d0d0a")  # pcapng section header
    assert _count(dest) == 2
    assert events and events[0]["phase"] == "export"
    assert sorted(p.name for p in tmp_path.iterdir()) == ["http only.pcapng"]


@pytest.mark.tshark
def test_export_all_as_pcap_and_explicit_filter(
    opened: PcapService, ctx: RequestContext, tmp_path: Path
) -> None:
    opened.set_filter({"expr": "http"}, ctx)
    everything = opened.export(
        {"kind": "pcap", "dest": str(tmp_path / "all.pcap"), "filter": ""}, ctx
    )
    assert everything["packets"] == 11
    assert (tmp_path / "all.pcap").read_bytes()[:4] == bytes.fromhex("d4c3b2a1")
    assert _count(tmp_path / "all.pcap") == 11
    one = opened.export({"kind": "pcapng", "dest": str(tmp_path / "one.pcapng"), "filter": "frame.number == 4"}, ctx)  # fmt: skip
    assert one["packets"] == 1
    with pytest.raises(FilterError):
        opened.export({"kind": "pcapng", "dest": str(tmp_path / "bad.pcapng"), "filter": "tcp.port =="}, ctx)  # fmt: skip
    assert not (tmp_path / "bad.pcapng").exists()


@pytest.mark.tshark
def test_export_refuses_to_overwrite_capture(
    service: PcapService, fixtures: Path, ctx: RequestContext, tmp_path: Path
) -> None:
    capture = tmp_path / "copy.pcap"
    capture.write_bytes((fixtures / "http.pcap").read_bytes())
    service.open({"path": str(capture)}, ctx)
    with pytest.raises(InvalidParamsError, match="open capture"):
        service.export({"kind": "pcapng", "dest": str(capture)}, ctx)
    assert capture.read_bytes() == (fixtures / "http.pcap").read_bytes()


@pytest.mark.tshark
def test_export_packet_list_follows_view(
    opened: PcapService, ctx: RequestContext, tmp_path: Path
) -> None:
    opened.set_filter({"expr": "tcp"}, ctx)
    opened.list_packets(
        {"offset": 0, "limit": 1, "sort": {"field": "frame.len", "desc": True}}, ctx
    )
    res = opened.export(
        {"kind": "csv", "dest": str(tmp_path / "list.csv"), "columns": ["http.host", "bogus.field"], "titles": ["Host"]},
        ctx,
    )  # fmt: skip
    assert res["packets"] == 11 and res["columns"][-1] == "http.host"
    rows = list(csv.reader(io.StringIO((tmp_path / "list.csv").read_text(encoding="utf-8"))))
    assert rows[0] == ["No.", "Time", "Source", "Destination", "Protocol", "Length", "Info", "Host"]
    lengths = [int(r[5]) for r in rows[1:]]
    assert lengths == sorted(lengths, reverse=True)  # current sort order
    assert "example.com" in {r[7] for r in rows[1:]}

    opened.set_filter({"expr": "http"}, ctx)
    res = opened.export({"kind": "json", "dest": str(tmp_path / "list.json")}, ctx)
    data = json.loads((tmp_path / "list.json").read_text(encoding="utf-8"))
    assert res["packets"] == len(data) == 2
    assert data[0]["protocol"] == "HTTP" and isinstance(data[0]["number"], int)
    assert set(data[0]) == {"number", "time", "source", "destination", "protocol", "length", "info"}


@pytest.mark.tshark
def test_export_packet_bytes(opened: PcapService, ctx: RequestContext, tmp_path: Path) -> None:
    res = opened.export({"kind": "bytes", "dest": str(tmp_path / "f4.bin"), "number": 4}, ctx)
    data = (tmp_path / "f4.bin").read_bytes()
    assert res["bytes"] == len(data) == 144
    assert b"GET /index.html" in data
    with pytest.raises(InvalidParamsError):
        opened.export({"kind": "bytes", "dest": str(tmp_path / "x.bin"), "number": 4, "source": 3}, ctx)  # fmt: skip


@pytest.mark.tshark
def test_set_coloring_first_match_wins(
    service: PcapService, fixtures: Path, ctx: RequestContext
) -> None:
    service.open({"path": str(fixtures / "mixed.pcapng")}, ctx)
    before = service.list_packets({"offset": 0, "limit": 30}, ctx)
    assert before["coloringId"] == 0 and all("color" not in r for r in before["rows"])
    res = service.set_coloring(
        {
            "rules": [
                {"filter": "dns", "background": "#ddeeff"},
                {"filter": "frame.len > 0 && nosuch.field"},
                {"filter": "udp", "foreground": "#ff0000"},
                {"filter": "bad @ rule"},
                {"filter": "tcp || udp"},
            ]
        },
        ctx,
    )
    assert set(res["errors"]) == {"1", "3"}
    assert "nosuch.field" in res["errors"]["1"]
    page = service.list_packets({"offset": 0, "limit": 30}, ctx)
    assert page["coloringId"] == res["coloringId"] > 0
    by_proto = {r["cells"][4]: r.get("color") for r in page["rows"]}
    assert by_proto["DNS"] == 0  # dns matches before udp
    assert by_proto["UDP"] == 2
    assert by_proto["HTTP"] == 4
    assert by_proto["ARP"] is None
    assert res["colored"] == sum(1 for r in page["rows"] if "color" in r)

    off = service.set_coloring({"rules": []}, ctx)
    page = service.list_packets({"offset": 0, "limit": 30}, ctx)
    assert off["colored"] == 0 and page["coloringId"] == 0
    assert all("color" not in r for r in page["rows"])


@pytest.mark.tshark
def test_default_coloring_rules_compile(
    service: PcapService, fixtures: Path, ctx: RequestContext
) -> None:
    """The defaults shipped in package.json must all be valid for tshark."""
    manifest = json.loads((fixtures.parent.parent / "package.json").read_text(encoding="utf-8"))
    setting = manifest["contributes"]["configuration"]["properties"]["pcapViewer.coloringRules"]
    rules = setting["default"]
    assert len(rules) >= 10
    service.open({"path": str(fixtures / "mixed.pcapng")}, ctx)
    res = service.set_coloring({"rules": rules}, ctx)
    assert res["errors"] == {}
    page = service.list_packets({"offset": 0, "limit": 30}, ctx)
    names = {r["cells"][4]: rules[r["color"]]["name"] for r in page["rows"] if "color" in r}
    assert names["ARP"] == "ARP"
    assert names["DNS"] == "DNS"
    assert names["UDP"] == "UDP"
