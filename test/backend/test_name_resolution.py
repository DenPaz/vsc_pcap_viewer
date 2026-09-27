"""Name resolution: -N switches, names in the list and details, addresses kept."""

from pathlib import Path
from typing import Any

import pytest

from pcap_backend.index_cache import index_key
from pcap_backend.pcap_service import UNRESOLVED_FIELDS, PcapService
from pcap_backend.protocol import InvalidParamsError, RequestContext
from pcap_backend.tshark import ConfigError, DissectionOptions, name_flags

ALL = {"mac": True, "network": True, "capturedDns": True, "transport": True}


def test_name_flags() -> None:
    assert name_flags({}) == ""
    assert name_flags({"mac": True}) == "m"
    assert name_flags(ALL) == "mndt"
    assert name_flags({**ALL, "external": True}) == "mndNt"
    # DNS answers and external lookups only make sense with network names.
    assert name_flags({"capturedDns": True, "external": True, "transport": True}) == "t"
    with pytest.raises(ConfigError):
        name_flags({"geoip": True})


def test_options_args() -> None:
    assert DissectionOptions().args() == [], "no switches: tshark's own preferences"
    assert DissectionOptions.from_params(names={}).args() == ["-n"]
    assert DissectionOptions.from_params(names={"mac": True}).args() == ["-N", "m"]
    assert DissectionOptions.from_params(names={"transport": True}).resolves_addresses is False
    assert DissectionOptions.from_params(names={"network": True}).resolves_addresses


def test_index_key_depends_on_names(tmp_path: Path) -> None:
    capture = tmp_path / "c.pcap"
    capture.write_bytes(b"x")
    common: dict[str, Any] = {
        "capture": capture,
        "tshark": Path("/usr/bin/tshark"),
        "tshark_version": "TShark 4.2",
        "lua_scripts": [],
        "decode_as": [],
        "prefs": {},
        "columns": [],
        "config": [],
    }
    keys = {index_key(**common, names=n) for n in (None, "", "m", "mnd")}
    assert len(keys) == 4


def _rows(svc: PcapService, ctx: RequestContext) -> dict[int, dict[str, Any]]:
    return {r["number"]: r for r in svc.list_packets({"offset": 0, "limit": 100}, ctx)["rows"]}


@pytest.mark.tshark
def test_names_in_the_list_with_addresses_kept(
    service: PcapService, ctx: RequestContext, fixtures: Path
) -> None:
    service.open({"path": str(fixtures / "mixed.pcapng"), "names": ALL}, ctx)
    rows = _rows(service, ctx)
    # 93.184.216.34 is example.com in the capture's own DNS answer.
    assert rows[11]["cells"][2:4] == ["example.com", "192.168.1.10"]
    assert rows[11]["addresses"] == ["93.184.216.34", "192.168.1.10"]
    assert "http(80)" in rows[11]["cells"][6], "transport names"
    assert rows[1]["cells"][3] == "Broadcast"
    assert rows[1]["addresses"] == ["02:00:00:00:00:01", "ff:ff:ff:ff:ff:ff"]
    assert "addresses" not in rows[26], "nothing resolved: no addresses sent"
    tree = service.packet_detail({"number": 11}, ctx)["tree"]
    assert any("Src: example.com (93.184.216.34)" in n["label"] for n in tree)
    # Resolved fields filter like Wireshark's.
    service.set_filter({"expr": 'ip.src_host == "example.com"'}, ctx)
    assert service.list_packets({"offset": 0, "limit": 100}, ctx)["rows"][0]["number"] == 11


@pytest.mark.tshark
def test_no_names(service: PcapService, ctx: RequestContext, fixtures: Path) -> None:
    service.open({"path": str(fixtures / "mixed.pcapng"), "names": {}}, ctx)
    rows = _rows(service, ctx)
    assert rows[1]["cells"][3] == "ff:ff:ff:ff:ff:ff"
    assert rows[11]["cells"][6].startswith("80 → 50000")
    assert all("addresses" not in r for r in rows.values())
    f = service._file
    assert f is not None and not set(UNRESOLVED_FIELDS) & set(f.base.fields), "not stored"


@pytest.mark.tshark
def test_reports_keep_addresses(service: PcapService, ctx: RequestContext, fixtures: Path) -> None:
    """Statistics rows become address filters, so -z reports never show names."""
    service.open({"path": str(fixtures / "mixed.pcapng"), "names": ALL}, ctx)
    table = service.stats({"kind": "endpoints", "type": "eth"}, ctx)
    addresses = [row["cells"][0] for row in table["rows"]]
    assert "ff:ff:ff:ff:ff:ff" in addresses and "Broadcast" not in addresses
    table = service.stats({"kind": "conversations", "type": "tcp"}, ctx)
    assert all("example.com" not in str(row["cells"]) for row in table["rows"])


def test_names_param_must_be_an_object(service: PcapService, ctx: RequestContext) -> None:
    with pytest.raises(InvalidParamsError):
        service.open({"path": __file__, "names": "mnd"}, ctx)
