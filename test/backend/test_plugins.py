"""tshark_plugins (Show TShark Plugins): the plugins tshark loads, which come
from the user's own folders, and where a dissector plugin goes."""

import os
from pathlib import Path

import pytest

from pcap_backend import plugins, tshark
from pcap_backend.pcap_service import PcapService
from pcap_backend.protocol import RequestContext

AS_ROOT = hasattr(os, "geteuid") and os.geteuid() == 0

# tshark 4.6 output: the name padded with spaces before the tab; Lua scripts
# have no version.
PLUGINS = (
    "ethercat.so     \t0.1.0\tdissector\t/usr/lib/wireshark/plugins/4.6/epan/ethercat.so\n"
    "li_dissectors.so\t1.0.0\tdissector\t/home/u/.local/lib/wireshark/plugins/4.6/epan/li_dissectors.so\n"
    "g711.so         \t0.1.0\tcodec\t/usr/lib/wireshark/plugins/4.6/codecs/g711.so\n"
    "mine.lua\t\tlua script\t/home/u/.local/lib/wireshark/plugins/mine.lua\n"
    "\n"
)
FOLDERS = (
    "Personal configuration:\t/home/u/.config/wireshark\n"
    "Personal Plugins:    \t/home/u/.local/lib/wireshark/plugins/4.6\n"
    "Global Plugins:      \t/usr/lib/wireshark/plugins/4.6\n"
    "Personal Lua Plugins:\t/home/u/.local/lib/wireshark/plugins\n"
    "Global Lua Plugins:  \t/usr/lib/wireshark/plugins\n"
)


def test_parse_plugins() -> None:
    parsed = plugins.parse_plugins(PLUGINS)
    assert [p["name"] for p in parsed] == ["ethercat.so", "li_dissectors.so", "g711.so", "mine.lua"]
    assert parsed[0] == {
        "name": "ethercat.so",
        "version": "0.1.0",
        "type": "dissector",
        "path": "/usr/lib/wireshark/plugins/4.6/epan/ethercat.so",
    }
    assert parsed[3]["version"] == ""
    assert parsed[3]["type"] == "lua script"


def test_plugin_folders() -> None:
    assert plugins.plugin_folders(FOLDERS) == {
        "personalPlugins": "/home/u/.local/lib/wireshark/plugins/4.6",
        "globalPlugins": "/usr/lib/wireshark/plugins/4.6",
        "personalLuaPlugins": "/home/u/.local/lib/wireshark/plugins",
        "globalLuaPlugins": "/usr/lib/wireshark/plugins",
    }
    # A tshark without Lua names no Lua folders.
    no_lua = plugins.plugin_folders("Personal Plugins:\t/p/4.6\nGlobal Plugins:\t/g/4.6\n")
    assert no_lua["personalLuaPlugins"] is None
    assert no_lua["globalLuaPlugins"] is None


@pytest.mark.skipif(os.name == "nt", reason="POSIX paths in the sample")
def test_describe_marks_and_lists_personal_plugins_first() -> None:
    out = plugins.describe(PLUGINS, FOLDERS, as_root=False)
    assert [(p["name"], p["personal"]) for p in out["plugins"]] == [
        ("li_dissectors.so", True),
        ("mine.lua", True),
        ("ethercat.so", False),
        ("g711.so", False),
    ]
    assert out["install"] == "/home/u/.local/lib/wireshark/plugins/4.6/epan"
    assert out["warnings"] == []
    # A folder whose name merely starts like the personal one isn't inside it.
    other = "x.lua\t\tlua script\t/home/u/.local/lib/wireshark/plugins-old/x.lua\n"
    assert plugins.describe(other, FOLDERS, as_root=False)["plugins"][0]["personal"] is False


def test_describe_warns_as_root() -> None:
    out = plugins.describe(PLUGINS, FOLDERS, as_root=True)
    assert "root" in out["warnings"][0]
    assert plugins.describe("", "", as_root=False) == {
        "plugins": [],
        "folders": dict.fromkeys(
            ["personalPlugins", "globalPlugins", "personalLuaPlugins", "globalLuaPlugins"]
        ),
        "install": None,
        "warnings": [],
    }


@pytest.mark.tshark
@pytest.mark.skipif(AS_ROOT, reason="Wireshark ignores personal plugins as root")
def test_tshark_plugins_reports_a_personal_plugin(
    service: PcapService, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # A personal Lua plugin: tshark loads it from the personal Lua folder
    # (~/.local/lib/wireshark/plugins; %APPDATA%\Wireshark\plugins on Windows).
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("APPDATA", str(tmp_path))
    monkeypatch.setattr(tshark, "_FOLDERS", {})  # folders are cached per tshark
    lua_dir = (
        tmp_path / "Wireshark/plugins"
        if os.name == "nt"
        else tmp_path / ".local/lib/wireshark/plugins"
    )
    lua_dir.mkdir(parents=True)
    (lua_dir / "pvtest.lua").write_text(
        'local p = Proto("pvtest", "PCAP Viewer test")\nregister_postdissector(p)\n',
        encoding="utf-8",
    )
    out = service.tshark_plugins({}, RequestContext())
    assert out["version"]
    assert out["folders"]["personalPlugins"]
    # (Resolved: a Windows temp folder can be an 8.3 name such as RUNNER~1.)
    assert Path(out["folders"]["personalPlugins"]).resolve().is_relative_to(tmp_path.resolve())
    assert out["install"] == str(Path(out["folders"]["personalPlugins"]) / "epan")
    mine = [p for p in out["plugins"] if p["name"] == "pvtest.lua"]
    if out["folders"]["personalLuaPlugins"] is None:
        pytest.skip("this tshark was built without Lua")
    assert len(mine) == 1
    assert mine[0]["personal"] is True
    assert out["plugins"][0]["name"] == "pvtest.lua"  # personal plugins come first
    assert all(not p["personal"] for p in out["plugins"][1:])
