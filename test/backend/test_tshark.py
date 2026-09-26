from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

from pcap_backend import tshark as ts
from pcap_backend.cancellation import CancelledError, CancelToken
from pcap_backend.tshark import (
    ConfigError,
    DissectionOptions,
    StreamResult,
    ToolNotFoundError,
    Tshark,
    clean_stderr,
    find_tool,
)


def test_dissection_options_args() -> None:
    opts = DissectionOptions.from_params(
        lua=["/x/my dissector.lua"],
        decode_as=["tcp.port==8080,http", "udp.port:9999,dns"],
        prefs={"tcp.desegment_tcp_streams": False, "http.tcp.port": 8080},
    )
    assert opts.args() == [
        "-X", "lua_script:/x/my dissector.lua",
        "-d", "tcp.port==8080,http",
        "-d", "udp.port:9999,dns",
        "-o", "http.tcp.port:8080",
        "-o", "tcp.desegment_tcp_streams:FALSE",
    ]  # fmt: skip


@pytest.mark.parametrize(
    "rule", ["tcp.port==8080", "-X,foo", "tcp.port==80,http;rm", "tcp.port==80, http", ""]
)
def test_decode_as_rejects_malformed(rule: str) -> None:
    with pytest.raises(ConfigError):
        DissectionOptions.from_params(decode_as=[rule])


@pytest.mark.parametrize("key", ["-X", "a b", "x=y", ""])
def test_prefs_reject_bad_keys(key: str) -> None:
    with pytest.raises(ConfigError):
        DissectionOptions.from_params(prefs={key: "1"})


def test_prefs_reject_multiline_values() -> None:
    with pytest.raises(ConfigError):
        DissectionOptions.from_params(prefs={"a.b": "1\n-o x"})


def test_missing_lua_script_warns(tmp_path: Path) -> None:
    opts = DissectionOptions.from_params(lua=[str(tmp_path / "missing.lua")])
    assert any("not found" in w for w in opts.check_scripts())


def test_argv_is_a_list_with_options_first() -> None:
    exe = Path("/opt/tshark")  # str() is platform-specific (backslashes on Windows)
    t = Tshark(exe, DissectionOptions.from_params(decode_as=["udp.port==1,dns"]))
    assert t.argv("-T", "pdml", capture="C:\\My Captures\\a b.pcap") == [
        str(exe), "-d", "udp.port==1,dns", "-r", "C:\\My Captures\\a b.pcap", "-T", "pdml",
    ]  # fmt: skip
    assert t.argv("-G", "fields", dissect=False) == [str(exe), "-G", "fields"]


def test_clean_stderr_drops_root_warning() -> None:
    text = 'Running as user "root" and group "root". This could be dangerous.\n\ntshark: boom\n'
    assert clean_stderr(text) == "tshark: boom"


def test_find_tool_configured_path(tmp_path: Path) -> None:
    exe = tmp_path / "tshark"
    exe.write_text("")
    assert find_tool("tshark", str(exe)) == exe
    with pytest.raises(ToolNotFoundError) as info:
        find_tool("tshark", str(tmp_path / "nope"))
    assert str(tmp_path / "nope") in info.value.searched


def test_find_tool_prefers_sibling(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    name = "capinfos.exe" if ts.IS_WINDOWS else "capinfos"
    (tmp_path / name).write_text("")
    monkeypatch.setattr(ts.shutil, "which", lambda _exe: None)
    assert find_tool("capinfos", sibling_of=tmp_path / "tshark") == tmp_path / name


def test_find_tool_not_found(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(ts.shutil, "which", lambda _exe: None)
    monkeypatch.setattr(ts, "_default_locations", lambda _exe: [Path("/definitely/not/here")])
    with pytest.raises(ToolNotFoundError, match="Install Wireshark"):
        find_tool("tshark")


def test_stream_lines_and_cancellation() -> None:
    py = sys.executable
    result = StreamResult()
    lines = list(ts.stream_lines([py, "-c", "print('a'); print('b')"], result))
    assert lines == [b"a", b"b"]
    assert result.returncode == 0

    token = CancelToken()
    result = StreamResult()
    script = "import time\nfor i in range(1000):\n    print(i, flush=True); time.sleep(0.01)"
    gen = ts.stream_lines([py, "-c", script], result, token)
    assert next(gen) == b"0"
    token.cancel()
    with pytest.raises(CancelledError):
        list(gen)
    assert len(ts.PROCESSES) == 0


def test_run_captures_stderr() -> None:
    res = ts.run([sys.executable, "-c", "import sys; sys.stderr.write('tshark: bad'); sys.exit(3)"])
    assert res.returncode == 3
    assert res.stderr == "tshark: bad"


@pytest.mark.tshark
def test_validate_filter_real_tshark() -> None:
    t = Tshark.locate()
    assert t.validate_filter("ip.src == 10.0.0.1 && tcp.port == 80") is None
    assert t.validate_filter("") is None
    err = t.validate_filter("ip.src ==")
    assert err
    assert "tshark:" not in err


@pytest.mark.tshark
def test_version_real_tshark() -> None:
    assert "TShark" in Tshark.locate().version()


@pytest.mark.skipif(os.name != "posix", reason="POSIX permissions")
def test_find_tool_skips_directories(tmp_path: Path) -> None:
    (tmp_path / "tshark").mkdir()
    with pytest.raises(ToolNotFoundError):
        find_tool("tshark", str(tmp_path / "tshark"))
