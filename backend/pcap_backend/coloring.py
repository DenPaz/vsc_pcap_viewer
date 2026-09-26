"""Packet coloring rules, evaluated by tshark itself.

tshark applies Wireshark's coloring rules with ``--color`` and reports the
matching rule per packet in ``frame.coloring_rule.name``, but it only reads the
rules from ``colorfilters`` in the personal configuration folder. Each coloring
pass therefore runs with ``WIRESHARK_CONFIG_DIR`` pointing at a temporary folder
that holds our generated ``colorfilters`` plus copies of the user's other
personal configuration files (preferences, disabled protocols, ...), so
dissection matches every other pass. Rules are named by their index, which
keeps the file format safe from arbitrary rule names.
"""

import re
import shutil
from dataclasses import dataclass
from pathlib import Path
from typing import Any

MAX_RULES = 255  # per-frame rule index is stored in one byte (0 = no rule)
_COLOR_RE = re.compile(r"^#([0-9a-fA-F]{6})$")
_COMPILE_ERROR_RE = re.compile(
    r'Could not compile "(?P<index>\d+)" in colorfilters file[^\n]*\n(?P<message>[^\n]*)'
)
_MAX_CONFIG_FILE = 4 << 20


@dataclass(frozen=True, slots=True)
class ColorRule:
    filter: str
    foreground: str  # "#rrggbb"
    background: str


def parse_rule(raw: Any) -> ColorRule | str:
    """A validated rule, or the reason it can't be used."""
    if not isinstance(raw, dict):
        return "rule must be an object"
    flt = raw.get("filter")
    if not isinstance(flt, str) or not flt.strip():
        return "rule has no filter"
    flt = " ".join(flt.split())  # the file format is one rule per line
    if "@" in flt:
        return "coloring rule filters cannot contain '@'"
    colors: list[str] = []
    for key, default in (("foreground", "#000000"), ("background", "#ffffff")):
        value = raw.get(key) or default
        if not isinstance(value, str) or not _COLOR_RE.match(value):
            return f"{key} must be a #rrggbb color"
        colors.append(value.lower())
    return ColorRule(flt, colors[0], colors[1])


def _rgb16(color: str) -> str:
    """``#rrggbb`` → colorfilters' 16-bit ``[r,g,b]``."""
    return "[" + ",".join(str(int(color[i : i + 2], 16) * 257) for i in (1, 3, 5)) + "]"


def colorfilters_text(rules: list[ColorRule | str]) -> str:
    """The ``colorfilters`` file for the valid rules, each named by its index."""
    lines = [
        f"@{i}@{r.filter}@{_rgb16(r.foreground)}{_rgb16(r.background)}"
        for i, r in enumerate(rules)
        if isinstance(r, ColorRule)
    ]
    return "\n".join(lines) + "\n"


def parse_compile_errors(stderr: str) -> dict[int, str]:
    """Rule index → tshark's message for rules it disabled because they don't compile."""
    return {
        int(m["index"]): m["message"].strip() or "invalid filter"
        for m in _COMPILE_ERROR_RE.finditer(stderr)
    }


def personal_config_dir(folders_output: str) -> Path | None:
    """The "Personal configuration" folder from ``tshark -G folders``."""
    for line in folders_output.split("\n"):
        name, sep, value = line.partition(":")
        if sep and name.strip() == "Personal configuration":
            path = Path(value.strip())
            return path if path.is_dir() else None
    return None


def prepare_config_dir(target: Path, rules: list[ColorRule | str], personal: Path | None) -> None:
    """Fill ``target`` with the user's personal config files and our colorfilters."""
    if personal is not None:
        for item in personal.iterdir():
            try:
                if (
                    item.is_file()
                    and item.name != "colorfilters"
                    and item.stat().st_size <= _MAX_CONFIG_FILE
                ):
                    shutil.copyfile(item, target / item.name)
            except OSError:
                continue  # unreadable config files are skipped, like tshark would
    (target / "colorfilters").write_text(colorfilters_text(rules), encoding="utf-8")
