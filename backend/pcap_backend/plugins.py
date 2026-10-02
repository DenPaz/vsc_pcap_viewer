"""tshark's plugins (``tshark -G plugins``) and plugin folders (``-G folders``),
for "Show TShark Plugins": which plugins tshark loads and where a new one goes.

Binary dissector plugins (``.so``/``.dll``, built for one Wireshark
major.minor) are loaded from ``<Personal Plugins>/epan``, which ``-G folders``
names with the version already in it (``~/.local/lib/wireshark/plugins/4.6``).
"""

from pathlib import Path
from typing import Any

# The ``-G folders`` names this module reports, and their result keys.
_FOLDERS = {
    "Personal Plugins": "personalPlugins",
    "Global Plugins": "globalPlugins",
    "Personal Lua Plugins": "personalLuaPlugins",
    "Global Lua Plugins": "globalLuaPlugins",
}


def parse_plugins(output: str) -> list[dict[str, str]]:
    """``tshark -G plugins`` lines (name, version, type, path; tab-separated,
    the name padded with spaces) -> ``[{name, version, type, path}]``."""
    plugins = []
    for line in output.split("\n"):
        cells = [cell.strip() for cell in line.split("\t")]
        if len(cells) < 3 or not cells[0]:
            continue
        plugins.append(
            {
                "name": cells[0],
                "version": cells[1],
                "type": cells[2],
                "path": cells[3] if len(cells) > 3 else "",
            }
        )
    return plugins


def plugin_folders(folders_output: str) -> dict[str, str | None]:
    """The plugin folders of ``tshark -G folders`` (None when tshark has none,
    e.g. the Lua folders of a tshark built without Lua)."""
    out: dict[str, str | None] = dict.fromkeys(_FOLDERS.values())
    for line in folders_output.split("\n"):
        name, sep, value = line.partition(":")
        key = _FOLDERS.get(name.strip()) if sep else None
        if key and value.strip():
            out[key] = value.strip()
    return out


def _inside(path: str, folder: str) -> bool:
    # (Path comparisons ignore case on Windows, like its file system.)
    return Path(path).absolute().is_relative_to(Path(folder).absolute())


def describe(plugins_output: str, folders_output: str, as_root: bool) -> dict[str, Any]:
    """The tshark_plugins result: the plugins (``personal`` when they come from
    the user's own folders, listed first), the plugin folders, ``install``
    (where a dissector plugin goes) and warnings."""
    folders = plugin_folders(folders_output)
    personal_roots = [f for f in (folders["personalPlugins"], folders["personalLuaPlugins"]) if f]
    plugins: list[dict[str, Any]] = [
        {**p, "personal": bool(p["path"]) and any(_inside(p["path"], f) for f in personal_roots)}
        for p in parse_plugins(plugins_output)
    ]
    plugins.sort(key=lambda p: (not p["personal"], p["name"].lower()))
    personal = folders["personalPlugins"]
    warnings = []
    if as_root:
        warnings.append(
            "tshark runs as root, and Wireshark ignores personal plugins (and "
            "WIRESHARK_PLUGIN_DIR) as root: only its own plugins are loaded"
        )
    return {
        "plugins": plugins,
        "folders": folders,
        "install": str(Path(personal) / "epan") if personal else None,
        "warnings": warnings,
    }
