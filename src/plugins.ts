/**
 * _PCAP: Show TShark Plugins_: what the backend's `tshark_plugins` answers and
 * the picker's rows (pure: no `vscode` import). Wireshark plugins (binary
 * dissectors such as `.so`/`.dll` files, or Lua scripts in the plugin folders)
 * are loaded by tshark itself, so the viewer only shows them.
 */

export interface TsharkPlugin {
  name: string;
  version: string;
  type: string;
  path: string;
  /** From the user's own plugin folders (listed first). */
  personal: boolean;
}

export interface PluginsResult {
  plugins: TsharkPlugin[];
  folders: {
    personalPlugins: string | null;
    globalPlugins: string | null;
    personalLuaPlugins: string | null;
    globalLuaPlugins: string | null;
  };
  /** Where a dissector plugin goes: `<personal plugins>/epan`. */
  install: string | null;
  warnings: string[];
  /** `tshark --version`'s first line. */
  version: string;
}

export type PluginRow =
  | { kind: "separator"; label: string }
  | { kind: "openFolder" | "copyFolder"; label: string; description: string; detail?: string }
  | { kind: "plugin"; label: string; description: string; detail: string; path: string };

/** "4.6.9" from "TShark (Wireshark) 4.6.9 (v4.6.9-0-g…)", else the line itself. */
export function tsharkVersion(line: string): string {
  return /\b(\d+\.\d+\.\d+)\b/.exec(line)?.[1] ?? line;
}

/** The picker's title: "TShark 4.6.9: 31 plugins, 1 of yours". */
export function pluginsTitle(result: PluginsResult): string {
  const count = result.plugins.length;
  const mine = result.plugins.filter((p) => p.personal).length;
  const plugins = `${count} plugin${count === 1 ? "" : "s"}`;
  return `TShark ${tsharkVersion(result.version)}: ${plugins}, ${mine} of yours`;
}

/**
 * The picker's rows: open or copy the personal folder a dissector plugin goes
 * into (`installExists`: whether it exists yet), then the user's plugins and
 * Wireshark's own, each plugin with its version, type and file.
 */
export function pluginRows(result: PluginsResult, installExists: boolean): PluginRow[] {
  const rows: PluginRow[] = [];
  if (result.install) {
    rows.push(
      {
        kind: "openFolder",
        label: "$(folder-opened) Open Personal Plugin Folder",
        description: result.install,
        detail: installExists
          ? "Dissector plugins (.so, .dll) built for this Wireshark version go here"
          : "Doesn't exist yet: opening it creates it. Dissector plugins (.so, .dll) go here",
      },
      { kind: "copyFolder", label: "$(copy) Copy Its Path", description: result.install },
    );
  }
  const section = (label: string, plugins: TsharkPlugin[]) => {
    if (!plugins.length) {
      return;
    }
    rows.push({ kind: "separator", label: `${label} (${plugins.length})` });
    for (const p of plugins) {
      rows.push({
        kind: "plugin",
        label: p.name,
        description: p.version ? `${p.version} · ${p.type}` : p.type,
        detail: p.path,
        path: p.path,
      });
    }
  };
  const mine = result.plugins.filter((p) => p.personal);
  const theirs = result.plugins.filter((p) => !p.personal);
  section("Your plugins", mine);
  section("Wireshark's plugins", theirs);
  return rows;
}
