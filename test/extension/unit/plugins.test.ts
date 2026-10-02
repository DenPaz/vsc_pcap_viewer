import * as assert from "node:assert/strict";
import { type PluginsResult, pluginRows, pluginsTitle, tsharkVersion } from "../../../src/plugins";

const RESULT: PluginsResult = {
  plugins: [
    {
      name: "li_dissectors.so",
      version: "1.0.0",
      type: "dissector",
      path: "/home/u/.local/lib/wireshark/plugins/4.6/epan/li_dissectors.so",
      personal: true,
    },
    {
      name: "mine.lua",
      version: "",
      type: "lua script",
      path: "/home/u/.local/lib/wireshark/plugins/mine.lua",
      personal: true,
    },
    {
      name: "ethercat.so",
      version: "0.1.0",
      type: "dissector",
      path: "/usr/lib/wireshark/plugins/4.6/epan/ethercat.so",
      personal: false,
    },
  ],
  folders: {
    personalPlugins: "/home/u/.local/lib/wireshark/plugins/4.6",
    globalPlugins: "/usr/lib/wireshark/plugins/4.6",
    personalLuaPlugins: "/home/u/.local/lib/wireshark/plugins",
    globalLuaPlugins: "/usr/lib/wireshark/plugins",
  },
  install: "/home/u/.local/lib/wireshark/plugins/4.6/epan",
  warnings: [],
  version: "TShark (Wireshark) 4.6.9 (v4.6.9-0-g1234abcd).",
};

suite("TShark plugins", () => {
  test("version and title", () => {
    assert.equal(tsharkVersion(RESULT.version), "4.6.9");
    assert.equal(
      tsharkVersion("TShark (Wireshark) 4.2.2 (Git v4.2.2 packaged as 4.2.2-1)"),
      "4.2.2",
    );
    assert.equal(tsharkVersion("something else"), "something else");
    assert.equal(pluginsTitle(RESULT), "TShark 4.6.9: 3 plugins, 2 of yours");
    assert.equal(
      pluginsTitle({ ...RESULT, plugins: RESULT.plugins.slice(2) }),
      "TShark 4.6.9: 1 plugin, 0 of yours",
    );
  });

  test("rows: the folder actions, then your plugins, then Wireshark's", () => {
    const rows = pluginRows(RESULT, true);
    assert.deepEqual(
      rows.map((r) => [r.kind, r.label]),
      [
        ["openFolder", "$(folder-opened) Open Personal Plugin Folder"],
        ["copyFolder", "$(copy) Copy Its Path"],
        ["separator", "Your plugins (2)"],
        ["plugin", "li_dissectors.so"],
        ["plugin", "mine.lua"],
        ["separator", "Wireshark's plugins (1)"],
        ["plugin", "ethercat.so"],
      ],
    );
    const [open, , , li, lua] = rows;
    assert.equal(open.kind === "openFolder" && open.description, RESULT.install);
    assert.match(open.kind === "openFolder" ? (open.detail ?? "") : "", /go here/);
    assert.deepEqual(li, {
      kind: "plugin",
      label: "li_dissectors.so",
      description: "1.0.0 · dissector",
      detail: RESULT.plugins[0].path,
      path: RESULT.plugins[0].path,
    });
    // Lua scripts have no version.
    assert.equal(lua.kind === "plugin" && lua.description, "lua script");
  });

  test("a missing folder is created when opened; no personal folder, no folder rows", () => {
    const [open] = pluginRows(RESULT, false);
    assert.match(open.kind === "openFolder" ? (open.detail ?? "") : "", /creates it/);
    const none = pluginRows({ ...RESULT, install: null, plugins: RESULT.plugins.slice(2) }, false);
    assert.deepEqual(
      none.map((r) => r.kind),
      ["separator", "plugin"],
    );
  });
});
