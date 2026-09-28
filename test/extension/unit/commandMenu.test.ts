import * as assert from "node:assert/strict";
import * as fs from "node:fs";
import * as path from "node:path";
import {
  COMMAND_GROUPS,
  EXCLUDED_COMMANDS,
  buildCommandMenu,
  commandGroup,
  hasExplicitGroup,
} from "../../../src/commandMenu";

const ROOT = path.resolve(__dirname, "../../../..");
const pkg = JSON.parse(fs.readFileSync(path.join(ROOT, "package.json"), "utf8"));
const contributed: { command: string; title: string; category?: string }[] =
  pkg.contributes.commands;

suite("☰ commands menu (from package.json)", () => {
  const menu = buildCommandMenu(pkg);

  test("every contributed command is listed, except the excluded ones", () => {
    const expected = contributed.map((c) => c.command).filter((id) => !(id in EXCLUDED_COMMANDS));
    assert.deepEqual(
      menu.map((c) => c.id),
      expected,
    );
    for (const id of Object.keys(EXCLUDED_COMMANDS)) {
      assert.ok(
        contributed.some((c) => c.command === id),
        `${id} is excluded but no longer contributed: drop it from EXCLUDED_COMMANDS`,
      );
      assert.ok(EXCLUDED_COMMANDS[id].length > 10, `${id} has a reason`);
    }
  });

  test("titles, categories and key bindings come from package.json", () => {
    const byId = new Map(menu.map((c) => [c.id, c]));
    for (const c of contributed.filter((c) => byId.has(c.command))) {
      assert.equal(byId.get(c.command)?.title, c.title);
      assert.equal(byId.get(c.command)?.category, c.category ?? "PCAP");
    }
    for (const k of pkg.contributes.keybindings as {
      command: string;
      key: string;
      mac?: string;
    }[]) {
      const item = byId.get(k.command);
      if (item) {
        assert.deepEqual(item.keys, { key: k.key, mac: k.mac });
      }
    }
    assert.deepEqual(byId.get("pcapViewer.applyFilter")?.keys, { key: "ctrl+/", mac: "cmd+/" });
    assert.equal(byId.get("pcapViewer.statistics.conversations")?.keys, undefined);
  });

  test("every command has an explicit heading (or is a PCAP Statistics one)", () => {
    for (const c of menu) {
      assert.ok(
        hasExplicitGroup(c.id) || c.category === "PCAP Statistics",
        `${c.id}: add it to GROUP_OF in src/commandMenu.ts`,
      );
      assert.ok(COMMAND_GROUPS.includes(c.group), `${c.id}: ${c.group}`);
    }
    assert.equal(commandGroup("pcapViewer.brandNew", "PCAP Statistics"), "Statistics");
    assert.equal(commandGroup("pcapViewer.brandNew", "PCAP"), "Other");
  });

  test("requirements", () => {
    const byId = new Map(menu.map((c) => [c.id, c]));
    assert.deepEqual(byId.get("pcapViewer.stopCapture")?.requires, ["capturing"]);
    assert.deepEqual(byId.get("pcapViewer.askAboutPackets")?.requires, ["ai", "selection"]);
    assert.deepEqual(byId.get("pcapViewer.toggleMark")?.requires, ["selection"]);
    assert.equal(byId.get("pcapViewer.statistics.conversations")?.requires, undefined);
  });

  test("only pcapViewer.* commands, and unknown shapes are tolerated", () => {
    const built = buildCommandMenu({
      contributes: {
        commands: [
          { command: "other.command", title: "Not ours" },
          { command: "pcapViewer.x", title: "X" },
        ],
      },
    });
    assert.deepEqual(
      built.map((c) => [c.id, c.category, c.group]),
      [["pcapViewer.x", "PCAP", "Other"]],
    );
    assert.deepEqual(buildCommandMenu({}), []);
  });
});
