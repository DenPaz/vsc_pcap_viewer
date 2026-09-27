import * as assert from "node:assert/strict";
import * as fs from "node:fs";
import * as path from "node:path";
import {
  EnvironmentDeps,
  checkEnvironment,
  environmentSummary,
  settingToFix,
  tsharkVersion,
} from "../../../src/environment";

const ROOT = path.resolve(__dirname, "../../../..");
const SETTINGS = { pythonPath: "", tsharkPath: "" };

function deps(over: Partial<EnvironmentDeps> = {}): EnvironmentDeps & { calls: unknown[][] } {
  const calls: unknown[][] = [];
  return {
    calls,
    findPython: (configured) => {
      calls.push(["findPython", configured]);
      return { python: ["python3.14"], version: "3.14.0" };
    },
    initialize: async (python, tsharkPath) => {
      calls.push(["initialize", python, tsharkPath]);
      return { version: "TShark (Wireshark) 4.6.1 (Git v4.6.1)", tsharkPath: "/usr/bin/tshark" };
    },
    ...over,
  };
}

suite("environment check", () => {
  test("both found: versions, paths and the settings used", async () => {
    const d = deps();
    const status = await checkEnvironment(
      { pythonPath: "/opt/py/bin/python3", tsharkPath: "/opt/ws/tshark" },
      d,
    );
    assert.deepEqual(status, {
      python: { ok: true, version: "3.14.0", command: "python3.14" },
      tshark: { ok: true, version: "4.6.1", path: "/usr/bin/tshark" },
    });
    assert.deepEqual(d.calls, [
      ["findPython", "/opt/py/bin/python3"],
      ["initialize", ["python3.14"], "/opt/ws/tshark"],
    ]);
    assert.equal(settingToFix(status), undefined);
    assert.equal(
      environmentSummary(status),
      "Ready: Python 3.14.0 (python3.14) and TShark 4.6.1 (/usr/bin/tshark).",
    );
  });

  test("no Python: tshark isn't looked for, and the Python setting is the fix", async () => {
    const d = deps({ findPython: () => ({ error: "No Python 3.14+ interpreter found." }) });
    const status = await checkEnvironment(SETTINGS, d);
    assert.deepEqual(status.python, { ok: false, error: "No Python 3.14+ interpreter found." });
    assert.equal(status.tshark.ok, false);
    assert.ok(!status.tshark.ok && status.tshark.skipped);
    assert.equal(d.calls.length, 0, "initialize (recorded) is never called");
    assert.equal(settingToFix(status), "pythonPath");
    assert.equal(environmentSummary(status), "No Python 3.14+ interpreter found.");
  });

  test("no tshark: the backend's message, and the tshark setting is the fix", async () => {
    const status = await checkEnvironment(
      SETTINGS,
      deps({
        initialize: async () => {
          throw new Error("tshark was not found. Install Wireshark…");
        },
      }),
    );
    assert.deepEqual(status.tshark, {
      ok: false,
      error: "tshark was not found. Install Wireshark…",
    });
    assert.equal(settingToFix(status), "tsharkPath");
    assert.match(environmentSummary(status), /^Python 3\.14\.0 is fine, but TShark isn't: tshark/);
  });

  test("tshark versions from its banner", () => {
    assert.equal(
      tsharkVersion("TShark (Wireshark) 4.2.2 (Git v4.2.2 packaged as 4.2.2-1)"),
      "4.2.2",
    );
    assert.equal(tsharkVersion("  something else "), "something else");
  });
});

suite("Get Started walkthrough", () => {
  const pkg = JSON.parse(fs.readFileSync(path.join(ROOT, "package.json"), "utf8"));
  const [walkthrough] = pkg.contributes.walkthroughs;
  const commands = new Set<string>(
    pkg.contributes.commands.map((c: { command: string }) => c.command),
  );
  const WORKBENCH = new Set(["workbench.action.openSettings"]);
  const source = fs
    .readdirSync(path.join(ROOT, "src"), { recursive: true, encoding: "utf8" })
    .filter((f) => f.endsWith(".ts"))
    .map((f) => fs.readFileSync(path.join(ROOT, "src", f), "utf8"))
    .join("\n");

  test("its id is the one the host opens", () => {
    assert.match(source, new RegExp(`WALKTHROUGH = "${walkthrough.id}"`));
  });

  test("every step's links, media and completion events exist", () => {
    for (const step of walkthrough.steps) {
      const links = [...step.description.matchAll(/\]\(command:([\w.]+)(?:\?([^)]*))?\)/g)];
      assert.ok(links.length > 0, `${step.id} has a button`);
      for (const [, command, args] of links) {
        assert.ok(commands.has(command) || WORKBENCH.has(command), `${step.id}: ${command}`);
        if (args) {
          const [key] = JSON.parse(decodeURIComponent(args));
          assert.ok(
            Object.keys(pkg.contributes.configuration.properties).some((k) => k.startsWith(key)),
            `${step.id}: no setting ${key}`,
          );
        }
      }
      assert.ok(fs.existsSync(path.join(ROOT, step.media.markdown)), step.media.markdown);
      for (const event of step.completionEvents) {
        const [kind, arg] = event.split(/:(.*)/s);
        if (kind === "onCommand") {
          assert.ok(commands.has(arg) || WORKBENCH.has(arg), `${step.id}: ${event}`);
        } else if (kind === "onContext") {
          assert.ok(source.includes(`"${arg}"`), `${step.id}: nothing sets ${arg}`);
        } else {
          assert.equal(kind, "onSettingChanged", `${step.id}: ${event}`);
        }
      }
    }
  });

  test("the sample capture is the mixed.pcapng fixture", () => {
    assert.deepEqual(
      fs.readFileSync(path.join(ROOT, "media", "sample.pcapng")),
      fs.readFileSync(path.join(ROOT, "test", "fixtures", "mixed.pcapng")),
    );
  });
});
