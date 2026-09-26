import * as assert from "node:assert/strict";
import * as path from "node:path";
import { normalizeColumns, normalizeSavedFilters, pushHistory, resolveLuaScripts, upsertSavedFilter } from "../../../src/settingsModel";

suite("settingsModel", () => {
  test("normalizeColumns accepts strings and objects, drops junk", () => {
    assert.deepEqual(normalizeColumns(["tcp.stream", { field: "http.host", title: "Host" }, { field: "-X" }, 42, "tcp.stream", { title: "x" }]), [
      { field: "tcp.stream", title: "tcp.stream" },
      { field: "http.host", title: "Host" },
    ]);
    assert.deepEqual(normalizeColumns("nope"), []);
  });

  test("resolveLuaScripts merges explicit scripts and folder contents", () => {
    const base = path.resolve("/work");
    const res = resolveLuaScripts(["a.lua", path.resolve("/abs/b.lua"), "a.lua"], "dissectors", base, (dir) => {
      assert.equal(dir, path.join(base, "dissectors"));
      return ["z.lua", "readme.md", "c.LUA"];
    });
    assert.deepEqual(res.scripts, [
      path.join(base, "a.lua"),
      path.resolve("/abs/b.lua"),
      path.join(base, "dissectors", "c.LUA"),
      path.join(base, "dissectors", "z.lua"),
    ]);
    assert.deepEqual(res.warnings, []);
  });

  test("resolveLuaScripts reports unreadable folders", () => {
    const res = resolveLuaScripts([], "/missing", undefined, () => {
      throw new Error("ENOENT");
    });
    assert.equal(res.scripts.length, 0);
    assert.match(res.warnings[0], /ENOENT/);
  });

  test("pushHistory de-duplicates and caps", () => {
    assert.deepEqual(pushHistory(["a", "b"], " b "), ["b", "a"]);
    assert.deepEqual(pushHistory(["a"], "  "), ["a"]);
    assert.deepEqual(pushHistory(["a", "b", "c"], "d", 3), ["d", "a", "b"]);
  });

  test("normalizeSavedFilters keeps valid, uniquely named entries", () => {
    assert.deepEqual(
      normalizeSavedFilters([
        { name: " Web ", filter: " http || tls " },
        { name: "Web", filter: "dns" },
        { name: "", filter: "x" },
        { name: "No filter" },
        "http",
        null,
      ]),
      [{ name: "Web", filter: "http || tls" }],
    );
    assert.deepEqual(normalizeSavedFilters({}), []);
  });

  test("upsertSavedFilter replaces by name and keeps order", () => {
    const list = [
      { name: "A", filter: "a" },
      { name: "B", filter: "b" },
    ];
    assert.deepEqual(upsertSavedFilter(list, { name: "A", filter: "aa" }), [
      { name: "A", filter: "aa" },
      { name: "B", filter: "b" },
    ]);
    assert.deepEqual(upsertSavedFilter(list, { name: "C", filter: "c" }).map((f) => f.name), ["A", "B", "C"]);
    assert.equal(list[0].filter, "a"); // not mutated
  });
});
