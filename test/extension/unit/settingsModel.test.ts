import * as assert from "node:assert/strict";
import * as path from "node:path";
import {
  COLORIZE_PALETTE,
  DEFAULT_NAME_RESOLUTION,
  nameResolutionLabel,
  parseCommentBackup,
  safeFileName,
  normalizeNameResolution,
  sameNameResolution,
  captureStem,
  coloringRulesSetting,
  configTargetFor,
  editableColoringRules,
  exportFileName,
  isColor,
  looksLikeKeyLog,
  normalizeColoringRules,
  normalizeColumns,
  prependColoringRule,
  normalizeSavedFilters,
  pushHistory,
  resolveLuaScripts,
  resolveSettingPath,
  upsertSavedFilter,
  withTlsKeyLog,
} from "../../../src/settingsModel";

suite("settingsModel", () => {
  test("normalizeColumns accepts strings and objects, drops junk", () => {
    assert.deepEqual(
      normalizeColumns([
        "tcp.stream",
        { field: "http.host", title: "Host" },
        { field: "-X" },
        42,
        "tcp.stream",
        { title: "x" },
      ]),
      [
        { field: "tcp.stream", title: "tcp.stream" },
        { field: "http.host", title: "Host" },
      ],
    );
    assert.deepEqual(normalizeColumns("nope"), []);
  });

  test("resolveLuaScripts merges explicit scripts and folder contents", () => {
    const base = path.resolve("/work");
    const res = resolveLuaScripts(
      ["a.lua", path.resolve("/abs/b.lua"), "a.lua"],
      "dissectors",
      base,
      (dir) => {
        assert.equal(dir, path.join(base, "dissectors"));
        return ["z.lua", "readme.md", "c.LUA"];
      },
    );
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
    assert.deepEqual(
      upsertSavedFilter(list, { name: "C", filter: "c" }).map((f) => f.name),
      ["A", "B", "C"],
    );
    assert.equal(list[0].filter, "a"); // not mutated
  });

  test("configTargetFor writes where the setting is defined for the scope", () => {
    assert.equal(
      configTargetFor({ workspaceFolderValue: ["a"], workspaceValue: ["b"] }, true),
      "workspaceFolder",
    );
    assert.equal(
      configTargetFor({ workspaceFolderValue: ["a"], workspaceValue: ["b"] }, false),
      "workspace",
    );
    assert.equal(configTargetFor({ workspaceValue: [] }, true), "workspace");
    assert.equal(configTargetFor({}, true), "global");
    assert.equal(configTargetFor(undefined, false), "global");
  });

  test("normalizeColoringRules keeps enabled rules with a filter, in order", () => {
    const rules = normalizeColoringRules([
      { name: "HTTP", filter: " http ", foreground: "#000000", background: "#e4ffc7" },
      { name: "Off", filter: "tcp", enabled: false },
      { name: "No filter", filter: "  " },
      "udp",
      { filter: "dns" },
    ]);
    assert.deepEqual(rules, [
      { name: "HTTP", filter: "http", foreground: "#000000", background: "#e4ffc7" },
      { name: "dns", filter: "dns", foreground: "#000000", background: "#ffffff" },
    ]);
    assert.deepEqual(normalizeColoringRules({}), []);
    assert.equal(
      normalizeColoringRules(
        Array.from({ length: 300 }, (_, i) => ({ filter: `frame.number == ${i}` })),
      ).length,
      255,
    );
  });

  test("prependColoringRule puts the new rule first and keeps raw entries", () => {
    const rule = {
      name: "x",
      filter: "ip.addr == 10.0.0.1",
      foreground: "#12272e",
      background: "#ffc0c0",
    };
    const existing = [{ name: "Off", filter: "tcp", enabled: false }];
    assert.deepEqual(prependColoringRule(existing, rule), [rule, existing[0]]);
    assert.deepEqual(prependColoringRule(undefined, rule), [rule]);
    assert.ok(COLORIZE_PALETTE.every((c) => isColor(c.background)));
    assert.ok(!isColor("red") && isColor("#A0b0C0"));
  });

  test("exportFileName suggests a file next to the capture", () => {
    assert.equal(
      exportFileName(path.join("dir", "trace.pcapng"), "filtered", "pcapng"),
      path.join("dir", "trace-filtered.pcapng"),
    );
    assert.equal(
      exportFileName(path.join("dir", "a.b.pcap"), "frame4", "bin"),
      path.join("dir", "a.b-frame4.bin"),
    );
    // Compression suffixes go too: the export is never compressed.
    assert.equal(
      exportFileName(path.join("dir", "trace.pcap.gz"), "filtered", "pcapng"),
      path.join("dir", "trace-filtered.pcapng"),
    );
    assert.equal(
      exportFileName(path.join("dir", "trace.pcapng.zst"), "packets", "csv"),
      path.join("dir", "trace-packets.csv"),
    );
  });

  test("captureStem drops compression and format extensions", () => {
    const cases: [string, string][] = [
      ["trace.pcap", "trace"],
      ["trace.pcap.gz", "trace"],
      ["TRACE.PCAPNG.ZST", "TRACE"],
      ["trace.pcap.lz4", "trace"],
      ["trace.pcap1", "trace"],
      ["capture.1", "capture"],
      ["hci.btsnoop", "hci"],
      ["my.trace.snoop", "my.trace"],
      ["archive.gz", "archive"],
      ["noext", "noext"],
    ];
    for (const [name, stem] of cases) {
      assert.equal(captureStem(path.join("dir", name)), stem, name);
    }
  });

  test("TLS key log: resolved path, merged into the preferences", () => {
    const base = path.resolve("ws");
    assert.equal(resolveSettingPath("keys/ssl.log", base), path.join(base, "keys", "ssl.log"));
    assert.equal(resolveSettingPath("  ", base), undefined);
    const prefs = { "tcp.desegment_tcp_streams": false, "tls.keylog_file": "/old.log" };
    assert.deepEqual(withTlsKeyLog(prefs, "/new.log"), {
      "tcp.desegment_tcp_streams": false,
      "tls.keylog_file": "/new.log",
    });
    assert.deepEqual(
      withTlsKeyLog(prefs, ""),
      prefs,
      "without the setting, prefs stay as they are",
    );
  });

  test("looksLikeKeyLog", () => {
    const random = `CLIENT_RANDOM ${"ab".repeat(32)} ${"cd".repeat(48)}`;
    const tls13 = `CLIENT_TRAFFIC_SECRET_0 ${"ab".repeat(32)} ${"ef".repeat(32)}`;
    assert.equal(looksLikeKeyLog(`# TLS secrets log file\n${random}\n`), true);
    assert.equal(
      looksLikeKeyLog(
        `${tls13}\r\nSERVER_HANDSHAKE_TRAFFIC_SECRET ${"12".repeat(32)} ${"34".repeat(32)}\r\n`,
      ),
      true,
    );
    assert.equal(looksLikeKeyLog(""), true, "a fresh SSLKEYLOGFILE is empty");
    assert.equal(looksLikeKeyLog(`${random}\nCLIENT_RAN`), true, "the last line may be cut short");
    assert.equal(looksLikeKeyLog("hello world\n"), false);
    assert.equal(looksLikeKeyLog("# only comments\n"), false);
    assert.equal(looksLikeKeyLog(`${random}\n-----BEGIN PRIVATE KEY-----\n`), false);
  });

  test("coloring rules for the editor, and back", () => {
    const raw = [
      { name: "DNS", filter: " dns ", foreground: "#12272E", background: "#c8e2ff" },
      { filter: "arp", enabled: false },
      "junk",
      { name: "Bad colors", filter: "icmp", foreground: "red", background: "#12" },
    ];
    const rules = editableColoringRules(raw);
    assert.deepEqual(rules, [
      { name: "DNS", filter: "dns", foreground: "#12272e", background: "#c8e2ff", enabled: true },
      { name: "", filter: "arp", foreground: "#000000", background: "#ffffff", enabled: false },
      {
        name: "Bad colors",
        filter: "icmp",
        foreground: "#000000",
        background: "#ffffff",
        enabled: true,
      },
    ]);
    assert.deepEqual(coloringRulesSetting(rules), [
      { name: "DNS", filter: "dns", foreground: "#12272e", background: "#c8e2ff" },
      { name: "arp", filter: "arp", foreground: "#000000", background: "#ffffff", enabled: false },
      { name: "Bad colors", filter: "icmp", foreground: "#000000", background: "#ffffff" },
    ]);
    assert.deepEqual(editableColoringRules("nope"), []);
  });
});

suite("settingsModel: name resolution", () => {
  test("reads the switches, keeping defaults for missing or invalid values", () => {
    const values: Record<string, unknown> = { network: true, transport: "yes", external: false };
    const n = normalizeNameResolution((key) => values[key]);
    assert.deepEqual(n, {
      mac: true,
      network: true,
      capturedDns: true,
      transport: false,
      external: false,
    });
    assert.deepEqual(
      normalizeNameResolution(() => undefined),
      DEFAULT_NAME_RESOLUTION,
    );
    assert.ok(sameNameResolution(n, { ...n }));
    assert.ok(!sameNameResolution(n, DEFAULT_NAME_RESOLUTION));
  });

  test("labels the status bar link", () => {
    assert.equal(nameResolutionLabel(DEFAULT_NAME_RESOLUTION), "Names: MAC");
    const all = { mac: true, network: true, capturedDns: true, transport: true, external: true };
    assert.equal(nameResolutionLabel(all), "Names: MAC, network (capture, DNS server), ports");
    assert.equal(
      nameResolutionLabel({ ...all, capturedDns: false, external: false, mac: false }),
      "Names: network, ports",
    );
    assert.equal(
      nameResolutionLabel({ ...all, mac: false, network: false, transport: false }),
      "Names: off",
    );
  });
});

suite("settingsModel: object file names", () => {
  test("safeFileName makes capture-derived names safe to suggest", () => {
    assert.equal(safeFileName("logo.png"), "logo.png");
    assert.equal(safeFileName("../../etc/passwd"), ".._.._etc_passwd");
    assert.equal(safeFileName('a:b*c?"d<e>|f\x01'), "a_b_c__d_e__f_");
    assert.equal(safeFileName("nul.txt"), "_nul.txt");
    assert.equal(safeFileName(" .. "), "object");
    assert.equal(safeFileName("x".repeat(300)).length, 200);
  });
});

suite("settingsModel: packet comment backups", () => {
  test("parseCommentBackup restores unsaved edits, deletions included", () => {
    const edits = parseCommentBackup('{"3": "a comment", "7": null, "x": "no", "0": "no", "9": 5}');
    assert.deepEqual(
      [...edits],
      [
        [3, "a comment"],
        [7, ""],
      ],
    );
    assert.equal(parseCommentBackup("null").size, 0);
    assert.throws(() => parseCommentBackup("{not json"));
  });
});
