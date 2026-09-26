// Unit tests for the webview's pure helpers (src/webview/lib.js), run with mocha under Node.
const assert = require("node:assert/strict");
const lib = require("../../src/webview/lib.js");

suite("webview lib: virtualization", () => {
  const base = { viewportHeight: 220, rowHeight: 22 };

  test("unscaled window", () => {
    const w = lib.computeWindow({ ...base, scrollTop: 0, total: 1000 });
    assert.deepEqual(w, { first: 0, count: 11, top: 0, virtualHeight: 22000, scaled: false });
    const w2 = lib.computeWindow({ ...base, scrollTop: 230, total: 1000 });
    assert.equal(w2.first, 10);
    assert.equal(w2.top, 220);
  });

  test("window clamps at the end and for tiny lists", () => {
    const w = lib.computeWindow({ ...base, scrollTop: 21780, total: 1000 });
    assert.equal(w.first + w.count, 1000);
    const small = lib.computeWindow({ ...base, scrollTop: 0, total: 3 });
    assert.equal(small.count, 3);
    const empty = lib.computeWindow({ ...base, scrollTop: 0, total: 0 });
    assert.equal(empty.count, 0);
  });

  test("scaled window maps scroll range onto all rows", () => {
    const total = 5_000_000; // 110M px unscaled
    const p = { ...base, total, maxScrollHeight: 1_000_000 };
    const top = lib.computeWindow({ ...p, scrollTop: 0 });
    assert.equal(top.scaled, true);
    assert.equal(top.virtualHeight, 1_000_000);
    assert.equal(top.first, 0);
    const bottom = lib.computeWindow({ ...p, scrollTop: 1_000_000 - 220 });
    assert.equal(bottom.first + bottom.count, total);
    const mid = lib.computeWindow({ ...p, scrollTop: (1_000_000 - 220) / 2 });
    assert.ok(Math.abs(mid.first - total / 2) < 10);
    assert.equal(mid.top, (1_000_000 - 220) / 2);
  });

  test("scrollTopForIndex round-trips (unscaled and scaled)", () => {
    for (const total of [1000, 5_000_000]) {
      const p = { ...base, total, maxScrollHeight: 1_000_000 };
      for (const index of [0, 1, 500, 999, total - 1]) {
        const scrollTop = lib.scrollTopForIndex({ ...p, index, scrollTop: 0 });
        const w = lib.computeWindow({ ...p, scrollTop });
        assert.ok(index >= w.first && index < w.first + w.count, `index ${index} of ${total} visible`);
      }
      const centered = lib.scrollTopForIndex({ ...p, index: 500, scrollTop: 0, center: true });
      const w = lib.computeWindow({ ...p, scrollTop: centered });
      assert.ok(500 - w.first >= 3, "centered row is not at the top edge");
    }
  });

  test("scrollTopForIndex keeps position when already visible", () => {
    assert.equal(lib.scrollTopForIndex({ ...base, total: 1000, index: 12, scrollTop: 220 }), 220);
  });

  test("pagesForRange", () => {
    assert.deepEqual(lib.pagesForRange(0, 30, 200, 1000), [0]);
    assert.deepEqual(lib.pagesForRange(190, 30, 200, 1000), [0, 1]);
    assert.deepEqual(lib.pagesForRange(390, 30, 200, 1000, 1), [0, 1, 2, 3]);
    assert.deepEqual(lib.pagesForRange(990, 30, 200, 1000, 1), [3, 4]);
    assert.deepEqual(lib.pagesForRange(0, 0, 200, 0), []);
  });

  test("LruMap evicts least recently used", () => {
    const m = new lib.LruMap(2);
    m.set("a", 1);
    m.set("b", 2);
    assert.equal(m.get("a"), 1);
    m.set("c", 3);
    assert.equal(m.has("b"), false);
    assert.equal(m.has("a"), true);
    assert.equal(m.size, 2);
  });
});

suite("webview lib: filters", () => {
  test("buildFieldFilter picks literal forms", () => {
    assert.equal(lib.buildFieldFilter({ name: "ip.src", show: "10.0.0.1" }), "ip.src == 10.0.0.1");
    assert.equal(lib.buildFieldFilter({ name: "tcp.port", show: "443" }), "tcp.port == 443");
    assert.equal(lib.buildFieldFilter({ name: "ip.flags", show: "0x02" }), "ip.flags == 0x02");
    assert.equal(lib.buildFieldFilter({ name: "eth.src", show: "02:00:00:00:00:01" }), "eth.src == 02:00:00:00:00:01");
    assert.equal(lib.buildFieldFilter({ name: "ipv6.src", show: "fe80::1" }), "ipv6.src == fe80::1");
    assert.equal(lib.buildFieldFilter({ name: "tcp.flags.syn", show: "True" }), "tcp.flags.syn == 1");
    assert.equal(lib.buildFieldFilter({ name: "http", proto: true, show: "x" }), "http");
    assert.equal(lib.buildFieldFilter({ name: "tcp.segments", show: "" }), "tcp.segments");
  });

  test("buildFieldFilter quotes and escapes strings", () => {
    assert.equal(lib.buildFieldFilter({ name: "http.host", show: "example.com" }), 'http.host == "example.com"');
    assert.equal(lib.buildFieldFilter({ name: "http.user_agent", show: 'a "b" \\c' }), 'http.user_agent == "a \\"b\\" \\\\c"');
  });

  test("buildFieldFilter rejects unfilterable nodes", () => {
    assert.equal(lib.buildFieldFilter({ show: "text" }), null);
    assert.equal(lib.buildFieldFilter({ name: "", show: "x" }), null);
    assert.equal(lib.buildFieldFilter({ name: "a b", show: "x" }), null);
  });

  test("combineFilter", () => {
    assert.equal(lib.combineFilter("", "tcp", "and"), "tcp");
    assert.equal(lib.combineFilter("ip", "tcp", "replace"), "tcp");
    assert.equal(lib.combineFilter("ip", "tcp", "and"), "(ip) && (tcp)");
    assert.equal(lib.combineFilter("ip", "tcp", "or"), "(ip) || (tcp)");
    assert.equal(lib.combineFilter("ip", "tcp", "not"), "(ip) && !(tcp)");
    assert.equal(lib.combineFilter("", "tcp", "not"), "!(tcp)");
  });
});

suite("webview lib: bytes", () => {
  const tree = [
    {
      id: 1, label: "Ethernet", name: "eth", pos: 0, size: 14, src: 0,
      children: [{ id: 2, label: "Dst", name: "eth.dst", pos: 0, size: 6, src: 0, children: [{ id: 3, label: "OUI", name: "eth.dst.oui", pos: 0, size: 3, src: 0 }] }],
    },
    { id: 4, label: "IP", name: "ip", pos: 14, size: 20, src: 0, children: [{ id: 5, label: "Src", name: "ip.src", pos: 26, size: 4, src: 0 }] },
    { id: 6, label: "HTTP", name: "http", pos: 0, size: 40, src: 1 },
  ];

  test("findNodeForByte returns the smallest enclosing field", () => {
    assert.deepEqual(lib.findNodeForByte(tree, 0, 1).map((n) => n.id), [1, 2, 3]);
    assert.deepEqual(lib.findNodeForByte(tree, 0, 4).map((n) => n.id), [1, 2]);
    assert.deepEqual(lib.findNodeForByte(tree, 0, 27).map((n) => n.id), [4, 5]);
    assert.deepEqual(lib.findNodeForByte(tree, 1, 1).map((n) => n.id), [6]);
    assert.equal(lib.findNodeForByte(tree, 0, 100), null);
  });

  test("nodeKey is stable across packets", () => {
    assert.equal(lib.nodeKey([{ name: "ip", label: "IPv4" }, { label: "Flags: 0x2" }]), "ip/Flags: #x#");
  });

  test("hex and formatting helpers", () => {
    assert.deepEqual([...lib.hexToBytes("00ff10")], [0, 255, 16]);
    assert.equal(lib.asciiChar(0x41), "A");
    assert.equal(lib.asciiChar(0x0a), ".");
    assert.equal(lib.formatOffset(16, 100), "0010");
    assert.equal(lib.formatOffset(16, 70000), "00000010");
    assert.equal(lib.formatRelativeTime("0.001000000"), "0.001000");
    assert.equal(lib.formatRelativeTime(""), "");
    assert.equal(lib.formatBytes(512), "512 B");
    assert.equal(lib.formatBytes(1536), "1.5 KB");
  });
});

suite("webview lib: autocomplete", () => {
  const ctx = (text, cursor = text.length) => lib.completionContext(text, cursor);

  test("field context at the start and after logical operators", () => {
    assert.deepEqual(ctx("ip.sr"), { kind: "field", prefix: "ip.sr", start: 0, end: 5 });
    assert.equal(ctx("").kind, "field");
    assert.deepEqual(ctx("tcp.port == 80 && ht"), { kind: "field", prefix: "ht", start: 18, end: 20 });
    assert.equal(ctx("!ht").kind, "field");
    assert.equal(ctx("frame.len > 100 || ").kind, "field");
    assert.equal(ctx("(ht").kind, "field");
    assert.equal(ctx("http and d").kind, "field");
  });

  test("the whole word under the cursor is replaced", () => {
    assert.deepEqual(ctx("ip.src == 1", 4), { kind: "field", prefix: "ip.s", start: 0, end: 6 });
  });

  test("operator context after a field", () => {
    assert.deepEqual(ctx("ip.src "), { kind: "operator", prefix: "", start: 7, end: 7 });
    assert.deepEqual(ctx("ip.src co"), { kind: "operator", prefix: "co", start: 7, end: 9 });
    assert.equal(ctx("http ").kind, "operator");
  });

  test("logical context after a complete comparison", () => {
    for (const text of [
      "ip.src == 10.0.0.1 ",
      "ip.src == 10.0.0.1 a",
      "(ip.src==1.2.3.4) ",
      'http.host contains "x" ',
      "tcp.port in {80 443} ",
      "eth.src == 00:11:22:33:44:55 ",
      "tcp.port == 80 ",
    ]) {
      assert.equal(ctx(text).kind, "logical", text);
    }
  });

  test("no completions inside strings or where a value is expected", () => {
    assert.equal(ctx('http.host == "ex').kind, "none");
    assert.equal(ctx('http.host == "a \\" b').kind, "none");
    assert.equal(ctx("ip.src == ").kind, "none");
    assert.equal(ctx("ip.src == 10").kind, "none");
    assert.equal(ctx("80").kind, "none");
  });

  test("operator suggestions filter by prefix", () => {
    assert.deepEqual(lib.operatorSuggestions("operator", "co").map((o) => o.label), ["contains"]);
    assert.deepEqual(lib.operatorSuggestions("logical", "").map((o) => o.label), ["&&", "||", "and", "or", "^^"]);
    assert.deepEqual(lib.operatorSuggestions("operator", "!").map((o) => o.label), ["!="]);
  });

  test("applyCompletion inserts fields as-is and pads operators", () => {
    assert.deepEqual(lib.applyCompletion("ip.sr", { start: 0, end: 5 }, "ip.src", false), { text: "ip.src", cursor: 6 });
    assert.deepEqual(lib.applyCompletion("ip.src ", { start: 7, end: 7 }, "==", true), { text: "ip.src == ", cursor: 10 });
    assert.deepEqual(lib.applyCompletion("ip.src co 1", { start: 7, end: 9 }, "contains", true), {
      text: "ip.src contains 1",
      cursor: 16,
    });
    assert.deepEqual(lib.applyCompletion("ip.s == 1", { start: 0, end: 4 }, "ip.src", false), { text: "ip.src == 1", cursor: 6 });
  });

  test("friendlyType", () => {
    assert.equal(lib.friendlyType("FT_IPv4"), "IPv4 address");
    assert.equal(lib.friendlyType("FT_UINT16"), "unsigned integer, 2 bytes");
    assert.equal(lib.friendlyType("FT_INT8"), "signed integer, 1 byte");
    assert.equal(lib.friendlyType("FT_STRING"), "character string");
    assert.equal(lib.friendlyType("FT_SOMETHING_NEW"), "something_new");
  });
});

suite("webview lib: columns", () => {
  test("acceptedColumns keeps configured titles for accepted fields only", () => {
    const configured = [
      { field: "tcp.stream", title: "Stream" },
      { field: "no.such.field", title: "Typo" },
      { field: "http.host", title: "Host" },
    ];
    const accepted = [{ field: "tcp.stream" }, { field: "http.host" }];
    assert.deepEqual(lib.acceptedColumns(configured, accepted), [
      { field: "tcp.stream", title: "Stream" },
      { field: "http.host", title: "Host" },
    ]);
    assert.deepEqual(lib.acceptedColumns(configured, []), []);
  });
});

suite("webview lib: follow stream and statistics helpers", () => {
  test("bytesToAscii keeps text, newlines and tabs; drops CR before LF", () => {
    assert.equal(lib.bytesToAscii(new Uint8Array([0x47, 0x0d, 0x0a, 0x00, 0x09, 0xc8, 0x0d])), "G\n.\t..");
  });

  test("hexDump lays out 16 bytes per line with offsets and ASCII", () => {
    const dump = lib.hexDump(new Uint8Array([...Buffer.from("HTTP/1.1 200 OK\r\nX")]), 16);
    assert.deepEqual(dump.split("\n"), [
      "00000010  48 54 54 50 2f 31 2e 31  20 32 30 30 20 4f 4b 0d  HTTP/1.1 200 OK.",
      "00000020  0a 58                                             .X",
    ]);
    assert.equal(lib.hexDump(new Uint8Array([])), "");
  });

  test("streamFilter", () => {
    assert.equal(lib.streamFilter("tcp", 3), "tcp.stream eq 3");
    assert.equal(lib.streamFilter("http", 0), "tcp.stream eq 0");
    assert.equal(lib.streamFilter("udp", 7), "udp.stream eq 7");
  });

  test("formatCell", () => {
    assert.equal(lib.formatCell(1234567), "1,234,567");
    assert.equal(lib.formatCell(0.0001234567), "0.000123");
    assert.equal(lib.formatCell("x"), "x");
    assert.equal(lib.formatCell(undefined), "");
  });

  test("sortRows is stable, numeric for numbers, natural for text", () => {
    const rows = [{ cells: ["b", 2] }, { cells: ["A", 10] }, { cells: ["a", 1] }, { cells: ["x10", 3] }, { cells: ["x9", 3] }];
    assert.deepEqual(lib.sortRows(rows, 0, false).map((r) => r.cells[0]), ["A", "a", "b", "x9", "x10"]);
    assert.deepEqual(lib.sortRows(rows, 1, true).map((r) => r.cells[1]), [10, 3, 3, 2, 1]);
    assert.deepEqual(lib.sortRows(rows, 1, true).map((r) => r.cells[0]).slice(1, 3), ["x10", "x9"]); // ties keep order
  });

  test("tableToCsv quotes where needed", () => {
    assert.equal(lib.tableToCsv([{ label: "a" }, { label: "b,c" }], [{ cells: [1, 'x"y'] }, { cells: ["line\nbreak", null] }]), 'a,"b,c"\n1,"x""y"\n"line\nbreak",');
  });

  test("niceTicks covers the maximum with 1-2-5 steps", () => {
    assert.deepEqual(lib.niceTicks(561), [0, 200, 400, 600]);
    assert.deepEqual(lib.niceTicks(1000), [0, 500, 1000]);
    assert.deepEqual(lib.niceTicks(5), [0, 2, 4, 6]);
    assert.deepEqual(lib.niceTicks(0), [0, 1]);
    assert.deepEqual(lib.niceTicks(0.9), [0, 0.5, 1]);
  });
});

suite("webview lib: coloring", () => {
  const coloring = { id: 3, rules: [{ foreground: "#000000", background: "#e4ffc7" }, { foreground: "red", background: "#ffffff" }] };

  test("rowColors uses the rule of the current coloring only", () => {
    assert.deepEqual(lib.rowColors({ color: 0, cid: 3 }, coloring), coloring.rules[0]);
    assert.equal(lib.rowColors({ color: 0, cid: 2 }, coloring), null); // stale page
    assert.equal(lib.rowColors({ cid: 3 }, coloring), null); // no rule matched
    assert.equal(lib.rowColors({ color: 5, cid: 3 }, coloring), null);
    assert.equal(lib.rowColors({ color: 1, cid: 3 }, coloring), null); // invalid color
    assert.equal(lib.rowColors({ color: 0, cid: 3 }, null), null);
    assert.equal(lib.rowColors(undefined, coloring), null);
  });
});
