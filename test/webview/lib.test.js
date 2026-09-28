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
        assert.ok(
          index >= w.first && index < w.first + w.count,
          `index ${index} of ${total} visible`,
        );
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
    // delete: the packet list drops the short last page when the list grows.
    assert.equal(m.delete("a"), true);
    assert.equal(m.delete("a"), false);
    assert.deepEqual([...m.entries()], [["c", 3]]);
  });
});

suite("webview lib: filters", () => {
  test("buildFieldFilter picks literal forms", () => {
    assert.equal(lib.buildFieldFilter({ name: "ip.src", show: "10.0.0.1" }), "ip.src == 10.0.0.1");
    assert.equal(lib.buildFieldFilter({ name: "tcp.port", show: "443" }), "tcp.port == 443");
    assert.equal(lib.buildFieldFilter({ name: "ip.flags", show: "0x02" }), "ip.flags == 0x02");
    assert.equal(
      lib.buildFieldFilter({ name: "eth.src", show: "02:00:00:00:00:01" }),
      "eth.src == 02:00:00:00:00:01",
    );
    assert.equal(
      lib.buildFieldFilter({ name: "ipv6.src", show: "fe80::1" }),
      "ipv6.src == fe80::1",
    );
    assert.equal(
      lib.buildFieldFilter({ name: "tcp.flags.syn", show: "True" }),
      "tcp.flags.syn == 1",
    );
    assert.equal(lib.buildFieldFilter({ name: "http", proto: true, show: "x" }), "http");
    assert.equal(lib.buildFieldFilter({ name: "tcp.segments", show: "" }), "tcp.segments");
  });

  test("buildFieldFilter quotes and escapes strings", () => {
    assert.equal(
      lib.buildFieldFilter({ name: "http.host", show: "example.com" }),
      'http.host == "example.com"',
    );
    assert.equal(
      lib.buildFieldFilter({ name: "http.user_agent", show: 'a "b" \\c' }),
      'http.user_agent == "a \\"b\\" \\\\c"',
    );
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
      id: 1,
      label: "Ethernet",
      name: "eth",
      pos: 0,
      size: 14,
      src: 0,
      children: [
        {
          id: 2,
          label: "Dst",
          name: "eth.dst",
          pos: 0,
          size: 6,
          src: 0,
          children: [{ id: 3, label: "OUI", name: "eth.dst.oui", pos: 0, size: 3, src: 0 }],
        },
      ],
    },
    {
      id: 4,
      label: "IP",
      name: "ip",
      pos: 14,
      size: 20,
      src: 0,
      children: [{ id: 5, label: "Src", name: "ip.src", pos: 26, size: 4, src: 0 }],
    },
    { id: 6, label: "HTTP", name: "http", pos: 0, size: 40, src: 1 },
  ];

  test("findNodeForByte returns the smallest enclosing field", () => {
    assert.deepEqual(
      lib.findNodeForByte(tree, 0, 1).map((n) => n.id),
      [1, 2, 3],
    );
    assert.deepEqual(
      lib.findNodeForByte(tree, 0, 4).map((n) => n.id),
      [1, 2],
    );
    assert.deepEqual(
      lib.findNodeForByte(tree, 0, 27).map((n) => n.id),
      [4, 5],
    );
    assert.deepEqual(
      lib.findNodeForByte(tree, 1, 1).map((n) => n.id),
      [6],
    );
    assert.equal(lib.findNodeForByte(tree, 0, 100), null);
  });

  test("nodeKey is stable across packets", () => {
    assert.equal(
      lib.nodeKey([{ name: "ip", label: "IPv4" }, { label: "Flags: 0x2" }]),
      "ip/Flags: #x#",
    );
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
    assert.equal(lib.formatDuration(5.9), "0:05");
    assert.equal(lib.formatDuration(754), "12:34");
    assert.equal(lib.formatDuration(3723), "1:02:03");
    assert.equal(lib.formatDuration(-1), "0:00");
  });
});

suite("webview lib: autocomplete", () => {
  const ctx = (text, cursor = text.length) => lib.completionContext(text, cursor);

  test("field context at the start and after logical operators", () => {
    assert.deepEqual(ctx("ip.sr"), { kind: "field", prefix: "ip.sr", start: 0, end: 5 });
    assert.equal(ctx("").kind, "field");
    assert.deepEqual(ctx("tcp.port == 80 && ht"), {
      kind: "field",
      prefix: "ht",
      start: 18,
      end: 20,
    });
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
    assert.deepEqual(
      lib.operatorSuggestions("operator", "co").map((o) => o.label),
      ["contains"],
    );
    assert.deepEqual(
      lib.operatorSuggestions("logical", "").map((o) => o.label),
      ["&&", "||", "and", "or", "^^"],
    );
    assert.deepEqual(
      lib.operatorSuggestions("operator", "!").map((o) => o.label),
      ["!="],
    );
  });

  test("applyCompletion inserts fields as-is and pads operators", () => {
    assert.deepEqual(lib.applyCompletion("ip.sr", { start: 0, end: 5 }, "ip.src", false), {
      text: "ip.src",
      cursor: 6,
    });
    assert.deepEqual(lib.applyCompletion("ip.src ", { start: 7, end: 7 }, "==", true), {
      text: "ip.src == ",
      cursor: 10,
    });
    assert.deepEqual(lib.applyCompletion("ip.src co 1", { start: 7, end: 9 }, "contains", true), {
      text: "ip.src contains 1",
      cursor: 16,
    });
    assert.deepEqual(lib.applyCompletion("ip.s == 1", { start: 0, end: 4 }, "ip.src", false), {
      text: "ip.src == 1",
      cursor: 6,
    });
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
    assert.equal(
      lib.bytesToAscii(new Uint8Array([0x47, 0x0d, 0x0a, 0x00, 0x09, 0xc8, 0x0d])),
      "G\n.\t..",
    );
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
    const rows = [
      { cells: ["b", 2] },
      { cells: ["A", 10] },
      { cells: ["a", 1] },
      { cells: ["x10", 3] },
      { cells: ["x9", 3] },
    ];
    assert.deepEqual(
      lib.sortRows(rows, 0, false).map((r) => r.cells[0]),
      ["A", "a", "b", "x9", "x10"],
    );
    assert.deepEqual(
      lib.sortRows(rows, 1, true).map((r) => r.cells[1]),
      [10, 3, 3, 2, 1],
    );
    assert.deepEqual(
      lib
        .sortRows(rows, 1, true)
        .map((r) => r.cells[0])
        .slice(1, 3),
      ["x10", "x9"],
    ); // ties keep order
  });

  test("tableToCsv quotes where needed", () => {
    assert.equal(
      lib.tableToCsv(
        [{ label: "a" }, { label: "b,c" }],
        [{ cells: [1, 'x"y'] }, { cells: ["line\nbreak", null] }],
      ),
      'a,"b,c"\n1,"x""y"\n"line\nbreak",',
    );
  });

  test("rowsToText: tab-separated rows, optional header, one line per row", () => {
    const rows = [
      ["1", "GET /\tx", "a\r\nb"],
      ["2", "", "c"],
    ];
    assert.equal(
      lib.rowsToText(["No.", "Info", "More"], rows, true),
      "No.\tInfo\tMore\n1\tGET / x\ta b\n2\t\tc",
    );
    assert.equal(lib.rowsToText(["No."], [["7"]], false), "7");
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
  const coloring = {
    id: 3,
    rules: [
      { foreground: "#000000", background: "#e4ffc7" },
      { foreground: "red", background: "#ffffff" },
    ],
  };

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

suite("webview lib: navigation and customisation", () => {
  const col = (id, extra = {}) => ({ id, field: id, ...extra });

  test("flowArrow places arrows between endpoint columns", () => {
    const layout = { gutter: 100, column: 50 };
    assert.deepEqual(lib.flowArrow(0, 2, 3, layout), { x1: 125, x2: 225, self: false });
    assert.deepEqual(lib.flowArrow(1, 1, 3, layout), { x1: 175, x2: 175, self: true });
    assert.equal(lib.flowArrow(-1, 0, 3, layout).x1, 275, "past the limit: the 'other' column");
    assert.equal(lib.truncate("abcdef", 4), "abc…");
    assert.equal(lib.truncate("abc", 4), "abc");
    assert.equal(lib.truncate("abc", 0), "");
  });

  test("niceRange covers min..max with round ticks", () => {
    assert.deepEqual(lib.niceRange(0.018, 0.038), [0.015, 0.02, 0.025, 0.03, 0.035, 0.04]);
    assert.deepEqual(lib.niceRange(120, 480), [100, 200, 300, 400, 500]);
    assert.deepEqual(lib.niceRange(5, 5), lib.niceTicks(5));
  });

  test("tcpGraphSeries builds the four TCP stream graphs", () => {
    // frame, time, dir, seq, len, ack, win, rtt, retrans
    const pts = [
      [1, 0, 0, 0, 0, 0, 8192, null, 0],
      [2, 0.1, 1, 0, 0, 1, 8192, 0.1, 0],
      [3, 0.2, 0, 1, 100, 1, 8192, null, 0],
      [4, 0.3, 1, 1, 0, 101, 4096, 0.1, 0],
      [5, 0.4, 0, 101, 100, 1, 8192, null, 0],
      [6, 0.5, 0, 101, 100, 1, 8192, null, 1],
    ];
    const stevens = lib.tcpGraphSeries(pts, 0, "stevens");
    assert.deepEqual(
      stevens.points.map((/** @type {any} */ p) => [p.frame, p.y, p.y2, p.flag]),
      [
        [3, 1, 101, false],
        [5, 101, 201, false],
        [6, 101, 201, true],
      ],
    );
    const tput = lib.tcpGraphSeries(pts, 0, "throughput", { window: 0.25 });
    assert.deepEqual(
      tput.points.map((/** @type {any} */ p) => p.y),
      [400, 800, 800],
      "bytes in the last 0.25 s, per second",
    );
    const rtt = lib.tcpGraphSeries(pts, 0, "rtt");
    assert.deepEqual(
      rtt.points.map((/** @type {any} */ p) => [p.frame, p.y]),
      [
        [2, 100],
        [4, 100],
      ],
      "the receiver's ACKs, in ms",
    );
    const win = lib.tcpGraphSeries(pts, 0, "window");
    assert.deepEqual(
      win.line.map((/** @type {any} */ p) => p.y),
      [8192, 4096],
    );
    assert.deepEqual(
      win.points.map((/** @type {any} */ p) => p.y),
      [100, 100, 100],
      "bytes sent but not acknowledged",
    );
    assert.equal(lib.tcpGraphSeries(pts, 1, "stevens").points.length, 0, "no data that way");
  });

  test("filterObjects filters Export Objects rows by protocol and text", () => {
    const objs = [
      { id: 0, protocol: "http", name: "logo.png", host: "example.com", contentType: "image/png" },
      {
        id: 1,
        protocol: "tftp",
        name: "config.bin",
        host: "",
        contentType: "application/octet-stream",
      },
      {
        id: 2,
        protocol: "http",
        name: "report",
        host: "cdn.example.org",
        contentType: "text/plain",
      },
    ];
    const ids = (/** @type {{id: number}[]} */ list) => list.map((o) => o.id);
    assert.deepEqual(ids(lib.filterObjects(objs, "", "")), [0, 1, 2]);
    assert.deepEqual(ids(lib.filterObjects(objs, "http", "")), [0, 2]);
    assert.deepEqual(ids(lib.filterObjects(objs, "", "  PNG ")), [0]);
    assert.deepEqual(ids(lib.filterObjects(objs, "", "example")), [0, 2]);
    assert.deepEqual(ids(lib.filterObjects(objs, "tftp", "example")), []);
  });

  test("cellAddress finds the address behind a resolved name", () => {
    const row = {
      cells: ["1", "0", "example.com", "Broadcast", "ARP"],
      addresses: ["93.184.216.34", "ff:ff:ff:ff:ff:ff"],
    };
    assert.equal(lib.cellAddress(col("source"), row), "93.184.216.34");
    assert.equal(lib.cellAddress(col("destination"), row), "ff:ff:ff:ff:ff:ff");
    assert.equal(
      lib.cellFilter(col("destination"), lib.cellAddress(col("destination"), row)),
      "eth.dst == ff:ff:ff:ff:ff:ff",
    );
    assert.equal(lib.cellAddress(col("protocol"), row), null);
    const same = {
      cells: ["1", "0", "10.0.0.1", "example.com"],
      addresses: ["10.0.0.1", "93.184.216.34"],
    };
    assert.equal(lib.cellAddress(col("source"), same), null, "the cell already shows the address");
    assert.equal(lib.cellAddress(col("source"), { cells: ["1", "0", "10.0.0.1"] }), null);
    assert.equal(lib.cellAddress(col("source"), undefined), null);
  });

  test("cellFilter builds filters from packet-list cells", () => {
    assert.equal(lib.cellFilter(col("source"), "192.168.1.10"), "ip.src == 192.168.1.10");
    assert.equal(lib.cellFilter(col("destination"), "93.184.216.34"), "ip.dst == 93.184.216.34");
    assert.equal(lib.cellFilter(col("source"), "fe80::1"), "ipv6.src == fe80::1");
    assert.equal(lib.cellFilter(col("destination"), "2001:db8::2"), "ipv6.dst == 2001:db8::2");
    assert.equal(
      lib.cellFilter(col("source"), "02:00:00:00:00:01"),
      "eth.src == 02:00:00:00:00:01",
    );
    assert.equal(lib.cellFilter(col("destination"), "Broadcast"), null); // a resolved name: no field to match
    assert.equal(lib.cellFilter(col("protocol"), "DNS"), "dns");
    assert.equal(lib.cellFilter(col("protocol"), "TLSv1.3"), "tls");
    assert.equal(lib.cellFilter(col("protocol"), "HTTP/JSON"), "http");
    assert.equal(lib.cellFilter(col("protocol"), "0x86dd"), null);
    assert.equal(lib.cellFilter(col("length"), "144"), "frame.len == 144");
    assert.equal(lib.cellFilter(col("number"), "4"), "frame.number == 4");
    assert.equal(lib.cellFilter(col("time"), "0.001000"), null);
    assert.equal(lib.cellFilter(col("info"), "GET /"), null);
    assert.equal(
      lib.cellFilter(col("custom:http.host", { field: "http.host", custom: true }), "example.com"),
      'http.host == "example.com"',
    );
    assert.equal(
      lib.cellFilter(col("custom:tcp.stream", { field: "tcp.stream", custom: true }), "3"),
      "tcp.stream == 3",
    );
    assert.equal(
      lib.cellFilter(col("custom:ip.ttl", { field: "ip.ttl", custom: true }), "64,63"),
      "ip.ttl == 64",
    ); // first occurrence
    assert.equal(
      lib.cellFilter(col("custom:x.y", { field: "x.y", custom: true }), 'say "hi"'),
      'x.y == "say \\"hi\\""',
    );
    assert.equal(lib.cellFilter(col("source"), ""), null);
  });

  test("parseHexBytes accepts the usual spellings", () => {
    assert.deepEqual(lib.parseHexBytes("474554"), ["47", "45", "54"]);
    assert.deepEqual(lib.parseHexBytes("47 45 54"), ["47", "45", "54"]);
    assert.deepEqual(lib.parseHexBytes("47:45:54"), ["47", "45", "54"]);
    assert.deepEqual(lib.parseHexBytes("0x47, 0x45"), ["47", "45"]);
    assert.deepEqual(lib.parseHexBytes("A b"), ["0a", "0b"]);
    assert.equal(lib.parseHexBytes("abc"), null);
    assert.equal(lib.parseHexBytes("zz"), null);
    assert.equal(lib.parseHexBytes("   "), null);
  });

  test("formatBytesAs: the bytes pane's copy formats", () => {
    const b = Uint8Array.from([0x47, 0x45, 0x54, 0x20, 0x2f, 0x0d, 0x0a, 0x00, 0x41]);
    assert.equal(lib.formatBytesAs(b, "hex"), "474554202f0d0a0041");
    assert.equal(lib.formatBytesAs(b, "escaped"), "\\x47\\x45\\x54\\x20\\x2f\\x0d\\x0a\\x00\\x41");
    assert.equal(lib.formatBytesAs(b, "base64"), Buffer.from(b).toString("base64"));
    assert.equal(lib.formatBytesAs(b, "text"), "GET /\nA");
    assert.equal(
      lib.formatBytesAs(b, "c"),
      "static const unsigned char packet_bytes[9] = {\n  0x47, 0x45, 0x54, 0x20, 0x2f, 0x0d, 0x0a, 0x00,\n  0x41\n};",
    );
    assert.equal(
      lib.formatBytesAs(b, "hexdump", 0x10),
      "00000010  47 45 54 20 2f 0d 0a 00  41                       GET /...A",
    );
    for (const n of [0, 1, 2, 3, 4, 5]) {
      const bytes = Uint8Array.from({ length: n }, (_, i) => i * 37);
      assert.equal(lib.toBase64(bytes), Buffer.from(bytes).toString("base64"));
    }
  });

  test("layoutColumns and moveColumn", () => {
    const all = ["number", "time", "source", "info", "custom:tcp.stream"].map((id) => ({ id }));
    const ids = (layout) => lib.layoutColumns(all, layout).map((c) => `${c.column.id}@${c.index}`);
    assert.deepEqual(ids(undefined), [
      "number@0",
      "time@1",
      "source@2",
      "info@3",
      "custom:tcp.stream@4",
    ]);
    assert.deepEqual(ids({ hidden: ["time"] }), [
      "number@0",
      "source@2",
      "info@3",
      "custom:tcp.stream@4",
    ]);
    assert.deepEqual(ids({ order: ["info", "number"] }), [
      "info@3",
      "number@0",
      "time@1",
      "source@2",
      "custom:tcp.stream@4",
    ]);
    assert.deepEqual(ids({ hidden: all.map((c) => c.id) }), ["number@0"]); // never zero columns
    assert.deepEqual(lib.moveColumn(["a", "b", "c", "d"], "d", "b"), ["a", "d", "b", "c"]);
    assert.deepEqual(lib.moveColumn(["a", "b", "c"], "a", null), ["b", "c", "a"]);
  });

  test("indexingLabel: percentage, packets, and the catching-up phase", () => {
    const n = (v) => v.toLocaleString();
    assert.equal(
      lib.indexingLabel({ frames: 420000, fraction: 0.4213 }),
      `Indexing… 42% · ${n(420000)} packets`,
    );
    assert.equal(lib.indexingLabel({ frames: 7, fraction: null }), "Indexing… 7 packets");
    assert.equal(lib.indexingLabel({ frames: 7, fraction: 1.7 }), "Indexing… 100% · 7 packets");
    assert.equal(
      lib.indexingLabel({ frames: 50000, fraction: 0.1, phase: "catching-up", resumedAt: 50000 }),
      `Resuming… re-reading packets 1–${n(50000)} (already shown)`,
    );
    assert.equal(
      lib.indexingLabel({ frames: 50001, fraction: 0.2, phase: "indexing", resumedAt: 50000 }),
      `Indexing… 20% · ${n(50001)} packets`,
    );
  });

  test("progressView: indexing first, then filter, export, coloring, other work", () => {
    const hidden = { visible: false, fraction: null, secondary: false, label: "" };
    assert.deepEqual(lib.progressView({}), hidden);
    assert.deepEqual(lib.progressView({ index: null, filter: undefined }), hidden);
    assert.deepEqual(lib.progressView({ index: { frames: 10, fraction: 0.25 }, filter: 0.9 }), {
      visible: true,
      fraction: 0.25,
      secondary: false,
      label: "Indexing packets",
    });
    assert.deepEqual(lib.progressView({ index: { frames: 10, fraction: null } }), {
      visible: true,
      fraction: null,
      secondary: false,
      label: "Indexing packets",
    });
    const resuming = lib.progressView({
      index: { frames: 10, fraction: 0.1, phase: "catching-up", resumedAt: 10 },
    });
    assert.deepEqual(resuming, {
      visible: true,
      fraction: 0.1,
      secondary: true,
      label: "Resuming indexing",
    });
    assert.deepEqual(lib.progressView({ filter: 0.5, exporting: 0.1 }).label, "Filtering packets");
    assert.deepEqual(lib.progressView({ exporting: null, coloring: 0.3 }), {
      visible: true,
      fraction: null,
      secondary: false,
      label: "Exporting",
    });
    assert.equal(lib.progressView({ coloring: 0.3, busy: null }).label, "Coloring packets");
    assert.equal(lib.progressView({ busy: -2 }).fraction, 0, "clamped to 0–1");
    assert.equal(lib.progressView({ busy: 0 }).visible, true, "0% is still running");
  });

  test("callFlow: endpoint columns and SIP/RTP rows in time order", () => {
    const streams = [
      { src: "10.0.0.2", dst: "10.0.0.1", start: 1.021, payload: "g711U", packets: 50, lost: 0 },
      {
        src: "10.0.0.1",
        dst: "10.0.0.2",
        start: 1.0213,
        payload: "g711U",
        packets: 49,
        lost: 1,
        lostPercent: 2,
      },
      { src: "10.0.0.9", dst: "10.0.0.8", start: 0, payload: "g729", packets: 1, lost: 0 },
    ];
    const call = {
      messages: [
        [1, 0, "10.0.0.1", "10.0.0.2", "INVITE (SDP)"],
        [4, 1.0, "10.0.0.2", "10.0.0.1", "200 OK (SDP)"],
        [105, 2.07, "10.0.0.1", "10.0.0.3", "BYE"],
      ],
      streams: [0, 1],
    };
    const { nodes, rows } = lib.callFlow(call, streams);
    assert.deepEqual(nodes, ["10.0.0.1", "10.0.0.2", "10.0.0.3"]);
    assert.deepEqual(
      rows.map((r) => [r.from, r.to, r.label, r.frame ?? `stream ${r.stream}`]),
      [
        [0, 1, "INVITE (SDP)", 1],
        [1, 0, "200 OK (SDP)", 4],
        [1, 0, "RTP g711U · 50 packets", "stream 0"],
        [0, 1, "RTP g711U · 49 packets · 1 lost (2.0%)", "stream 1"],
        [0, 2, "BYE", 105],
      ],
    );
    assert.equal(
      lib.rtpStreamLabel({ payload: "g711A", packets: 10, lost: -2 }),
      "g711A · 10 packets · 2 duplicated",
    );
  });

  test("rtpProblems lists sequence gaps, late packets and payload changes", () => {
    const points = [
      [7, 0, 1000, 0, 0, 0, 1, 0, 0],
      [48, 0.42, 1021, 42.3, 1.05, -2.6, 0, 1, 1],
      [50, 0.44, 1024, 20, 1, 0, 0, 1, 2],
      [51, 0.45, 1022, 1, 1, 0, 0, 2, 0],
      [52, 0.46, 1025, 20, 1, 0, 0, 3, 0],
    ];
    assert.deepEqual(lib.rtpProblems(points), [
      { frame: 48, text: "1 packet lost before seq 1021" },
      { frame: 50, text: "2 packets lost before seq 1024" },
      { frame: 51, text: "Seq 1022 out of order or duplicated" },
      { frame: 52, text: "Payload type changed at seq 1025" },
    ]);
  });

  test("groupCommands: headings in order, commands in their order, unknown groups under Other", () => {
    const c = (id, group) => ({ id, title: id, category: "PCAP", group });
    const groups = lib.groupCommands([
      c("other1", "Other"),
      c("stats1", "Statistics"),
      c("filter1", "Filters"),
      c("odd", "Something New"),
      c("stats2", "Statistics"),
      c("ai1", "AI"),
    ]);
    assert.deepEqual(
      groups.map((g) => [g.group, g.commands.map((x) => x.id)]),
      [
        ["Filters", ["filter1"]],
        ["Statistics", ["stats1", "stats2"]],
        ["AI", ["ai1"]],
        ["Other", ["other1", "odd"]],
      ],
    );
    assert.deepEqual(lib.groupCommands([]), []);
    assert.deepEqual(lib.COMMAND_GROUP_ORDER.slice(0, 3), ["Filters", "Packets", "Statistics"]);
  });

  test("filterCommands: every word, case-insensitive, in the title, heading or category", () => {
    const commands = [
      { id: "a", title: "Conversations", category: "PCAP Statistics", group: "Statistics" },
      { id: "b", title: "Export Objects…", category: "PCAP", group: "Export" },
      { id: "c", title: "Follow TCP Stream", category: "PCAP", group: "Statistics" },
    ];
    const ids = (text) => lib.filterCommands(commands, text).map((c) => c.id);
    assert.deepEqual(ids(""), ["a", "b", "c"]);
    assert.deepEqual(ids("   "), ["a", "b", "c"]);
    assert.deepEqual(ids("CONV"), ["a"]);
    assert.deepEqual(ids("statistics"), ["a", "c"], "heading or category");
    assert.deepEqual(ids("pcap statistics tcp"), ["c"]);
    assert.deepEqual(ids("export"), ["b"]);
    assert.deepEqual(ids("nothing"), []);
  });

  test("formatKeybinding: Ctrl+… on Windows and Linux, symbols (the mac binding) on macOS", () => {
    const f = lib.formatKeybinding;
    assert.equal(f({ key: "ctrl+/", mac: "cmd+/" }, false), "Ctrl+/");
    assert.equal(f({ key: "ctrl+/", mac: "cmd+/" }, true), "⌘/");
    assert.equal(f({ key: "ctrl+shift+n", mac: "cmd+shift+n" }, false), "Ctrl+Shift+N");
    assert.equal(f({ key: "ctrl+shift+n", mac: "cmd+shift+n" }, true), "⌘⇧N");
    assert.equal(f({ key: "ctrl+alt+c", mac: "cmd+alt+c" }, true), "⌘⌥C");
    assert.equal(f({ key: "alt+left", mac: "alt+left" }, false), "Alt+Left");
    assert.equal(f({ key: "alt+left", mac: "alt+left" }, true), "⌥←");
    assert.equal(f({ key: "ctrl+g" }, true), "⌃G", "no mac binding: the key binding, in symbols");
    assert.equal(f({ key: "ctrl+k ctrl+s" }, false), "Ctrl+K Ctrl+S", "chords");
    assert.equal(f(undefined, false), "");
  });

  test("commandUnavailable: the first unmet requirement's reason, or null", () => {
    const ctx = { selected: false, marks: 0, filter: false, capturing: false, ai: false };
    const cmd = (requires) => ({ id: "x", title: "X", category: "PCAP", group: "Other", requires });
    assert.equal(lib.commandUnavailable(cmd(undefined), ctx), null);
    assert.equal(lib.commandUnavailable(cmd(["selection"]), ctx), "Select a packet first");
    assert.equal(lib.commandUnavailable(cmd(["selection"]), { ...ctx, selected: true }), null);
    assert.equal(lib.commandUnavailable(cmd(["marks"]), ctx), "No packets are marked");
    assert.equal(lib.commandUnavailable(cmd(["marks"]), { ...ctx, marks: 2 }), null);
    assert.equal(lib.commandUnavailable(cmd(["filter"]), ctx), "No display filter is applied");
    assert.equal(lib.commandUnavailable(cmd(["capturing"]), ctx), "No capture is running");
    assert.match(lib.commandUnavailable(cmd(["ai", "selection"]), ctx), /^AI help isn't available/);
    assert.equal(
      lib.commandUnavailable(cmd(["ai", "selection"]), { ...ctx, ai: true }),
      "Select a packet first",
    );
    assert.equal(lib.commandUnavailable(cmd(["something new"]), ctx), null, "unknown: allowed");
  });

  test("filterButtonTitle: the comment above the filter", () => {
    assert.equal(lib.filterButtonTitle({ filter: "dns" }), "dns");
    assert.equal(
      lib.filterButtonTitle({ filter: "dns.flags.rcode != 0", comment: "Failed lookups" }),
      "Failed lookups\ndns.flags.rcode != 0",
    );
  });
});
