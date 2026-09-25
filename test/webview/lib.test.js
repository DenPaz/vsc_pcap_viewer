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
