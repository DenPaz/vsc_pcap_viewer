/**
 * End-to-end tests of the statistics and follow-stream panels (stats.js,
 * follow.js) in headless Chromium, with a stand-in host that forwards to the
 * real backend exactly like src/panels/*.ts does.
 */
const assert = require("node:assert/strict");
const path = require("node:path");
const { FIXTURES, HAVE_TSHARK, loadDeps, serveWebview, renderPanelHtml, startBackend, newPage } = require("./harness");

const deps = loadDeps();
const maybe = deps && HAVE_TSHARK ? suite : suite.skip;

const TITLES = {
  conversations: "Conversations",
  endpoints: "Endpoints",
  phs: "Protocol Hierarchy",
  io: "I/O Graph",
  expert: "Expert Information",
  properties: "Capture File Properties",
};

maybe("statistics and follow panels (Chromium + real backend)", function () {
  this.timeout(60_000);
  let server, browser, client, origin;
  const pages = [];

  suiteSetup(async function () {
    server = await serveWebview();
    origin = `http://127.0.0.1:${server.address().port}`;
    client = await startBackend(deps);
    await client.request("open", { path: path.join(FIXTURES, "mixed.pcapng") }, { timeoutMs: 0 });
    try {
      browser = await deps.chromium.launch();
    } catch (err) {
      console.warn(`skipping panel e2e: no Chromium available (${err.message.split("\n")[0]})`);
      this.skip();
    }
  });

  suiteTeardown(async () => {
    await browser?.close();
    await client?.dispose();
    server?.close();
  });

  /** Open stats.js with a stand-in for StatsPanel (src/panels/statsPanel.ts). */
  async function openStats(kind, captureFilter = "") {
    const { page, problems, post } = await newPage(browser);
    const log = [];
    await page.exposeFunction("__toHost", async (raw) => {
      const msg = JSON.parse(raw);
      log.push(msg);
      if (msg.type === "ready") {
        await post({ type: "init", kind, title: TITLES[kind], filter: captureFilter });
      } else if (msg.type === "query") {
        const params = { kind, type: msg.params.type, interval: msg.params.interval, filter: msg.params.limit ? captureFilter : "" };
        client.request("stats", params, { timeoutMs: 0 }).then(
          (table) => post({ type: "result", id: msg.id, table }),
          (err) => post({ type: "error", id: msg.id, message: err.message, cancelled: err.code === -32800 }),
        );
      }
    });
    await page.setContent(renderPanelHtml(origin, "stats.js"), { waitUntil: "load" });
    pages.push(problems);
    return { page, log };
  }

  const rows = (page) => page.$$eval("table.stats tbody tr", (trs) => trs.map((tr) => [...tr.children].map((td) => td.textContent)));
  const waitRows = (page, n) => page.waitForFunction((count) => document.querySelectorAll("table.stats tbody tr").length === count, n);

  test("conversations: type switch, sorting, row filter and CSV", async () => {
    const { page, log } = await openStats("conversations");
    await waitRows(page, 1);
    assert.equal(await page.textContent(".panel-title"), "TCP Conversations");
    assert.deepEqual((await rows(page))[0].slice(0, 3), ["192.168.1.10:50000", "93.184.216.34:80", "11"]);

    await page.selectOption("select[aria-label='Address type']", "udp");
    await waitRows(page, 4);
    await page.click("th:has-text('Packets A → B')"); // numeric columns sort descending first
    const sorted = (await rows(page)).map((r) => r[4]);
    assert.deepEqual(sorted, [...sorted].sort((a, b) => Number(b) - Number(a)));

    await page.click("table.stats tbody tr >> nth=0");
    await page.click("button:has-text('Apply as Filter')");
    const filter = log.find((m) => m.type === "filter");
    assert.equal(filter.apply, true);
    assert.match(filter.expr, /^ip\.addr == 10\.0\.0\.1 && udp\.port == 12345 && ip\.addr == 10\.0\.0\.2 && udp\.port == 9999$/);

    await page.click("button:has-text('Copy as CSV')");
    const csv = log.find((m) => m.type === "copy").text.split("\n");
    assert.equal(csv[0], "Address A,Address B,Packets,Bytes,Packets A → B,Bytes A → B,Packets B → A,Bytes B → A,Rel Start,Duration");
    assert.equal(csv.length, 5);
  });

  test("limit to the capture's display filter", async () => {
    const { page } = await openStats("conversations", "http");
    await waitRows(page, 1);
    assert.equal((await rows(page))[0][2], "11");
    await page.check("input[type=checkbox]");
    await page.waitForFunction(() => document.querySelector("table.stats tbody tr td:nth-child(3)")?.textContent === "2");
    assert.match(await page.textContent(".status"), /matching http/);
  });

  test("protocol hierarchy keeps the tree and indents by depth", async () => {
    const { page } = await openStats("phs");
    await waitRows(page, 11);
    // tshark 4.6 adds a top-level "frame" row (everything one level deeper than
    // 4.2), so compare depths instead of expecting absolute ones.
    const indent = (proto) => page.$eval(`table.stats tbody tr:has(td:text-is('${proto}')) td`, (td) => parseFloat(getComputedStyle(td).paddingLeft));
    assert.equal((await indent("dns")) - (await indent("udp")), 16, "dns one level below udp");
    assert.equal((await indent("arp")) - (await indent("eth")), 16, "arp one level below eth");
    const names = (await rows(page)).map((r) => r[0]);
    const eth = names.indexOf("eth");
    assert.deepEqual(names.slice(eth, eth + 3), ["eth", "arp", "ip"]);
  });

  test("IO graph: line chart with crosshair tooltip, keyboard and metric switch", async () => {
    const { page } = await openStats("io");
    await page.waitForSelector(".chart svg .series-line");
    assert.ok((await page.getAttribute(".chart svg .series-line", "d")).startsWith("M"));
    assert.ok((await page.$$eval(".chart .axis text", (t) => t.length)) >= 4);
    const box = await page.locator(".chart svg").boundingBox();
    await page.mouse.move(box.x + box.width / 2, box.y + box.height / 2);
    await page.waitForSelector(".chart .tooltip:not(.hidden)");
    assert.match(await page.textContent(".chart .tooltip strong"), /^\d+ packets$/);
    await page.focus(".chart");
    await page.keyboard.press("Home");
    await page.keyboard.press("ArrowRight");
    assert.match(await page.textContent(".chart .tooltip span"), /^0\.00\d+–0\.00\d+ s$/);
    await page.selectOption("select[aria-label='Metric']", "bytes");
    await page.mouse.move(box.x + box.width / 2, box.y + box.height / 2);
    await page.waitForFunction(() => /bytes$/.test(document.querySelector(".chart .tooltip strong")?.textContent ?? ""));
  });

  test("expert information: severity and go to packet", async () => {
    const { page, log } = await openStats("expert");
    await page.waitForSelector("table.stats tbody tr");
    assert.ok(await page.$(".sev.sev-Chat"));
    await page.click("table.stats tbody tr:has-text('Connection finish (FIN)')");
    await page.click("button:has-text('Go to Packet')");
    assert.deepEqual(log.find((m) => m.type === "goto"), { type: "goto", frame: 18 });
    await page.click("button:has-text('Prepare as Filter')");
    assert.deepEqual(log.find((m) => m.type === "filter"), { type: "filter", expr: '_ws.expert.message == "Connection finish (FIN)"', apply: false });
  });

  test("capture file properties", async () => {
    const { page } = await openStats("properties");
    await page.waitForSelector("table.stats tbody tr");
    const props = Object.fromEntries((await rows(page)).map((r) => [r[0], r[1]]));
    assert.equal(props["Number of packets"], "26");
    assert.equal(await page.$("input[type=checkbox]"), null); // no filter limit for file properties
  });

  test("follow TCP stream: directions, formats, stepping, filter and save", async () => {
    const { page, problems, post } = await newPage(browser);
    pages.push(problems);
    const log = [];
    let target = { frame: 14 };
    const load = () =>
      client.request("follow_stream", { proto: "tcp", ...target }, { timeoutMs: 0 }).then(
        (result) => post({ type: "result", result, label: "TCP" }),
        (err) => post({ type: "error", message: err.message }),
      );
    await page.exposeFunction("__toHost", async (raw) => {
      const msg = JSON.parse(raw);
      log.push(msg);
      if (msg.type === "ready") {
        await load();
      } else if (msg.type === "stream") {
        target = { stream: msg.stream };
        await load();
      }
    });
    await page.setContent(renderPanelHtml(origin, "follow.js"), { waitUntil: "load" });
    await page.waitForSelector("pre.segment");
    assert.equal(await page.textContent(".panel-title"), "TCP stream 0");
    assert.match(await page.textContent(".follow-legend"), /192\.168\.1\.10:50000 → 93\.184\.216\.34:80/);
    assert.ok((await page.textContent("pre.segment.dir0")).startsWith("GET /index.html HTTP/1.1\nHost: example.com"));
    assert.ok((await page.textContent("pre.segment.dir1")).startsWith("HTTP/1.1 200 OK\nContent-Type: text/html"));

    await page.selectOption("select[aria-label='Direction']", "1");
    assert.equal(await page.locator("pre.segment.dir0").count(), 0);
    await page.selectOption("select[aria-label='Show data as']", "hex");
    assert.ok((await page.textContent("pre.segment")).startsWith("00000000  48 54 54 50 2f 31 2e 31"));

    await page.click("button:has-text('Save as…')");
    const saveText = log.find((m) => m.type === "save");
    assert.equal(saveText.dir, 1);
    assert.equal(saveText.format, "text");
    assert.ok(saveText.text.startsWith("00000000  48 54 54 50"));
    await page.selectOption("select[aria-label='Show data as']", "raw");
    await page.click("button:has-text('Save as…')");
    assert.deepEqual(log.filter((m) => m.type === "save").at(-1), { type: "save", dir: 1, format: "raw" });

    await page.click("button:has-text('Filter to Stream')");
    assert.deepEqual(log.find((m) => m.type === "filter"), { type: "filter", expr: "tcp.stream eq 0", apply: true });

    // There is only one TCP stream in the capture: the next one is empty.
    await page.click("button[title='Next stream']");
    await page.waitForFunction(() => document.querySelector(".panel-title").textContent === "TCP stream 1");
    assert.equal(await page.textContent(".status"), "No payload in this stream.");
    assert.equal(await page.locator("pre.segment").count(), 0);
  });

  test("no script errors or CSP violations in any panel", () => {
    for (const p of pages) {
      assert.deepEqual(p.errors, []);
      assert.deepEqual(p.csp, []);
    }
  });
});
