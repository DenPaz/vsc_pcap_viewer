/**
 * End-to-end tests of the statistics and follow-stream panels (stats.js,
 * follow.js) in headless Chromium, with a stand-in host that forwards to the
 * real backend exactly like src/panels/*.ts does.
 */
const assert = require("node:assert/strict");
const path = require("node:path");
const {
  FIXTURES,
  HAVE_TSHARK,
  loadDeps,
  serveWebview,
  renderPanelHtml,
  startBackend,
  newPage,
} = require("./harness");

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
        const params = {
          kind,
          type: msg.params.type,
          interval: msg.params.interval,
          filter: msg.params.limit ? captureFilter : "",
        };
        client.request("stats", params, { timeoutMs: 0 }).then(
          (table) => post({ type: "result", id: msg.id, table }),
          (err) =>
            post({
              type: "error",
              id: msg.id,
              message: err.message,
              cancelled: err.code === -32800,
            }),
        );
      }
    });
    await page.setContent(renderPanelHtml(origin, "stats.js"), { waitUntil: "load" });
    pages.push(problems);
    return { page, log };
  }

  const rows = (page) =>
    page.$$eval("table.stats tbody tr", (trs) =>
      trs.map((tr) => [...tr.children].map((td) => td.textContent)),
    );
  const waitRows = (page, n) =>
    page.waitForFunction(
      (count) => document.querySelectorAll("table.stats tbody tr").length === count,
      n,
    );

  test("conversations: type switch, sorting, row filter and CSV", async () => {
    const { page, log } = await openStats("conversations");
    await waitRows(page, 1);
    assert.equal(await page.textContent(".panel-title"), "TCP Conversations");
    assert.deepEqual((await rows(page))[0].slice(0, 3), [
      "192.168.1.10:50000",
      "93.184.216.34:80",
      "11",
    ]);

    await page.selectOption("select[aria-label='Address type']", "udp");
    await waitRows(page, 4);
    await page.click("th:has-text('Packets A → B')"); // numeric columns sort descending first
    const sorted = (await rows(page)).map((r) => r[4]);
    assert.deepEqual(
      sorted,
      [...sorted].sort((a, b) => Number(b) - Number(a)),
    );

    await page.click("table.stats tbody tr >> nth=0");
    await page.click("button:has-text('Apply as Filter')");
    const filter = log.find((m) => m.type === "filter");
    assert.equal(filter.apply, true);
    assert.match(
      filter.expr,
      /^ip\.addr == 10\.0\.0\.1 && udp\.port == 12345 && ip\.addr == 10\.0\.0\.2 && udp\.port == 9999$/,
    );

    await page.click("button:has-text('Copy as CSV')");
    const csv = log.find((m) => m.type === "copy").text.split("\n");
    assert.equal(
      csv[0],
      "Address A,Address B,Packets,Bytes,Packets A → B,Bytes A → B,Packets B → A,Bytes B → A,Rel Start,Duration",
    );
    assert.equal(csv.length, 5);
  });

  test("limit to the capture's display filter", async () => {
    const { page } = await openStats("conversations", "http");
    await waitRows(page, 1);
    assert.equal((await rows(page))[0][2], "11");
    await page.check("input[type=checkbox]");
    await page.waitForFunction(
      () => document.querySelector("table.stats tbody tr td:nth-child(3)")?.textContent === "2",
    );
    assert.match(await page.textContent(".status"), /matching http/);
  });

  test("protocol hierarchy keeps the tree and indents by depth", async () => {
    const { page } = await openStats("phs");
    await waitRows(page, 11);
    // tshark 4.6 adds a top-level "frame" row (everything one level deeper than
    // 4.2), so compare depths instead of expecting absolute ones.
    const indent = (proto) =>
      page.$eval(`table.stats tbody tr:has(td:text-is('${proto}')) td`, (td) =>
        parseFloat(getComputedStyle(td).paddingLeft),
      );
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
    // A resize redraws the chart (e.g. when the table below gets a scrollbar):
    // the hovered point and its tooltip stay.
    const drawn = await page.$(".chart svg");
    await page.setViewportSize({ width: 1000, height: 800 });
    await page.waitForFunction((old) => document.querySelector(".chart svg") !== old, drawn);
    assert.equal(
      await page.$eval(".chart .tooltip", (t) => t.classList.contains("hidden")),
      false,
      "the tooltip survives a redraw",
    );
    const shrunk = await page.$(".chart svg");
    await page.setViewportSize({ width: 1200, height: 800 });
    await page.waitForFunction((old) => document.querySelector(".chart svg") !== old, shrunk);
    const resized = await page.locator(".chart svg").boundingBox();
    await page.mouse.move(resized.x + resized.width / 2, resized.y + resized.height / 2);
    await page.focus(".chart");
    await page.keyboard.press("Home");
    await page.keyboard.press("ArrowRight");
    assert.match(await page.textContent(".chart .tooltip span"), /^0\.00\d+–0\.00\d+ s$/);
    await page.selectOption("select[aria-label='Metric']", "bytes");
    await page.mouse.move(resized.x + resized.width / 2 + 5, resized.y + resized.height / 2);
    await page.waitForFunction(() =>
      /bytes$/.test(document.querySelector(".chart .tooltip strong")?.textContent ?? ""),
    );
  });

  test("expert information: severity and go to packet", async () => {
    const { page, log } = await openStats("expert");
    await page.waitForSelector("table.stats tbody tr");
    assert.ok(await page.$(".sev.sev-Chat"));
    await page.click("table.stats tbody tr:has-text('Connection finish (FIN)')");
    await page.click("button:has-text('Go to Packet')");
    assert.deepEqual(
      log.find((m) => m.type === "goto"),
      { type: "goto", frame: 18 },
    );
    await page.click("button:has-text('Prepare as Filter')");
    assert.deepEqual(
      log.find((m) => m.type === "filter"),
      { type: "filter", expr: '_ws.expert.message == "Connection finish (FIN)"', apply: false },
    );
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
    assert.match(
      await page.textContent(".follow-legend"),
      /192\.168\.1\.10:50000 → 93\.184\.216\.34:80/,
    );
    assert.ok(
      (await page.textContent("pre.segment.dir0")).startsWith(
        "GET /index.html HTTP/1.1\nHost: example.com",
      ),
    );
    assert.ok(
      (await page.textContent("pre.segment.dir1")).startsWith(
        "HTTP/1.1 200 OK\nContent-Type: text/html",
      ),
    );

    await page.selectOption("select[aria-label='Direction']", "1");
    assert.equal(await page.locator("pre.segment.dir0").count(), 0);
    await page.selectOption("select[aria-label='Show data as']", "hex");
    assert.ok(
      (await page.textContent("pre.segment")).startsWith("00000000  48 54 54 50 2f 31 2e 31"),
    );

    await page.click("button:has-text('Save as…')");
    const saveText = log.find((m) => m.type === "save");
    assert.equal(saveText.dir, 1);
    assert.equal(saveText.format, "text");
    assert.ok(saveText.text.startsWith("00000000  48 54 54 50"));
    await page.selectOption("select[aria-label='Show data as']", "raw");
    await page.click("button:has-text('Save as…')");
    assert.deepEqual(log.filter((m) => m.type === "save").at(-1), {
      type: "save",
      dir: 1,
      format: "raw",
    });

    await page.click("button:has-text('Filter to Stream')");
    assert.deepEqual(
      log.find((m) => m.type === "filter"),
      { type: "filter", expr: "tcp.stream eq 0", apply: true },
    );

    // There is only one TCP stream in the capture: the next one is empty.
    await page.click("button[title='Next stream']");
    await page.waitForFunction(
      () => document.querySelector(".panel-title").textContent === "TCP stream 1",
    );
    assert.equal(await page.textContent(".status"), "No payload in this stream.");
    assert.equal(await page.locator("pre.segment").count(), 0);
  });

  /** Open coloring.js with a stand-in for ColoringPanel (src/panels/coloringPanel.ts). */
  async function openColoring(rules, defaults) {
    const { page, problems, post } = await newPage(browser);
    const log = [];
    await page.exposeFunction("__toHost", async (raw) => {
      const msg = JSON.parse(raw);
      log.push(msg);
      if (msg.type === "ready") {
        await post({ type: "init", rules, defaults, canValidate: true });
      } else if (msg.type === "validate") {
        const res = await client.request("validate_filter", { expr: msg.filter });
        await post({
          type: "validation",
          id: msg.id,
          filter: msg.filter,
          error: res.valid ? null : res.error,
        });
      }
    });
    await page.setContent(renderPanelHtml(origin, "coloring.js"), { waitUntil: "load" });
    pages.push(problems);
    return { page, log, post };
  }

  test("coloring rules editor: edit, check filters, reorder, add, remove and save", async () => {
    const dns = {
      name: "DNS",
      filter: "dns",
      foreground: "#12272e",
      background: "#c8e2ff",
      enabled: true,
    };
    const tcp = {
      name: "TCP",
      filter: "tcp",
      foreground: "#000000",
      background: "#e7e6ff",
      enabled: true,
    };
    const arp = {
      name: "ARP",
      filter: "arp",
      foreground: "#000000",
      background: "#faf0d7",
      enabled: false,
    };
    const { page, log, post } = await openColoring([dns, tcp, arp], [dns]);
    const rowsOf = () =>
      page.$$eval("table.rules tbody tr[data-id]", (trs) =>
        trs.map((tr) => ({
          on: /** @type {HTMLInputElement} */ (tr.querySelector("input[type=checkbox]")).checked,
          name: /** @type {HTMLInputElement} */ (tr.querySelector(".rule-name")).value,
          filter: /** @type {HTMLInputElement} */ (tr.querySelector(".rule-filter")).value,
          sample: /** @type {HTMLElement} */ (tr.querySelector(".rule-sample")).style
            .backgroundColor,
        })),
      );
    await page.waitForSelector("table.rules tbody tr[data-id]");
    assert.deepEqual(await rowsOf(), [
      { on: true, name: "DNS", filter: "dns", sample: "rgb(200, 226, 255)" },
      { on: true, name: "TCP", filter: "tcp", sample: "rgb(231, 230, 255)" },
      { on: false, name: "ARP", filter: "arp", sample: "rgb(250, 240, 215)" },
    ]);
    const save = "button:has-text('Save')";
    assert.equal(await page.isDisabled(save), true, "nothing to save yet");

    // A filter tshark rejects is marked (it can still be saved: tshark skips it).
    const second = "table.rules tbody tr[data-id] >> nth=1";
    await page.fill(`${second} >> .rule-filter`, "tcp.port ==");
    await page.waitForFunction(() =>
      /\S/.test(document.querySelectorAll("table.rules .rule-problem")[1]?.textContent ?? ""),
    );
    assert.equal(await page.getAttribute(`${second} >> .rule-filter`, "aria-invalid"), "true");
    assert.equal(await page.isDisabled(save), false);
    // An empty filter can't be saved.
    await page.fill(`${second} >> .rule-filter`, "");
    assert.match(await page.textContent(`${second} >> .rule-problem`), /Enter a display filter/);
    assert.equal(await page.isDisabled(save), true);
    await page.fill(`${second} >> .rule-filter`, "tcp.port == 80");
    await page.waitForFunction(
      () => document.querySelectorAll("table.rules .rule-problem")[1]?.textContent === "",
    );

    // Add a rule on top, give it a filter and a color; move it down; remove ARP.
    await page.click("button:has-text('Add Rule')");
    await page.keyboard.type("udp");
    await page.$eval("table.rules tbody tr[data-id] input[aria-label='Row color']", (el) => {
      const input = /** @type {HTMLInputElement} */ (el);
      input.value = "#ff0000";
      input.dispatchEvent(new window.Event("input", { bubbles: true }));
    });
    await page.focus("table.rules tbody tr[data-id] >> nth=0 >> .rule-filter");
    await page.keyboard.press("Alt+ArrowDown");
    assert.equal(
      await page.evaluate(() => /** @type {HTMLInputElement} */ (document.activeElement)?.value),
      "udp",
      "focus follows the moved rule",
    );
    await page.click("table.rules tbody tr[data-id] >> nth=3 >> button[aria-label='Remove rule']");
    await page.uncheck("table.rules tbody tr[data-id] >> nth=0 >> input[type=checkbox]");
    assert.deepEqual(await rowsOf(), [
      { on: false, name: "DNS", filter: "dns", sample: "rgb(200, 226, 255)" },
      { on: true, name: "", filter: "udp", sample: "rgb(255, 0, 0)" },
      { on: true, name: "TCP", filter: "tcp.port == 80", sample: "rgb(231, 230, 255)" },
    ]);
    assert.match(await page.textContent(".status"), /3 rules, 2 enabled · unsaved changes/);

    await page.click(save);
    const saved = log.find((m) => m.type === "save");
    assert.deepEqual(saved.rules, [
      { ...dns, enabled: false },
      { name: "", filter: "udp", foreground: "#000000", background: "#ff0000", enabled: true },
      { ...tcp, filter: "tcp.port == 80" },
    ]);
    // The host answers with what the setting now holds (empty names become the filter).
    const stored = [saved.rules[0], { ...saved.rules[1], name: "udp" }, saved.rules[2]];
    await post({ type: "rules", rules: stored }); // the settings change can come first
    await post({ type: "saved", rules: stored });
    await page.waitForFunction(
      () =>
        !/unsaved|changed in settings/.test(document.querySelector(".status")?.textContent ?? ""),
    );
    assert.equal(await page.isDisabled(save), true);
    assert.equal((await rowsOf())[1].name, "udp");

    // Edited elsewhere while there are unsaved edits: say so; Revert loads them.
    await page.fill("table.rules tbody tr[data-id] >> nth=2 >> .rule-name", "Web");
    await post({ type: "rules", rules: [dns] });
    await page.waitForFunction(() =>
      /changed in settings/.test(document.querySelector(".status")?.textContent ?? ""),
    );
    await page.click("button:has-text('Restore Defaults')");
    assert.deepEqual(
      (await rowsOf()).map((r) => r.name),
      ["DNS"],
    );
    await page.click("button:has-text('Open settings.json')");
    assert.equal(log.at(-1).type, "openSettings");
  });

  test("export objects: list, filter, sort, go to packet and save", async () => {
    const objects = await startBackend(deps);
    try {
      await objects.request(
        "open",
        { path: path.join(FIXTURES, "objects.pcap") },
        { timeoutMs: 0 },
      );
      const { page, problems, post } = await newPage(browser);
      const log = [];
      // A stand-in for ObjectsPanel (src/panels/objectsPanel.ts).
      await page.exposeFunction("__toHost", async (raw) => {
        const msg = JSON.parse(raw);
        log.push(msg);
        if (msg.type === "ready") {
          await post({ type: "init", title: "Export Objects · objects.pcap" });
        }
        if (msg.type === "ready" || msg.type === "list") {
          const onProgress = (p) => void post({ type: "progress", fraction: p.fraction ?? null });
          objects.request("export_objects", {}, { timeoutMs: 0, onProgress }).then(
            (res) => post({ type: "objects", objects: res.objects }),
            (err) => post({ type: "error", message: err.message, cancelled: err.code === -32800 }),
          );
        }
      });
      await page.setContent(renderPanelHtml(origin, "objects.js"), { waitUntil: "load" });
      pages.push(problems);
      await waitRows(page, 7);
      const all = await rows(page);
      assert.deepEqual(all[0], ["6", "HTTP", "example.com", "image/png", "776 B", "logo.png"]);
      assert.deepEqual(
        all.map((r) => r[5]),
        ["logo.png", "report", "upload", "dup.txt", "dup(1).txt", "config.bin", "Test report.eml"],
      );
      assert.match(await page.textContent(".status"), /^7 objects, /);
      assert.deepEqual(
        await page.$$eval("#objects-protocol option", (os) => os.map((o) => o.textContent)),
        ["All (7)", "HTTP (5)", "TFTP (1)", "IMF (1)"],
      );
      assert.ok(await page.isDisabled("#objects-save"), "nothing selected yet");

      await page.selectOption("#objects-protocol", "tftp");
      await waitRows(page, 1);
      assert.equal(await page.textContent("#objects-save-all"), "Save 1 Shown…");
      await page.selectOption("#objects-protocol", "");
      await page.fill("#objects-text", "DUP");
      await waitRows(page, 2);
      await page.fill("#objects-text", "");
      await waitRows(page, 7);

      await page.click("th:has-text('Size')"); // numeric: largest first
      assert.deepEqual((await rows(page)).map((r) => r[5]).slice(0, 3), [
        "report",
        "logo.png",
        "config.bin",
      ]);
      await page.click("th:has-text('Size')");
      assert.equal((await rows(page))[6][5], "report");

      await page.click("table.stats tbody tr:has-text('config.bin')");
      assert.ok(!(await page.isDisabled("#objects-save")));
      await page.click("#objects-save");
      assert.deepEqual(log.at(-1), { type: "save", id: 5 });
      await page.click("#objects-goto");
      assert.deepEqual(log.at(-1), { type: "goto", frame: 27 });
      await page.focus("table.stats");
      await page.keyboard.press("ArrowUp"); // (sorted by size, ascending: the mail comes before)
      await page.keyboard.press("Enter");
      assert.deepEqual(log.at(-1), { type: "goto", frame: 53 });
      await page.dblclick("table.stats tbody tr:has-text('logo.png')");
      assert.deepEqual(log.at(-1), { type: "goto", frame: 6 });
      await page.click("#objects-save-all");
      assert.deepEqual(log.at(-1).type, "saveAll");
      assert.deepEqual([...log.at(-1).ids].sort(), [0, 1, 2, 3, 4, 5, 6]);

      await page.click("button:has-text('Refresh')");
      await page.waitForFunction(() =>
        /^7 objects/.test(document.querySelector(".status")?.textContent ?? ""),
      );
    } finally {
      await objects.dispose();
    }
  });

  /** Open a panel script with a stand-in host that forwards `method` to the backend. */
  async function openGraphPanel(script, onMessage) {
    const { page, problems, post } = await newPage(browser);
    const log = [];
    await page.exposeFunction("__toHost", async (raw) => {
      const msg = JSON.parse(raw);
      log.push(msg);
      await onMessage(msg, post);
    });
    await page.setContent(renderPanelHtml(origin, script), { waitUntil: "load" });
    pages.push(problems);
    return { page, log, post };
  }

  test("flow graph: endpoints, arrows, go to packet, follows the filter", async () => {
    let filter = "";
    const { page, log, post } = await openGraphPanel("flowgraph.js", async (msg, reply) => {
      // A stand-in for FlowGraphPanel (src/panels/flowGraphPanel.ts).
      if (msg.type === "ready") {
        await reply({ type: "init", title: "Flow Graph · mixed.pcapng", filter });
      } else if (msg.type === "query") {
        const params = { offset: msg.offset, limit: msg.limit };
        client.request("flow_graph", params, { timeoutMs: 0 }).then(
          (pageData) => reply({ type: "page", id: msg.id, offset: msg.offset, page: pageData }),
          (err) => reply({ type: "error", id: msg.id, message: err.message }),
        );
      }
    });
    await page.waitForFunction(() => document.querySelectorAll(".flow-row").length === 26);
    const nodes = await page.$$eval(".flow-node", (els) => els.map((e) => e.textContent));
    assert.deepEqual(nodes.slice(0, 3), ["02:00:00:00:00:01", "Broadcast", "192.168.1.10"]);
    assert.equal(nodes.length, 8);
    assert.match(
      await page.textContent(".status, .toolbar span"),
      /26 packets between 8 endpoints/,
    );
    const label = await page.textContent(".flow-row:nth-of-type(1) .flow-label");
    assert.match(label, /^ARP: Who has 192\.168\.1\.1\?/);
    await page.screenshot({
      path: process.env.PCAP_SCREENSHOTS ? `${process.env.PCAP_SCREENSHOTS}/flow.png` : undefined,
    });

    await page.click(".flow-row:nth-of-type(4)");
    assert.deepEqual(log.at(-1), { type: "goto", frame: 4 });
    await page.focus(".flow-scroll");
    await page.keyboard.press("ArrowDown");
    await page.keyboard.press("Enter");
    assert.deepEqual(log.at(-1), { type: "goto", frame: 5 });

    // The capture's filter changes: the graph follows it.
    await client.request("set_filter", { expr: "dns" });
    filter = "dns";
    await post({ type: "reset", filter });
    await page.waitForFunction(() => document.querySelectorAll(".flow-row").length === 6);
    assert.equal((await page.$$(".flow-node")).length, 2);
    assert.match(await page.textContent(".toolbar span"), /6 packets matching dns between 2/);
    await client.request("set_filter", { expr: "" });
  });

  test("TCP stream graph: the four graphs, direction, stepping, go to packet", async () => {
    const { page, log } = await openGraphPanel("tcpgraph.js", async (msg, reply) => {
      // A stand-in for TcpGraphPanel (src/panels/tcpGraphPanel.ts).
      if (msg.type === "ready") {
        await reply({ type: "init", frame: 14 });
      } else if (msg.type === "query") {
        const params = msg.stream !== undefined ? { stream: msg.stream } : { frame: msg.frame };
        client.request("tcp_graph", params, { timeoutMs: 0 }).then(
          (result) => reply({ type: "stream", id: msg.id, result }),
          (err) => reply({ type: "error", id: msg.id, message: err.message }),
        );
      }
    });
    // mixed.pcapng: an HTTP exchange; the server sends the most data, so it's shown first.
    await page.waitForFunction(() =>
      /^TCP stream 0: 93\.184\.216\.34:80 → 192\.168\.1\.10:50000$/.test(
        document.querySelector(".panel-title").textContent,
      ),
    );
    assert.ok(
      (await page.$$(".chart line.seg")).length >= 1,
      "Stevens: one segment per data packet",
    );
    assert.match(await page.textContent(".status"), /data segments/);
    await page.screenshot({
      path: process.env.PCAP_SCREENSHOTS
        ? `${process.env.PCAP_SCREENSHOTS}/tcp-stevens.png`
        : undefined,
    });

    for (const [kind, selector] of [
      ["throughput", ".chart path.series-line"],
      ["rtt", ".chart circle.dot"],
      ["window", ".chart path.series-line"],
    ]) {
      await page.selectOption("select", kind);
      await page.waitForSelector(selector, { state: "attached" }); // (a flat line has no height)
    }
    await page.screenshot({
      path: process.env.PCAP_SCREENSHOTS
        ? `${process.env.PCAP_SCREENSHOTS}/tcp-window.png`
        : undefined,
    });

    await page.selectOption("select", "stevens");
    await page.click("#tcp-direction");
    assert.match(await page.textContent(".panel-title"), /192\.168\.1\.10:50000 → 93\.184/);

    const box = await page.locator(".chart svg").boundingBox();
    await page.mouse.move(box.x + box.width / 2, box.y + box.height / 2);
    await page.waitForFunction(() =>
      /^Packet \d+/.test(document.querySelector(".chart .tooltip").textContent),
    );
    await page.mouse.click(box.x + box.width / 2, box.y + box.height / 2);
    for (let i = 0; i < 50 && log.at(-1).type !== "goto"; i++) {
      await page.waitForTimeout(20); // (the message reaches the stand-in host asynchronously)
    }
    assert.equal(log.at(-1).type, "goto");

    await page.click("button[title='Next stream']");
    await page.waitForFunction(() =>
      /^TCP stream 1/.test(document.querySelector(".panel-title").textContent),
    );
    assert.match(await page.textContent(".status"), /No packets in this stream/);
  });

  test("no script errors or CSP violations in any panel", () => {
    for (const p of pages) {
      assert.deepEqual(p.errors, []);
      assert.deepEqual(p.csp, []);
    }
  });
});
