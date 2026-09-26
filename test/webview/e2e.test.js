/**
 * End-to-end test of the real webview (index.html + lib.js + main.js) in
 * headless Chromium, with a minimal stand-in for the extension host that
 * forwards RPCs to the real Python backend (and therefore real tshark).
 *
 * Skips when tshark, the compiled BackendClient or a Chromium build are missing.
 * Set PCAP_VIEWER_SCREENSHOT=<path> to save a screenshot of the final state.
 */
const assert = require("node:assert/strict");
const path = require("node:path");
const { ROOT, HAVE_TSHARK, loadDeps, serveWebview, renderEditorHtml, startBackend } = require("./harness");

const deps = loadDeps();
const maybe = deps && HAVE_TSHARK ? suite : suite.skip;

maybe("webview end-to-end (Chromium + real backend)", function () {
  this.timeout(60_000);
  let server, browser, page, client;
  // What the stand-in host received / keeps (mirrors pcapEditor.ts behaviour).
  const hostLog = [];
  let savedFilters = [{ name: "Web", filter: "http" }];
  const cspViolations = [];
  const pageErrors = [];

  const post = (msg) => page.evaluate((m) => window.postMessage(m, "*"), msg);

  suiteSetup(async function () {
    server = await serveWebview();
    const origin = `http://127.0.0.1:${server.address().port}`;
    client = await startBackend(deps);

    try {
      browser = await deps.chromium.launch();
    } catch (err) {
      console.warn(`skipping webview e2e: no Chromium available (${err.message.split("\n")[0]})`);
      this.skip();
    }
    page = await browser.newPage({ viewport: { width: 1200, height: 800 } });
    page.on("pageerror", (err) => pageErrors.push(err.message));
    page.on("console", (m) => {
      if (/Content Security Policy/i.test(m.text())) {
        cspViolations.push(m.text());
      }
    });

    // Minimal extension-host emulation (see src/pcapEditor.ts).
    await page.exposeFunction("__toHost", async (raw) => {
      const msg = JSON.parse(raw);
      if (msg.type === "ready") {
        const info = await client.request(
          "open",
          { path: path.join(ROOT, "test", "fixtures", "http.pcap"), columns: ["tcp.stream"] },
          { timeoutMs: 0, onProgress: (p) => void post({ type: "progress", ...p }) },
        );
        await post({
          type: "init",
          info,
          columns: [{ field: "tcp.stream", title: "Stream" }],
          filter: "",
          history: ["tcp.port == 80"],
          savedFilters,
          elapsedMs: 12,
        });
      } else if (msg.type === "saveFilter") {
        // The real host asks for a name; the stand-in uses "Saved <n>".
        hostLog.push(msg);
        savedFilters = [...savedFilters, { name: `Saved ${savedFilters.length}`, filter: msg.expr }];
        await post({ type: "savedFilters", savedFilters });
      } else if (["manageSavedFilters", "filterApplied", "selection", "follow", "decodeAs"].includes(msg.type)) {
        hostLog.push(msg);
      } else if (msg.type === "rpc") {
        const pending = client.send(msg.method, msg.params, { timeoutMs: 0 });
        pending.promise.then(
          (result) => post({ type: "rpcResult", id: msg.id, result }),
          (err) => post({ type: "rpcError", id: msg.id, error: { code: err.code, message: err.message } }),
        );
      }
    });
    await page.setContent(renderEditorHtml(origin), { waitUntil: "load" });
  });

  suiteTeardown(async () => {
    if (process.env.PCAP_VIEWER_SCREENSHOT && page) {
      await page.screenshot({ path: process.env.PCAP_VIEWER_SCREENSHOT });
    }
    await browser?.close();
    await client?.dispose();
    server?.close();
  });

  const rowNumbers = () => page.$$eval("#list-rows .list-row:not(.loading)", (rows) => rows.map((r) => Number(r.children[0].textContent)));

  test("renders the packet list with base and custom columns", async () => {
    await page.waitForSelector("#overlay.hidden", { state: "attached" });
    await page.waitForFunction(() => document.querySelectorAll("#list-rows .list-row:not(.loading)").length === 11);
    assert.deepEqual(await rowNumbers(), [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11]);
    const headers = await page.$$eval("#list-header > div", (cells) => cells.map((c) => c.firstChild.textContent));
    assert.deepEqual(headers, ["No.", "Time", "Source", "Destination", "Protocol", "Length", "Info", "Stream"]);
    const fourth = await page.$$eval("#list-rows .list-row", (rows) => [...rows[3].children].map((c) => c.textContent));
    assert.equal(fourth[1], "0.003000");
    assert.equal(fourth[4], "HTTP");
    assert.equal(fourth[7], "0");
    assert.match(await page.textContent("#status-left"), /Packets: 11/);
  });

  test("invalid filter is flagged and not applied", async () => {
    await page.fill("#filter-input", "tcp.port ==");
    await page.waitForSelector("#filter-input.invalid");
    await page.press("#filter-input", "Enter");
    await page.waitForSelector("#filter-error:not(.hidden)");
    assert.equal((await rowNumbers()).length, 11);
  });

  test("valid filter narrows the list", async () => {
    await page.fill("#filter-input", "http");
    await page.waitForSelector("#filter-input.valid");
    await page.press("#filter-input", "Enter");
    await page.waitForFunction(() => document.querySelectorAll("#list-rows .list-row:not(.loading)").length === 2);
    assert.deepEqual(await rowNumbers(), [4, 7]);
    assert.match(await page.textContent("#status-left"), /Displayed: 2/);
  });

  test("selecting a packet shows the tree and bytes, with two-way highlighting", async () => {
    await page.click("#list-rows .list-row >> nth=1"); // frame 7 (reassembled HTTP)
    await page.waitForSelector("#detail-tree .node-row");
    const protos = await page.$$eval("#detail-tree > div > .node-row .label", (ls) => ls.map((l) => l.textContent));
    assert.ok(protos[0].startsWith("Frame 7"));
    assert.ok(protos.some((p) => p.startsWith("Hypertext Transfer Protocol")));
    // Two byte sources: frame and reassembled TCP.
    assert.equal(await page.locator("#bytes-tabs button").count(), 2);

    // Tree -> bytes: expand IPv4 and select the source address.
    await page.click("#detail-tree .node-row:has-text('Internet Protocol Version 4') .twisty");
    await page.click("#detail-tree .node-row:has-text('Source Address')");
    const marked = await page.$$eval("#bytes-view .b.hl", (bs) => bs.map((b) => b.textContent).join(" "));
    assert.equal(marked, "5d b8 d8 22"); // 93.184.216.34

    // Bytes -> tree: clicking an HTTP byte in the reassembled source selects an HTTP field.
    await page.click("#bytes-tabs button >> nth=1");
    await page.click("#bytes-view .b[data-i='2']");
    const selected = await page.textContent("#detail-tree .node-row.selected .label");
    assert.match(selected, /HTTP\/1\.1 200 OK|Response Version/);
  });

  test("apply-as-filter from the tree context menu", async () => {
    await page.click("#detail-tree .node-row:has-text('Source Address')", { button: "right" });
    await page.click("#context-menu .item:has-text('Apply as Filter')");
    await page.waitForFunction(() => document.querySelector("#filter-input").value === "ip.src == 93.184.216.34");
    await page.waitForFunction(() => /Displayed: 5/.test(document.querySelector("#status-left").textContent));
  });

  test("sorting by a column header", async () => {
    await page.click("#filter-clear");
    await page.waitForFunction(() => document.querySelectorAll("#list-rows .list-row:not(.loading)").length === 11);
    await page.click("#list-header > div:has-text('Length')");
    await page.click("#list-header > div:has-text('Length')"); // descending
    await page.waitForFunction(() => document.querySelector("#list-rows .list-row").children[5].textContent === "345");
    const lengths = await page.$$eval("#list-rows .list-row", (rows) => rows.slice(0, 3).map((r) => r.children[5].textContent));
    assert.deepEqual(lengths, ["345", "254", "144"]);
  });

  test("keyboard navigation moves the selection", async () => {
    await page.focus("#list-viewport");
    await page.keyboard.press("Home");
    await page.keyboard.press("ArrowDown");
    await page.waitForFunction(() => document.querySelector("#list-rows .list-row.selected")?.dataset.index === "1");
  });

  const suggestions = () =>
    page.$$eval("#suggest .suggest-item", (rows) =>
      rows.map((r) => ({
        label: r.querySelector(".suggest-label").textContent,
        detail: r.querySelector(".suggest-detail")?.textContent ?? "",
        desc: r.querySelector(".suggest-desc")?.textContent ?? "",
      })),
    );

  test("autocomplete suggests fields with type and description", async () => {
    await page.fill("#filter-input", "");
    await page.focus("#filter-input");
    await page.keyboard.type("ip.sr");
    await page.waitForSelector("#suggest:not(.hidden) .suggest-item");
    const items = await suggestions();
    const src = items.find((i) => i.label === "ip.src");
    assert.ok(src, JSON.stringify(items));
    assert.equal(src.detail, "IPv4 address");
    assert.match(src.desc, /Source Address/);
    assert.ok(items.every((i) => i.label.startsWith("ip.sr")));
    assert.equal(await page.getAttribute("#filter-input", "aria-expanded"), "true");
    // Tab accepts the first (exact-prefix) suggestion.
    await page.keyboard.press("Tab");
    assert.equal(await page.inputValue("#filter-input"), "ip.src");
    await page.waitForSelector("#suggest.hidden", { state: "attached" });
  });

  test("operators are offered after a field, then the filter applies", async () => {
    await page.keyboard.type(" ");
    await page.waitForSelector("#suggest:not(.hidden) .suggest-item");
    const ops = (await suggestions()).map((i) => i.label);
    assert.deepEqual(ops.slice(0, 3), ["==", "!=", ">"]);
    assert.ok(ops.includes("contains"));
    await page.keyboard.press("ArrowDown"); // Enter accepts once a suggestion is picked
    await page.keyboard.press("Enter");
    assert.equal(await page.inputValue("#filter-input"), "ip.src == ");
    await page.keyboard.type("93.184.216.34");
    await page.waitForSelector("#suggest.hidden", { state: "attached" }); // no suggestions for values
    await page.keyboard.press("Enter");
    await page.waitForFunction(() => /Displayed: 5/.test(document.querySelector("#status-left").textContent));
    assert.ok(hostLog.some((m) => m.type === "filterApplied" && m.expr === "ip.src == 93.184.216.34"));
  });

  test("arrow keys, Tab and Escape drive the dropdown", async () => {
    await page.fill("#filter-input", "");
    await page.keyboard.type("tcp.fl");
    await page.waitForSelector("#suggest:not(.hidden) .suggest-item");
    await page.keyboard.press("ArrowDown");
    await page.keyboard.press("ArrowDown");
    const second = (await suggestions())[1].label;
    await page.keyboard.press("Tab");
    assert.equal(await page.inputValue("#filter-input"), second);
    await page.keyboard.type(" && udp.");
    await page.waitForSelector("#suggest:not(.hidden) .suggest-item");
    await page.keyboard.press("Escape");
    await page.waitForSelector("#suggest.hidden", { state: "attached" });
    assert.equal(await page.inputValue("#filter-input"), `${second} && udp.`); // first Escape only closes
  });

  test("saved and recent filters menu: apply, save and manage", async () => {
    // Empty input: the ★ menu lists saved and recent filters.
    await page.fill("#filter-input", "");
    await page.click("#filter-saved");
    let items = await suggestions();
    assert.deepEqual(items.map((i) => i.label), ["Web", "tcp.port == 80", "Manage saved filters…"]);
    await page.click("#suggest .suggest-item:has-text('Web')");
    await page.waitForFunction(() => /Displayed: 2/.test(document.querySelector("#status-left").textContent));
    assert.equal(await page.inputValue("#filter-input"), "http");

    // Save the current filter; the host answers with the updated list.
    await page.fill("#filter-input", "tcp.len == 0");
    await page.click("#filter-saved");
    await page.click("#suggest .suggest-item:has-text('Save this filter')");
    await page.fill("#filter-input", "");
    await page.focus("#filter-input");
    await page.keyboard.press("ArrowDown"); // also opens the menu on an empty input
    // The host answers asynchronously; the open menu refreshes when it does.
    await page.waitForSelector("#suggest .suggest-item:has-text('Saved 1')");
    assert.deepEqual(hostLog.filter((m) => m.type === "saveFilter").pop(), { type: "saveFilter", expr: "tcp.len == 0" });
    items = await suggestions();
    assert.ok(items.some((i) => i.label === "Saved 1" && i.desc === "tcp.len == 0"), JSON.stringify(items));
    await page.click("#suggest .suggest-item:has-text('Manage saved filters')");
    assert.equal(hostLog.at(-1).type, "manageSavedFilters");
  });

  test("an unknown custom column is dropped instead of breaking the list", async () => {
    await post({
      type: "columns",
      columns: [
        { field: "tcp.stream", title: "Stream" },
        { field: "no.such.field", title: "Typo" },
      ],
    });
    await page.waitForFunction(() => /no\.such\.field/.test(document.querySelector("#filter-error").textContent));
    await page.waitForFunction(() => document.querySelectorAll("#list-rows .list-row:not(.loading)").length > 0);
    const headers = await page.$$eval("#list-header > div", (cells) => cells.map((c) => c.firstChild.textContent));
    assert.deepEqual(headers.slice(-2), ["Info", "Stream"]);
  });

  test("the selection is reported and the packet list offers Follow Stream", async () => {
    await page.click("#filter-clear");
    await page.waitForFunction(() => document.querySelectorAll("#list-rows .list-row:not(.loading)").length === 11);
    await page.click("#list-header > div:has-text('No.')"); // back to frame order
    await page.waitForFunction(() => {
      const row = document.querySelectorAll("#list-rows .list-row")[3];
      return row && !row.classList.contains("loading") && row.children[0].textContent === "4";
    });
    await page.click("#list-rows .list-row >> nth=3", { button: "right" }); // frame 4 (HTTP GET)
    assert.ok(hostLog.some((m) => m.type === "selection" && m.frame === 4));
    const items = await page.$$eval("#context-menu .item", (els) => els.map((e) => [e.textContent, !e.classList.contains("disabled")]));
    assert.deepEqual(items.slice(0, 4), [
      ["Follow TCP Stream", true],
      ["Follow UDP Stream", true],
      ["Follow TLS Stream", false],
      ["Follow HTTP Stream", true],
    ]);
    await page.click("#context-menu .item:has-text('Follow HTTP Stream')");
    assert.deepEqual(hostLog.at(-1), { type: "follow", proto: "http", frame: 4 });
    await page.click("#list-rows .list-row >> nth=3", { button: "right" });
    await page.click("#context-menu .item:has-text('Decode As')");
    assert.deepEqual(hostLog.at(-1), { type: "decodeAs", frame: 4 });
  });

  test("no script errors or CSP violations", () => {
    assert.deepEqual(pageErrors, []);
    assert.deepEqual(cspViolations, []);
  });
});
