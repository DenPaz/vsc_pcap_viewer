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
  // Stubbed "✨ Ask AI" answer (the real host validates suggestions with tshark first); null = never answer.
  /** @type {{suggestions: {filter: string, explanation: string}[], message?: string} | null} */
  let aiReply = null;
  // The stand-in host's pcapViewer.columns (Apply as Column / Remove update it and send it back).
  let customCols = [{ field: "tcp.stream", title: "Stream" }];
  let layout = { order: [], hidden: [] };
  const cspViolations = [];
  const pageErrors = [];

  const post = (msg) => page.evaluate((m) => window.postMessage(m, "*"), msg);
  /** Wait until the stand-in host has received a matching message. */
  async function waitForHost(pred, timeoutMs = 5000) {
    const start = Date.now();
    while (!hostLog.some(pred)) {
      if (Date.now() - start > timeoutMs) {
        throw new Error("the host never received the expected message");
      }
      await new Promise((r) => setTimeout(r, 20));
    }
  }

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
          columns: customCols,
          layout,
          timeFormat: "relative",
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
      } else if (msg.type === "aiSuggest") {
        hostLog.push(msg);
        if (aiReply) {
          await post({ type: "aiSuggestions", id: msg.id, ...aiReply });
        }
      } else if (msg.type === "aiCancel") {
        hostLog.push(msg);
      } else if (msg.type === "applyColumn") {
        hostLog.push(msg);
        if (!customCols.some((c) => c.field === msg.field)) {
          customCols = [...customCols, { field: msg.field, title: msg.title }];
        }
        await post({ type: "columns", columns: customCols, layout });
      } else if (msg.type === "removeColumn") {
        hostLog.push(msg);
        customCols = customCols.filter((c) => c.field !== msg.field);
        await post({ type: "columns", columns: customCols, layout });
      } else if (msg.type === "columnLayout") {
        hostLog.push(msg);
        layout = msg.layout;
      } else if (["marks", "pickTimeFormat", "renameColumn"].includes(msg.type)) {
        hostLog.push(msg);
      } else if (["manageSavedFilters", "filterApplied", "selection", "follow", "decodeAs", "colorize", "exportBytes"].includes(msg.type)) {
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
    // The clicked cell's Apply as Filter entries come first, then Follow.
    assert.deepEqual(items.slice(0, 2).map((i) => i[0]), ["Apply as Filter", "Prepare as Filter"]);
    assert.deepEqual(items.slice(5, 9), [
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

  test("coloring rules color the rows; Colorize and Export Bytes reach the host", async () => {
    // Frame 4 is still selected from the previous test.
    const rules = [
      { name: "HTTP", filter: "http", foreground: "#12272e", background: "#e4ffc7" },
      { name: "TCP", filter: "tcp", foreground: "#000000", background: "#e7e6ff" },
    ];
    const res = await client.request("set_coloring", { rules: rules.map(({ filter, foreground, background }) => ({ filter, foreground, background })) }, { timeoutMs: 0 });
    await post({ type: "coloring", coloringId: res.coloringId, rules: rules.map(({ name, foreground, background }) => ({ name, foreground, background })) });
    await page.waitForFunction(() => document.querySelector("#list-rows .list-row")?.classList.contains("colored"));
    const rows = await page.$$eval("#list-rows .list-row", (els) =>
      els.map((r) => ({ frame: r.children[0].textContent, selected: r.classList.contains("selected"), bg: r.style.backgroundColor })),
    );
    assert.equal(rows[0].bg, "rgb(231, 230, 255)"); // TCP handshake: rule 2
    assert.equal(rows[6].bg, "rgb(228, 255, 199)"); // frame 7, HTTP response: rule 1
    assert.deepEqual(rows[3], { frame: "4", selected: true, bg: "" }); // selection colors win

    await page.click("#detail-tree .node-row:has-text('Source Address')", { button: "right" });
    await page.click("#context-menu .item:has-text('Colorize with Filter')");
    assert.deepEqual(hostLog.at(-1), { type: "colorize", filter: "ip.src == 192.168.1.10" });
    await page.click("#list-rows .list-row >> nth=3", { button: "right" });
    await page.click("#context-menu .item:has-text('Export Packet Bytes')");
    assert.deepEqual(hostLog.at(-1), { type: "exportBytes", frame: 4 });

    await post({ type: "coloring", coloringId: 0, rules: [] }); // coloring turned off
    await page.waitForFunction(() => !document.querySelector("#list-rows .list-row.colored"));
  });

  const statusText = () => page.textContent("#status-left");

  test("✨ Ask AI: describe the packets, pick a suggestion, Enter applies it", async () => {
    await page.click("#filter-clear");
    await page.waitForFunction(() => !/Displayed/.test(document.querySelector("#status-left").textContent));
    assert.ok(await page.$eval("#filter-ai", (b) => b.classList.contains("hidden")), "hidden until the host says a model is available");
    await post({ type: "aiAvailable", available: true });
    await page.waitForSelector("#filter-ai:not(.hidden)");

    await page.fill("#filter-input", "tcp"); // typed, not applied (its completions close in ask mode)
    aiReply = {
      suggestions: [
        { filter: "tcp.flags.syn == 1", explanation: "Connection attempts: packets with the SYN flag set" },
        { filter: "tcp.flags.reset == 1", explanation: "Connections that were reset" },
      ],
    };
    await page.click("#filter-ai");
    assert.equal(await page.inputValue("#filter-input"), "");
    assert.match(await page.getAttribute("#filter-input", "placeholder"), /Describe the packets/);
    await page.type("#filter-input", "tcp connection attempts");
    await new Promise((r) => setTimeout(r, 150));
    assert.ok(await page.$eval("#suggest", (s) => s.classList.contains("hidden")), "no field completions while describing");
    await page.press("#filter-input", "Enter");
    await page.waitForSelector("#suggest .suggest-item.kind-ai");
    assert.equal(hostLog.filter((m) => m.type === "aiSuggest").at(-1).request, "tcp connection attempts");
    const items = await page.$$eval("#suggest .suggest-item", (els) => els.map((e) => [e.querySelector(".suggest-label").textContent, e.querySelector(".suggest-desc").textContent]));
    assert.deepEqual(items, [
      ["tcp.flags.syn == 1", "Connection attempts: packets with the SYN flag set"],
      ["tcp.flags.reset == 1", "Connections that were reset"],
    ]);
    assert.equal(await page.inputValue("#filter-input"), "tcp", "the filter text is back while choosing");

    await page.click("#suggest .suggest-item >> nth=0");
    assert.equal(await page.inputValue("#filter-input"), "tcp.flags.syn == 1");
    assert.doesNotMatch(await statusText(), /Displayed/, "picking a suggestion doesn't apply it");
    await page.press("#filter-input", "Enter");
    await page.waitForFunction(() => /Displayed: 2/.test(document.querySelector("#status-left").textContent)); // SYN and SYN/ACK
  });

  test("✨ Ask AI: Esc cancels, no suggestions show a message, the action hides when unavailable", async () => {
    aiReply = null; // the host doesn't answer: the request stays in flight
    await page.click("#filter-ai");
    await page.type("#filter-input", "something slow");
    await page.press("#filter-input", "Enter");
    await page.waitForFunction(() => /Asking the language model/.test(document.querySelector("#filter-error").textContent));
    await page.press("#filter-input", "Escape");
    const asked = hostLog.filter((m) => m.type === "aiSuggest").at(-1);
    await waitForHost((m) => m.type === "aiCancel" && m.id === asked.id); // host messages arrive asynchronously
    assert.equal(await page.inputValue("#filter-input"), "tcp.flags.syn == 1", "Esc restores the filter");
    assert.ok(await page.$eval("#filter-error", (e) => e.classList.contains("hidden")));

    aiReply = { suggestions: [], message: "The language model didn't come up with a valid display filter." };
    await page.click("#filter-ai");
    await page.type("#filter-input", "gibberish");
    await page.press("#filter-input", "Enter");
    await page.waitForFunction(() => /didn't come up with a valid display filter/.test(document.querySelector("#filter-error").textContent));
    assert.equal(await page.inputValue("#filter-input"), "tcp.flags.syn == 1");

    await post({ type: "aiAvailable", available: false });
    await page.waitForSelector("#filter-ai.hidden", { state: "attached" });
    // Autocomplete works as before.
    await page.fill("#filter-input", "");
    await page.type("#filter-input", "tcp.fla");
    await page.waitForSelector("#suggest .suggest-item.kind-field");
  });

  // ---------------------------------------------------------------- navigation & customisation

  const status = () => page.textContent("#status-left");
  const waitSelected = (n) => page.waitForFunction((f) => new RegExp(`Selected: ${f}(\\D|$)`).test(document.querySelector("#status-left").textContent), n);
  const rowEl = (frame) => page.locator("#list-rows .list-row").nth(frame - 1); // unfiltered, unsorted view
  const command = (name) => post({ type: "command", command: name });
  const headerIds = () => page.$$eval("#list-header > div", (cells) => cells.map((c) => c.dataset.id));

  async function cleanView() {
    await post({ type: "aiAvailable", available: false });
    await page.click("#filter-clear");
    await page.waitForFunction(() => !/Displayed/.test(document.querySelector("#status-left").textContent));
    await page.waitForFunction(() => document.querySelectorAll("#list-rows .list-row:not(.loading)").length === 11);
    const sorted = await page.$("#list-header .sort-indicator");
    if (sorted) {
      await page.click("#list-header > div:has(.sort-indicator)"); // cycle the sort off
      await page.click("#list-header > div:has(.sort-indicator)");
    }
  }

  test("Find Packet: Ctrl+F, string / hex / filter, F3, errors and Esc", async () => {
    await cleanView();
    await rowEl(1).click();
    await waitSelected(1);
    await page.keyboard.press("Control+f");
    await page.waitForSelector("#find-bar:not(.hidden)");
    assert.equal(await page.evaluate(() => document.activeElement.id), "find-input");

    await page.selectOption("#find-mode", "string");
    assert.ok(await page.isVisible("#find-case-label"));
    await page.fill("#find-input", "INDEX.HTML");
    await page.press("#find-input", "Enter");
    await waitSelected(4);
    assert.equal(await page.textContent("#find-status"), "Packet 4");
    await page.press("#find-input", "Enter"); // the only match: wraps to itself
    await page.waitForFunction(() => /wrapped/.test(document.querySelector("#find-status").textContent));

    await page.selectOption("#find-mode", "hex");
    await page.fill("#find-input", "xyz");
    assert.equal(await page.textContent("#find-status"), "Not hex bytes");
    assert.ok(await page.$eval("#find-input", (i) => i.classList.contains("invalid")));
    await page.fill("#find-input", "47 45 54"); // "GET"
    await page.press("#find-input", "Enter");
    await page.waitForFunction(() => /Packet 4/.test(document.querySelector("#find-status").textContent));

    await page.selectOption("#find-mode", "filter");
    await page.fill("#find-input", "tcp.flags.fin == 1");
    await page.press("#find-input", "Enter");
    await waitSelected(9);
    await page.keyboard.press("F3");
    await waitSelected(10);
    await page.keyboard.press("Shift+F3");
    await waitSelected(9);

    await page.fill("#find-input", "tcp.port ==");
    await page.press("#find-input", "Enter");
    await page.waitForFunction(() => document.querySelector("#find-status").classList.contains("error"));
    await page.selectOption("#find-mode", "string");
    await page.fill("#find-input", "no such text anywhere");
    await page.press("#find-input", "Enter");
    await page.waitForFunction(() => document.querySelector("#find-status").textContent === "Not found");

    await page.press("#find-input", "Escape");
    assert.ok(await page.$eval("#find-bar", (b) => b.classList.contains("hidden")));
  });

  test("frame links jump to the referenced packet; Alt+Left / Alt+Right walk the history", async () => {
    await cleanView();
    await rowEl(7).click(); // HTTP response: "[Request in frame: 4]"
    await waitSelected(7);
    const http = page.locator("#detail-tree .node-row:has-text('Hypertext Transfer Protocol')").first();
    if ((await http.getAttribute("aria-expanded")) !== "true") {
      await http.locator(".twisty").click();
    }
    const link = page.locator("#detail-tree .node-row.frame-link:has-text('Request in frame')");
    await link.waitFor();
    assert.match(await link.getAttribute("title"), /Go to packet 4/);
    await link.locator(".label").click();
    await waitSelected(4);
    await command("goBack"); // Alt+Left (a keybinding in VS Code)
    await waitSelected(7);
    await command("goForward");
    await waitSelected(4);

    // A link to a packet the filter hides offers to clear the filter.
    await page.fill("#filter-input", "http.response");
    await page.press("#filter-input", "Enter");
    await page.waitForFunction(() => /Displayed: 1/.test(document.querySelector("#status-left").textContent));
    await page.locator("#list-rows .list-row").first().click();
    await waitSelected(7);
    await page.locator("#detail-tree .node-row.frame-link:has-text('Request in frame') .label").click();
    await page.waitForFunction(() => /Packet 4 is not displayed/.test(document.querySelector("#filter-error").textContent));
    await page.click("#filter-error button:has-text('Clear filter and go')");
    await waitSelected(4);
    assert.doesNotMatch(await status(), /Displayed/);
  });

  test("marks: toggle, next/previous marked, the mark style wins over coloring, unmark all", async () => {
    await cleanView();
    const rules = [{ filter: "tcp", foreground: "#000000", background: "#e7e6ff" }];
    const res = await client.request("set_coloring", { rules }, { timeoutMs: 0 });
    await post({ type: "coloring", coloringId: res.coloringId, rules: [{ name: "TCP", foreground: "#000000", background: "#e7e6ff" }] });
    await page.waitForFunction(() => document.querySelector("#list-rows .list-row")?.classList.contains("colored"));

    for (const frame of [2, 9]) {
      await rowEl(frame).click();
      await waitSelected(frame);
      await command("toggleMark"); // Ctrl+M
      await page.waitForFunction((f) => document.querySelectorAll("#list-rows .list-row")[f - 1]?.classList.contains("marked"), frame);
    }
    await page.waitForFunction(() => /Marked: 2/.test(document.querySelector("#status-left").textContent));
    assert.deepEqual(hostLog.filter((m) => m.type === "marks").at(-1), { type: "marks", count: 2 });
    await rowEl(1).click(); // select another row so row 2 isn't drawn as selected
    const marked = await rowEl(2).evaluate((r) => ({ marked: r.classList.contains("marked"), inline: r.style.backgroundColor }));
    assert.deepEqual(marked, { marked: true, inline: "" }, "marked rows ignore coloring rules");

    await command("nextMark"); // Shift+Ctrl+N
    await waitSelected(2);
    await command("nextMark");
    await waitSelected(9);
    await command("nextMark"); // wraps
    await waitSelected(2);
    await command("previousMark");
    await waitSelected(9);

    await rowEl(9).click({ button: "right" });
    assert.ok(await page.isVisible("#context-menu .item:has-text('Unmark Packet')"));
    await page.keyboard.press("Escape");
    await command("unmarkAll");
    await page.waitForFunction(() => !document.querySelector("#list-rows .list-row.marked"));
    await post({ type: "coloring", coloringId: 0, rules: [] });
  });

  test("Apply as Column, header menu hide/show, drag to reorder", async () => {
    await cleanView();
    await rowEl(4).click();
    await waitSelected(4);
    const src = page.locator("#detail-tree .node-row:has-text('Source Address')").first();
    await src.waitFor();
    await src.click({ button: "right" });
    await page.click("#context-menu .item:has-text('Apply as Column')");
    assert.deepEqual(hostLog.filter((m) => m.type === "applyColumn").at(-1), { type: "applyColumn", field: "ip.src", title: "Source Address" });
    await page.waitForFunction(() => [...document.querySelectorAll("#list-header > div")].some((c) => c.dataset.id === "custom:ip.src"));

    await page.click("#list-header > div[data-id='time']", { button: "right" });
    await page.click("#context-menu .item:has-text('Hide “Time”')");
    assert.ok(!(await headerIds()).includes("time"));
    assert.deepEqual(layout.hidden, ["time"]);
    await page.click("#list-header > div[data-id='number']", { button: "right" });
    // The unchecked "Time" entry shows it again.
    await page.$$eval("#context-menu .item", (items) => items.find((i) => i.textContent.trim() === "Time" && !i.textContent.startsWith("✓")).click());
    assert.ok((await headerIds()).includes("time"));

    await page.dragAndDrop("#list-header > div[data-id='protocol']", "#list-header > div[data-id='number']");
    assert.deepEqual((await headerIds()).slice(0, 2), ["protocol", "number"]);
    assert.equal(layout.order[0], "protocol");
    await page.waitForFunction(() => document.querySelector("#list-rows .list-row:not(.loading)")?.children[0]?.textContent === "TCP");

    await page.click("#list-header > div[data-id='custom:ip.src']", { button: "right" });
    await page.click("#context-menu .item:has-text('Remove Column')");
    await page.waitForFunction(() => ![...document.querySelectorAll("#list-header > div")].some((c) => c.dataset.id === "custom:ip.src"));
    await page.click("#list-header > div[data-id='number']", { button: "right" });
    await page.click("#context-menu .item:has-text('Reset Column Order and Visibility')");
    assert.deepEqual((await headerIds()).slice(0, 2), ["number", "time"]);
  });

  test("cell menu: Apply / Prepare as Filter from a packet-list cell", async () => {
    await cleanView();
    const srcCell = rowEl(1).locator("div").nth(2); // Source of frame 1: 192.168.1.10
    await srcCell.click({ button: "right" });
    await page.click("#context-menu .item:text-is('Apply as Filter')");
    await page.waitForFunction(() => document.querySelector("#filter-input").value === "ip.src == 192.168.1.10");
    await page.waitForFunction(() => /Displayed: 6/.test(document.querySelector("#status-left").textContent));

    // Displayed now: 1, 3, 4, 8, 9, 11; the third row is frame 4, Protocol "HTTP".
    await page.locator("#list-rows .list-row").nth(2).locator("div").nth(4).click({ button: "right" });
    await page.click("#context-menu .item:text-is('Prepare as Filter')");
    assert.equal(await page.inputValue("#filter-input"), "http");
    await rowEl(1).locator("div").nth(6).click({ button: "right" }); // Info: no filter
    assert.ok(await page.$eval("#context-menu .item:text-is('Apply as Filter')", (i) => i.classList.contains("disabled")));
    await page.keyboard.press("Escape");
  });

  test("time display format and time reference", async () => {
    await cleanView();
    const timeCell = (frame) => rowEl(frame).locator("div").nth(1).textContent();
    await page.click("#status-time");
    assert.deepEqual(hostLog.at(-1), { type: "pickTimeFormat" });
    await post({ type: "timeFormat", format: "utc" }); // the host saved pcapViewer.timeFormat
    await page.waitForFunction(() => document.querySelectorAll("#list-rows .list-row")[0]?.children[1]?.textContent === "2023-11-14 22:13:20.000000");
    assert.equal(await page.textContent("#status-time"), "Time: UTC date and time");
    await post({ type: "timeFormat", format: "delta_captured" });
    await page.waitForFunction(() => document.querySelectorAll("#list-rows .list-row")[4]?.children[1]?.textContent === "0.001000");
    await post({ type: "timeFormat", format: "relative" });

    await rowEl(4).click();
    await waitSelected(4);
    await command("toggleTimeReference"); // Ctrl+T
    await page.waitForFunction(() => document.querySelectorAll("#list-rows .list-row")[3]?.children[1]?.textContent === "*REF*");
    assert.equal(await timeCell(5), "0.001000");
    assert.equal(await timeCell(1), "-0.003000");
    assert.match(await status(), /Time reference: 4/);
    await command("toggleTimeReference");
    await page.waitForFunction(() => document.querySelectorAll("#list-rows .list-row")[3]?.children[1]?.textContent === "0.003000");
  });

  test("Ctrl+Home / Ctrl+End and conversation stepping", async () => {
    await cleanView();
    await rowEl(3).click();
    await page.keyboard.press("Control+End");
    await waitSelected(11);
    await page.keyboard.press("Control+Home");
    await waitSelected(1);
    await command("nextInConversation"); // Ctrl+.
    await waitSelected(2);
    await command("previousInConversation"); // Ctrl+,
    await waitSelected(1);
    await command("previousInConversation");
    await page.waitForFunction(() => /No previous packet in this conversation/.test(document.querySelector("#filter-error").textContent));
  });

  test("no script errors or CSP violations", () => {
    assert.deepEqual(pageErrors, []);
    assert.deepEqual(cspViolations, []);
  });
});
