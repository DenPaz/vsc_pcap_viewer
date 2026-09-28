/**
 * End-to-end test of the real webview (index.html + lib.js + main.js) in
 * headless Chromium, with a minimal stand-in for the extension host that
 * forwards RPCs to the real Python backend (and therefore real tshark).
 *
 * Skips when tshark, the compiled BackendClient or a Chromium build are missing.
 * Set PCAP_VIEWER_SCREENSHOT=<path> to save a screenshot of the final state.
 */
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { isDeepStrictEqual } = require("node:util");
const { spawnSync } = require("node:child_process");
const {
  ROOT,
  HAVE_TSHARK,
  loadDeps,
  serveWebview,
  renderEditorHtml,
  startBackend,
} = require("./harness");

const deps = loadDeps();
const maybe = deps && HAVE_TSHARK ? suite : suite.skip;
/** The ☰ menu's list, as the host builds it (src/commandMenu.ts, compiled). */
const menuCommands = deps
  ? require(path.join(ROOT, "out", "src", "commandMenu.js")).buildCommandMenu(
      JSON.parse(fs.readFileSync(path.join(ROOT, "package.json"), "utf8")),
    )
  : [];

maybe("webview end-to-end (Chromium + real backend)", function () {
  this.timeout(60_000);
  let server, browser, page, client;
  // What the stand-in host received / keeps (mirrors pcapEditor.ts behaviour).
  const hostLog = [];
  /** Unsaved comment edits (the real host keeps them in PcapDocument). */
  const commentEdits = {};
  let savedFilters = [{ name: "Web", filter: "http" }];
  // Stubbed "✨ Ask AI" answer (the real host validates suggestions with tshark first); null = never answer.
  /** @type {{suggestions: {filter: string, explanation: string}[], message?: string} | null} */
  let aiReply = null;
  // The stand-in host's pcapViewer.columns (Apply as Column / Remove update it and send it back).
  let customCols = [{ field: "tcp.stream", title: "Stream" }];
  let layout = { order: [], hidden: [] };
  // packet_detail requests the webview made, and a delay for exact ones (to see the quick view first).
  const detailRequests = [];
  let exactDetailDelayMs = 0;
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

  /** Assert that the host's last message (of `expected.type` with `ofType`) is `expected`,
   * waiting for it: messages reach the host asynchronously, after the action resolves. */
  async function expectHostLast(expected, { ofType = false } = {}) {
    const last = () => (ofType ? hostLog.filter((m) => m.type === expected.type) : hostLog).at(-1);
    const start = Date.now();
    while (!isDeepStrictEqual(last(), expected) && Date.now() - start < 5000) {
      await new Promise((r) => setTimeout(r, 20));
    }
    assert.deepEqual(last(), expected);
  }

  suiteSetup(async function () {
    server = await serveWebview();
    const origin = `http://127.0.0.1:${server.address().port}`;
    // Live capture uses a stand-in dumpcap (no capture rights needed): it "captures"
    // mixed.pcapng's 26 packets, one every 80 ms, then stays idle until stopped.
    const venvPython = path.join(
      ROOT,
      ".venv",
      process.platform === "win32" ? "Scripts/python.exe" : "bin/python",
    );
    process.env.PCAP_VIEWER_DUMPCAP = JSON.stringify([
      process.env.PCAP_VIEWER_PYTHON ?? (fs.existsSync(venvPython) ? venvPython : "python3"),
      path.join(ROOT, "test", "fixtures", "fake_dumpcap.py"),
    ]);
    process.env.FAKE_DUMPCAP_DELAY = "0.08";
    client = await startBackend(deps);
    // Streaming filters report their matches as "filter" notifications (see src/pcapEditor.ts).
    client.onNotification("filter", (p) => void post({ type: "filterEvent", ...p }));

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

    /** Webview rpc id → backend request id, for "cancel". */
    const inflight = new Map();
    // Minimal extension-host emulation (see src/pcapEditor.ts).
    await page.exposeFunction("__toHost", async (raw) => {
      const msg = JSON.parse(raw);
      if (msg.type === "ready") {
        // Like PcapEditorSession: the ☰ menu's commands come first, built from package.json.
        await post({ type: "commands", commands: menuCommands });
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
          quickDetail: { after: 20000, window: 300 },
          filter: "",
          history: ["tcp.port == 80"],
          savedFilters,
          elapsedMs: 12,
          names: "Names: MAC",
        });
      } else if (msg.type === "saveFilter") {
        // The real host asks for a name; the stand-in uses "Saved <n>".
        hostLog.push(msg);
        savedFilters = [
          ...savedFilters,
          { name: `Saved ${savedFilters.length}`, filter: msg.expr },
        ];
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
      } else if (
        [
          "marks",
          "pickTimeFormat",
          "pickNameResolution",
          "renameColumn",
          "exportSelected",
          "copy",
          "askAboutPackets",
          "runCommand",
          "addFilterButton",
          "editFilterButton",
        ].includes(msg.type)
      ) {
        hostLog.push(msg);
      } else if (
        [
          "manageSavedFilters",
          "filterApplied",
          "selection",
          "follow",
          "decodeAs",
          "colorize",
          "exportBytes",
        ].includes(msg.type)
      ) {
        hostLog.push(msg);
      } else if (msg.type === "stopCapture") {
        hostLog.push(msg);
        await client.request("capture_stop", {});
      } else if (msg.type === "setComment") {
        // Like PcapDocument/pushComments: the edits go to the backend, then the viewer refreshes.
        hostLog.push(msg);
        commentEdits[msg.frame] = msg.text || null;
        await client.request("set_comments", { edits: commentEdits });
        await post({ type: "commentsChanged" });
      } else if (msg.type === "cancel") {
        // Like PcapEditorSession: cancel the backend request behind a webview rpc.
        const backendId = inflight.get(msg.id);
        if (backendId !== undefined) {
          client.cancel(backendId);
        }
      } else if (msg.type === "rpc") {
        if (msg.method === "packet_detail") {
          detailRequests.push(msg.params);
          if (!msg.params.mode && exactDetailDelayMs) {
            await new Promise((r) => setTimeout(r, exactDetailDelayMs));
          }
        }
        const pending = client.send(msg.method, msg.params, {
          timeoutMs: 0,
          onProgress: (p) =>
            void post({
              type: "progress",
              id: msg.id,
              phase: p.phase,
              fraction: p.fraction,
              frames: p.frames,
              matched: p.matched,
            }),
        });
        inflight.set(msg.id, pending.id);
        pending.promise.catch(() => undefined).then(() => inflight.delete(msg.id));
        pending.promise.then(
          (result) => post({ type: "rpcResult", id: msg.id, result }),
          (err) =>
            post({ type: "rpcError", id: msg.id, error: { code: err.code, message: err.message } }),
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

  const rowNumbers = () =>
    page.$$eval("#list-rows .list-row:not(.loading)", (rows) =>
      rows.map((r) => Number(r.children[0].textContent)),
    );

  test("renders the packet list with base and custom columns", async () => {
    await page.waitForSelector("#overlay.hidden", { state: "attached" });
    await page.waitForFunction(
      () => document.querySelectorAll("#list-rows .list-row:not(.loading)").length === 11,
    );
    assert.deepEqual(await rowNumbers(), [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11]);
    const headers = await page.$$eval("#list-header > div", (cells) =>
      cells.map((c) => c.firstChild.textContent),
    );
    assert.deepEqual(headers, [
      "No.",
      "Time",
      "Source",
      "Destination",
      "Protocol",
      "Length",
      "Info",
      "Stream",
    ]);
    const fourth = await page.$$eval("#list-rows .list-row", (rows) =>
      [...rows[3].children].map((c) => c.textContent),
    );
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
    await page.waitForFunction(
      () => document.querySelectorAll("#list-rows .list-row:not(.loading)").length === 2,
    );
    assert.deepEqual(await rowNumbers(), [4, 7]);
    assert.match(await page.textContent("#status-left"), /Displayed: 2/);
  });

  test("selecting a packet shows the tree and bytes, with two-way highlighting", async () => {
    await page.click("#list-rows .list-row >> nth=1"); // frame 7 (reassembled HTTP)
    await page.waitForSelector("#detail-tree .node-row");
    const protos = await page.$$eval("#detail-tree > div > .node-row .label", (ls) =>
      ls.map((l) => l.textContent),
    );
    assert.ok(protos[0].startsWith("Frame 7"));
    assert.ok(protos.some((p) => p.startsWith("Hypertext Transfer Protocol")));
    // Two byte sources: frame and reassembled TCP.
    assert.equal(await page.locator("#bytes-tabs button").count(), 2);

    // Tree -> bytes: expand IPv4 and select the source address.
    await page.click("#detail-tree .node-row:has-text('Internet Protocol Version 4') .twisty");
    await page.click("#detail-tree .node-row:has-text('Source Address')");
    const marked = await page.$$eval("#bytes-view .b.hl", (bs) =>
      bs.map((b) => b.textContent).join(" "),
    );
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
    await page.waitForFunction(
      () => document.querySelector("#filter-input").value === "ip.src == 93.184.216.34",
    );
    await page.waitForFunction(() =>
      /Displayed: 5/.test(document.querySelector("#status-left").textContent),
    );
  });

  test("sorting by a column header", async () => {
    await page.click("#filter-clear");
    await page.waitForFunction(
      () => document.querySelectorAll("#list-rows .list-row:not(.loading)").length === 11,
    );
    await page.click("#list-header > div:has-text('Length')");
    await page.click("#list-header > div:has-text('Length')"); // descending
    await page.waitForFunction(
      () => document.querySelector("#list-rows .list-row").children[5].textContent === "345",
    );
    const lengths = await page.$$eval("#list-rows .list-row", (rows) =>
      rows.slice(0, 3).map((r) => r.children[5].textContent),
    );
    assert.deepEqual(lengths, ["345", "254", "144"]);
  });

  test("keyboard navigation moves the selection", async () => {
    await page.focus("#list-viewport");
    await page.keyboard.press("Home");
    await page.keyboard.press("ArrowDown");
    await page.waitForFunction(
      () => document.querySelector("#list-rows .list-row.selected")?.dataset.index === "1",
    );
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
    await page.waitForFunction(() =>
      /Displayed: 5/.test(document.querySelector("#status-left").textContent),
    );
    assert.ok(
      hostLog.some((m) => m.type === "filterApplied" && m.expr === "ip.src == 93.184.216.34"),
    );
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
    assert.deepEqual(
      items.map((i) => i.label),
      ["Web", "tcp.port == 80", "Manage saved filters…"],
    );
    await page.click("#suggest .suggest-item:has-text('Web')");
    await page.waitForFunction(() =>
      /Displayed: 2/.test(document.querySelector("#status-left").textContent),
    );
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
    assert.deepEqual(hostLog.filter((m) => m.type === "saveFilter").pop(), {
      type: "saveFilter",
      expr: "tcp.len == 0",
    });
    items = await suggestions();
    assert.ok(
      items.some((i) => i.label === "Saved 1" && i.desc === "tcp.len == 0"),
      JSON.stringify(items),
    );
    await page.click("#suggest .suggest-item:has-text('Manage saved filters')");
    await expectHostLast({ type: "manageSavedFilters" });
  });

  test("an unknown custom column is dropped instead of breaking the list", async () => {
    await post({
      type: "columns",
      columns: [
        { field: "tcp.stream", title: "Stream" },
        { field: "no.such.field", title: "Typo" },
      ],
    });
    await page.waitForFunction(() =>
      /no\.such\.field/.test(document.querySelector("#filter-error").textContent),
    );
    await page.waitForFunction(
      () => document.querySelectorAll("#list-rows .list-row:not(.loading)").length > 0,
    );
    const headers = await page.$$eval("#list-header > div", (cells) =>
      cells.map((c) => c.firstChild.textContent),
    );
    assert.deepEqual(headers.slice(-2), ["Info", "Stream"]);
  });

  test("the selection is reported and the packet list offers Follow Stream", async () => {
    await page.click("#filter-clear");
    await page.waitForFunction(
      () => document.querySelectorAll("#list-rows .list-row:not(.loading)").length === 11,
    );
    await page.click("#list-header > div:has-text('No.')"); // back to frame order
    await page.waitForFunction(() => {
      const row = document.querySelectorAll("#list-rows .list-row")[3];
      return row && !row.classList.contains("loading") && row.children[0].textContent === "4";
    });
    await page.click("#list-rows .list-row >> nth=3", { button: "right" }); // frame 4 (HTTP GET)
    assert.ok(hostLog.some((m) => m.type === "selection" && m.frame === 4));
    const items = await page.$$eval("#context-menu .item", (els) =>
      els.map((e) => [e.textContent, !e.classList.contains("disabled")]),
    );
    // The clicked cell's Apply as Filter entries come first, then Follow.
    assert.deepEqual(
      items.slice(0, 2).map((i) => i[0]),
      ["Apply as Filter", "Prepare as Filter"],
    );
    assert.deepEqual(items.slice(5, 9), [
      ["Follow TCP Stream", true],
      ["Follow UDP Stream", true],
      ["Follow TLS Stream", false],
      ["Follow HTTP Stream", true],
    ]);
    await page.click("#context-menu .item:has-text('Follow HTTP Stream')");
    await expectHostLast({ type: "follow", proto: "http", frame: 4 });
    await page.click("#list-rows .list-row >> nth=3", { button: "right" });
    await page.click("#context-menu .item:has-text('Decode As')");
    await expectHostLast({ type: "decodeAs", frame: 4 });
  });

  test("coloring rules color the rows; Colorize and Export Bytes reach the host", async () => {
    // Frame 4 is still selected from the previous test.
    const rules = [
      { name: "HTTP", filter: "http", foreground: "#12272e", background: "#e4ffc7" },
      { name: "TCP", filter: "tcp", foreground: "#000000", background: "#e7e6ff" },
    ];
    // A separate coloring pass shows its progress until the colors arrive.
    await post({ type: "coloringProgress", fraction: null });
    await page.waitForFunction(() =>
      / · Coloring…$/.test(document.querySelector("#status-left")?.textContent ?? ""),
    );
    await post({ type: "coloringProgress", fraction: 0.4 });
    await page.waitForFunction(() =>
      / · Coloring… 40%$/.test(document.querySelector("#status-left")?.textContent ?? ""),
    );
    const res = await client.request(
      "set_coloring",
      {
        rules: rules.map(({ filter, foreground, background }) => ({
          filter,
          foreground,
          background,
        })),
      },
      { timeoutMs: 0 },
    );
    await post({
      type: "coloring",
      coloringId: res.coloringId,
      rules: rules.map(({ name, foreground, background }) => ({ name, foreground, background })),
    });
    await page.waitForFunction(
      () => !/Coloring/.test(document.querySelector("#status-left")?.textContent ?? ""),
    );
    await page.waitForFunction(() =>
      document.querySelector("#list-rows .list-row")?.classList.contains("colored"),
    );
    const rows = await page.$$eval("#list-rows .list-row", (els) =>
      els.map((r) => ({
        frame: r.children[0].textContent,
        selected: r.classList.contains("selected"),
        bg: r.style.backgroundColor,
      })),
    );
    assert.equal(rows[0].bg, "rgb(231, 230, 255)"); // TCP handshake: rule 2
    assert.equal(rows[6].bg, "rgb(228, 255, 199)"); // frame 7, HTTP response: rule 1
    assert.deepEqual(rows[3], { frame: "4", selected: true, bg: "" }); // selection colors win

    await page.click("#detail-tree .node-row:has-text('Source Address')", { button: "right" });
    await page.click("#context-menu .item:has-text('Colorize with Filter')");
    await expectHostLast({ type: "colorize", filter: "ip.src == 192.168.1.10" });
    await page.click("#list-rows .list-row >> nth=3", { button: "right" });
    await page.click("#context-menu .item:has-text('Export Packet Bytes')");
    await expectHostLast({ type: "exportBytes", frame: 4 });

    await post({ type: "coloring", coloringId: 0, rules: [] }); // coloring turned off
    await page.waitForFunction(() => !document.querySelector("#list-rows .list-row.colored"));
    await post({ type: "coloringProgress", fraction: 0.1 });
    await post({ type: "coloringProgress", fraction: null, done: true }); // failed or cancelled
    await page.waitForFunction(
      () => !/Coloring/.test(document.querySelector("#status-left")?.textContent ?? ""),
    );
  });

  const statusText = () => page.textContent("#status-left");

  test("✨ Ask AI: describe the packets, pick a suggestion, Enter applies it", async () => {
    await page.click("#filter-clear");
    await page.waitForFunction(
      () => !/Displayed/.test(document.querySelector("#status-left").textContent),
    );
    assert.ok(
      await page.$eval("#filter-ai", (b) => b.classList.contains("hidden")),
      "hidden until the host says a model is available",
    );
    await post({ type: "aiAvailable", available: true });
    await page.waitForSelector("#filter-ai:not(.hidden)");

    await page.fill("#filter-input", "tcp"); // typed, not applied (its completions close in ask mode)
    aiReply = {
      suggestions: [
        {
          filter: "tcp.flags.syn == 1",
          explanation: "Connection attempts: packets with the SYN flag set",
        },
        { filter: "tcp.flags.reset == 1", explanation: "Connections that were reset" },
      ],
    };
    await page.click("#filter-ai");
    assert.equal(await page.inputValue("#filter-input"), "");
    assert.match(await page.getAttribute("#filter-input", "placeholder"), /Describe the packets/);
    await page.type("#filter-input", "tcp connection attempts");
    await new Promise((r) => setTimeout(r, 150));
    assert.ok(
      await page.$eval("#suggest", (s) => s.classList.contains("hidden")),
      "no field completions while describing",
    );
    await page.press("#filter-input", "Enter");
    await page.waitForSelector("#suggest .suggest-item.kind-ai");
    assert.equal(
      hostLog.filter((m) => m.type === "aiSuggest").at(-1).request,
      "tcp connection attempts",
    );
    const items = await page.$$eval("#suggest .suggest-item", (els) =>
      els.map((e) => [
        e.querySelector(".suggest-label").textContent,
        e.querySelector(".suggest-desc").textContent,
      ]),
    );
    assert.deepEqual(items, [
      ["tcp.flags.syn == 1", "Connection attempts: packets with the SYN flag set"],
      ["tcp.flags.reset == 1", "Connections that were reset"],
    ]);
    assert.equal(
      await page.inputValue("#filter-input"),
      "tcp",
      "the filter text is back while choosing",
    );

    await page.click("#suggest .suggest-item >> nth=0");
    assert.equal(await page.inputValue("#filter-input"), "tcp.flags.syn == 1");
    assert.doesNotMatch(await statusText(), /Displayed/, "picking a suggestion doesn't apply it");
    await page.press("#filter-input", "Enter");
    await page.waitForFunction(() =>
      /Displayed: 2/.test(document.querySelector("#status-left").textContent),
    ); // SYN and SYN/ACK
  });

  test("✨ Ask AI: Esc cancels, no suggestions show a message, the action hides when unavailable", async () => {
    aiReply = null; // the host doesn't answer: the request stays in flight
    await page.click("#filter-ai");
    await page.type("#filter-input", "something slow");
    await page.press("#filter-input", "Enter");
    await page.waitForFunction(() =>
      /Asking the language model/.test(document.querySelector("#filter-error").textContent),
    );
    await page.press("#filter-input", "Escape");
    const asked = hostLog.filter((m) => m.type === "aiSuggest").at(-1);
    await waitForHost((m) => m.type === "aiCancel" && m.id === asked.id); // host messages arrive asynchronously
    assert.equal(
      await page.inputValue("#filter-input"),
      "tcp.flags.syn == 1",
      "Esc restores the filter",
    );
    assert.ok(await page.$eval("#filter-error", (e) => e.classList.contains("hidden")));

    aiReply = {
      suggestions: [],
      message: "The language model didn't come up with a valid display filter.",
    };
    await page.click("#filter-ai");
    await page.type("#filter-input", "gibberish");
    await page.press("#filter-input", "Enter");
    await page.waitForFunction(() =>
      /didn't come up with a valid display filter/.test(
        document.querySelector("#filter-error").textContent,
      ),
    );
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
  const waitSelected = (n) =>
    page.waitForFunction(
      (f) =>
        new RegExp(`Selected: ${f}(\\D|$)`).test(
          document.querySelector("#status-left").textContent,
        ),
      n,
    );
  const rowEl = (frame) => page.locator("#list-rows .list-row").nth(frame - 1); // unfiltered, unsorted view
  const command = (name) => post({ type: "command", command: name });
  const headerIds = () =>
    page.$$eval("#list-header > div", (cells) => cells.map((c) => c.dataset.id));

  /** Open another capture in the viewer, as the host would after a reload. */
  async function reopenCapture(file, extra = {}, label = "Names: MAC") {
    const info = await client.request(
      "open",
      { path: path.join(ROOT, "test", "fixtures", file), columns: ["tcp.stream"], ...extra },
      { timeoutMs: 0 },
    );
    await post({
      type: "init",
      info,
      columns: customCols,
      layout,
      timeFormat: "relative",
      quickDetail: { after: 20000, window: 300 },
      filter: "",
      history: [],
      savedFilters,
      elapsedMs: 1,
      names: label,
    });
    await page.waitForFunction(
      (n) => document.querySelector("#status-left").textContent.includes(`Packets: ${n}`),
      info.frames,
    );
    await page.waitForFunction(
      () => document.querySelectorAll("#list-rows .list-row:not(.loading)").length >= 11,
    );
  }

  async function cleanView() {
    await post({ type: "aiAvailable", available: false });
    await page.click("#filter-clear");
    await page.waitForFunction(
      () => !/Displayed/.test(document.querySelector("#status-left").textContent),
    );
    await page.waitForFunction(
      () => document.querySelectorAll("#list-rows .list-row:not(.loading)").length === 11,
    );
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
    await page.waitForFunction(() =>
      /wrapped/.test(document.querySelector("#find-status").textContent),
    );

    await page.selectOption("#find-mode", "hex");
    await page.fill("#find-input", "xyz");
    assert.equal(await page.textContent("#find-status"), "Not hex bytes");
    assert.ok(await page.$eval("#find-input", (i) => i.classList.contains("invalid")));
    await page.fill("#find-input", "47 45 54"); // "GET"
    await page.press("#find-input", "Enter");
    await page.waitForFunction(() =>
      /Packet 4/.test(document.querySelector("#find-status").textContent),
    );

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
    await page.waitForFunction(() =>
      document.querySelector("#find-status").classList.contains("error"),
    );
    await page.selectOption("#find-mode", "string");
    await page.fill("#find-input", "no such text anywhere");
    await page.press("#find-input", "Enter");
    await page.waitForFunction(
      () => document.querySelector("#find-status").textContent === "Not found",
    );

    await page.press("#find-input", "Escape");
    assert.ok(await page.$eval("#find-bar", (b) => b.classList.contains("hidden")));
  });

  test("frame links jump to the referenced packet; Alt+Left / Alt+Right walk the history", async () => {
    await cleanView();
    await rowEl(7).click(); // HTTP response: "[Request in frame: 4]"
    await waitSelected(7);
    const http = page
      .locator("#detail-tree .node-row:has-text('Hypertext Transfer Protocol')")
      .first();
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
    await page.waitForFunction(() =>
      /Displayed: 1/.test(document.querySelector("#status-left").textContent),
    );
    await page.locator("#list-rows .list-row").first().click();
    await waitSelected(7);
    await page
      .locator("#detail-tree .node-row.frame-link:has-text('Request in frame') .label")
      .click();
    await page.waitForFunction(() =>
      /Packet 4 is not displayed/.test(document.querySelector("#filter-error").textContent),
    );
    await page.click("#filter-error button:has-text('Clear filter and go')");
    await waitSelected(4);
    assert.doesNotMatch(await status(), /Displayed/);
  });

  test("marks: toggle, next/previous marked, the mark style wins over coloring, unmark all", async () => {
    await cleanView();
    const rules = [{ filter: "tcp", foreground: "#000000", background: "#e7e6ff" }];
    const res = await client.request("set_coloring", { rules }, { timeoutMs: 0 });
    await post({
      type: "coloring",
      coloringId: res.coloringId,
      rules: [{ name: "TCP", foreground: "#000000", background: "#e7e6ff" }],
    });
    await page.waitForFunction(() =>
      document.querySelector("#list-rows .list-row")?.classList.contains("colored"),
    );

    for (const frame of [2, 9]) {
      await rowEl(frame).click();
      await waitSelected(frame);
      await command("toggleMark"); // Ctrl+M
      await page.waitForFunction(
        (f) =>
          document.querySelectorAll("#list-rows .list-row")[f - 1]?.classList.contains("marked"),
        frame,
      );
    }
    await page.waitForFunction(() =>
      /Marked: 2/.test(document.querySelector("#status-left").textContent),
    );
    await expectHostLast({ type: "marks", count: 2 }, { ofType: true });
    await rowEl(1).click(); // select another row so row 2 isn't drawn as selected
    const marked = await rowEl(2).evaluate((r) => ({
      marked: r.classList.contains("marked"),
      inline: r.style.backgroundColor,
    }));
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
    await expectHostLast(
      {
        type: "applyColumn",
        field: "ip.src",
        title: "Source Address",
      },
      { ofType: true },
    );
    await page.waitForFunction(() =>
      [...document.querySelectorAll("#list-header > div")].some(
        (c) => c.dataset.id === "custom:ip.src",
      ),
    );

    await page.click("#list-header > div[data-id='time']", { button: "right" });
    await page.click("#context-menu .item:has-text('Hide “Time”')");
    assert.ok(!(await headerIds()).includes("time"));
    assert.deepEqual(layout.hidden, ["time"]);
    await page.click("#list-header > div[data-id='number']", { button: "right" });
    // The unchecked "Time" entry shows it again.
    await page.$$eval("#context-menu .item", (items) =>
      items.find((i) => i.textContent.trim() === "Time" && !i.textContent.startsWith("✓")).click(),
    );
    assert.ok((await headerIds()).includes("time"));

    await page.dragAndDrop(
      "#list-header > div[data-id='protocol']",
      "#list-header > div[data-id='number']",
    );
    assert.deepEqual((await headerIds()).slice(0, 2), ["protocol", "number"]);
    assert.equal(layout.order[0], "protocol");
    await page.waitForFunction(
      () =>
        document.querySelector("#list-rows .list-row:not(.loading)")?.children[0]?.textContent ===
        "TCP",
    );

    await page.click("#list-header > div[data-id='custom:ip.src']", { button: "right" });
    await page.click("#context-menu .item:has-text('Remove Column')");
    await page.waitForFunction(
      () =>
        ![...document.querySelectorAll("#list-header > div")].some(
          (c) => c.dataset.id === "custom:ip.src",
        ),
    );
    await page.click("#list-header > div[data-id='number']", { button: "right" });
    await page.click("#context-menu .item:has-text('Reset Column Order and Visibility')");
    assert.deepEqual((await headerIds()).slice(0, 2), ["number", "time"]);
  });

  test("cell menu: Apply / Prepare as Filter from a packet-list cell", async () => {
    await cleanView();
    const srcCell = rowEl(1).locator("div").nth(2); // Source of frame 1: 192.168.1.10
    await srcCell.click({ button: "right" });
    await page.click("#context-menu .item:text-is('Apply as Filter')");
    await page.waitForFunction(
      () => document.querySelector("#filter-input").value === "ip.src == 192.168.1.10",
    );
    await page.waitForFunction(() =>
      /Displayed: 6/.test(document.querySelector("#status-left").textContent),
    );

    // Displayed now: 1, 3, 4, 8, 9, 11; the third row is frame 4, Protocol "HTTP".
    await page
      .locator("#list-rows .list-row")
      .nth(2)
      .locator("div")
      .nth(4)
      .click({ button: "right" });
    await page.click("#context-menu .item:text-is('Prepare as Filter')");
    assert.equal(await page.inputValue("#filter-input"), "http");
    await rowEl(1).locator("div").nth(6).click({ button: "right" }); // Info: no filter
    assert.ok(
      await page.$eval("#context-menu .item:text-is('Apply as Filter')", (i) =>
        i.classList.contains("disabled"),
      ),
    );
    await page.keyboard.press("Escape");
  });

  test("time display format and time reference", async () => {
    await cleanView();
    const timeCell = (frame) => rowEl(frame).locator("div").nth(1).textContent();
    await page.click("#status-time");
    await expectHostLast({ type: "pickTimeFormat" });
    await post({ type: "timeFormat", format: "utc" }); // the host saved pcapViewer.timeFormat
    await page.waitForFunction(
      () =>
        document.querySelectorAll("#list-rows .list-row")[0]?.children[1]?.textContent ===
        "2023-11-14 22:13:20.000000",
    );
    assert.equal(await page.textContent("#status-time"), "Time: UTC date and time");
    await post({ type: "timeFormat", format: "delta_captured" });
    await page.waitForFunction(
      () =>
        document.querySelectorAll("#list-rows .list-row")[4]?.children[1]?.textContent ===
        "0.001000",
    );
    await post({ type: "timeFormat", format: "relative" });

    await rowEl(4).click();
    await waitSelected(4);
    await command("toggleTimeReference"); // Ctrl+T
    await page.waitForFunction(
      () =>
        document.querySelectorAll("#list-rows .list-row")[3]?.children[1]?.textContent === "*REF*",
    );
    assert.equal(await timeCell(5), "0.001000");
    assert.equal(await timeCell(1), "-0.003000");
    assert.match(await status(), /Time reference: 4/);
    await command("toggleTimeReference");
    await page.waitForFunction(
      () =>
        document.querySelectorAll("#list-rows .list-row")[3]?.children[1]?.textContent ===
        "0.003000",
    );
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
    await page.waitForFunction(() =>
      /No previous packet in this conversation/.test(
        document.querySelector("#filter-error").textContent,
      ),
    );
  });

  test("multi-select: Shift/Ctrl+click, Shift+arrows, Esc, Ctrl+A; mark, copy and export the selection", async () => {
    await cleanView();
    const selectedNumbers = () =>
      page.$$eval("#list-rows .list-row.selected", (rows) =>
        rows.map((r) => Number(r.children[0].textContent)),
      );
    const waitSelection = (frames) =>
      page.waitForFunction(
        (want) =>
          [...document.querySelectorAll("#list-rows .list-row.selected")]
            .map((r) => r.children[0].textContent)
            .join() === want.join(),
        frames,
      );
    const lastSelection = () => hostLog.filter((m) => m.type === "selection").at(-1);

    await rowEl(2).click();
    await waitSelected(2);
    await rowEl(5).click({ modifiers: ["Shift"] });
    await waitSelection([2, 3, 4, 5]);
    assert.match(await status(), /Selected: 5 \(4 packets\)/);
    await waitForHost((m) => m.type === "selection" && m.frames?.length === 4);
    assert.deepEqual(
      [...lastSelection().frames].sort((a, b) => a - b),
      [2, 3, 4, 5],
    );
    assert.equal(lastSelection().frame, 5, "the clicked row is focused (detail pane)");
    assert.ok(await rowEl(5).evaluate((r) => r.classList.contains("focused")));

    await rowEl(8).click({ modifiers: ["ControlOrMeta"] }); // add
    await rowEl(3).click({ modifiers: ["ControlOrMeta"] }); // take out
    await waitSelection([2, 4, 5, 8]);
    await waitSelected(8);

    // Right-click inside the selection keeps it; the menu acts on all of it.
    await rowEl(4).click({ button: "right" });
    assert.deepEqual(await selectedNumbers(), [2, 4, 5, 8]);
    await page.click("#context-menu .item:has-text('Copy 4 Rows')");
    await waitForHost((m) => m.type === "copy" && m.text.startsWith("No.\t"));
    const copied = hostLog
      .filter((m) => m.type === "copy")
      .at(-1)
      .text.split("\n");
    assert.equal(copied.length, 5, "a header line plus one line per row");
    assert.deepEqual(
      copied.slice(1).map((l) => l.split("\t")[0]),
      ["2", "4", "5", "8"],
    );
    // Ctrl+C in the list: VS Code fires a "copy" event in the webview.
    const clip = await page.evaluate(() => {
      const viewport = /** @type {HTMLElement} */ (document.getElementById("list-viewport"));
      viewport.focus();
      const data = new window.DataTransfer();
      viewport.dispatchEvent(
        new window.ClipboardEvent("copy", { clipboardData: data, bubbles: true, cancelable: true }),
      );
      return data.getData("text/plain");
    });
    assert.equal(clip.split("\n").length, 5);

    await command("toggleMark"); // Ctrl+M marks the whole selection
    await page.waitForFunction(
      () => document.querySelectorAll("#list-rows .list-row.marked").length === 4,
    );
    await page.waitForFunction(() =>
      /Marked: 4/.test(document.querySelector("#status-left").textContent),
    );
    await command("toggleMark"); // all marked: unmark them
    await page.waitForFunction(() => !document.querySelector("#list-rows .list-row.marked"));

    await rowEl(2).click({ button: "right" });
    await page.click("#context-menu .item:has-text('Export 4 Selected Packets')");
    await waitForHost((m) => m.type === "exportSelected");

    await page.focus("#list-viewport");
    await page.keyboard.press("Escape"); // back to one selected row: the focused one (right-clicked last)
    await waitSelection([2]);
    await rowEl(6).click();
    await page.keyboard.press("Shift+ArrowDown");
    await page.keyboard.press("Shift+ArrowDown");
    await waitSelection([6, 7, 8]);
    await waitSelected(8);
    await page.keyboard.press("Shift+ArrowUp");
    await waitSelection([6, 7]);

    // A new sort keeps the selection (same packets, new rows)...
    await page.click("#list-header > div[data-id='number']");
    await page.click("#list-header > div[data-id='number']"); // No. descending
    await page.waitForFunction(
      () =>
        document.querySelector("#list-rows .list-row:not(.loading)")?.children[0]?.textContent ===
        "11",
    );
    await waitSelection([7, 6]);
    await page.click("#list-header > div[data-id='number']"); // sort off

    // Ctrl+A: Chromium's select-all (the key, or VS Code's Select All command running
    // execCommand("selectAll") in the webview) selects every packet, not the page's text.
    await page.focus("#list-viewport");
    await page.keyboard.press("ControlOrMeta+a");
    await page.waitForFunction(
      () => document.querySelectorAll("#list-rows .list-row.selected").length === 11,
    );
    assert.match(await status(), /\(11 packets\)/);
    assert.equal(await page.evaluate(() => String(window.getSelection())), "", "no text selected");
    await page.keyboard.press("Escape");
    await page.waitForFunction(
      () => document.querySelectorAll("#list-rows .list-row.selected").length === 1,
    );
    await page.evaluate(() => document.execCommand("selectAll"));
    await page.waitForFunction(
      () => document.querySelectorAll("#list-rows .list-row.selected").length === 11,
    );
    assert.equal(await page.evaluate(() => String(window.getSelection())), "");
    // ...a new filter drops it.
    await page.fill("#filter-input", "http");
    await page.press("#filter-input", "Enter");
    await page.waitForFunction(() =>
      /Displayed: 2/.test(document.querySelector("#status-left").textContent),
    );
    await page.waitForFunction(
      () => document.querySelectorAll("#list-rows .list-row.selected").length <= 1,
    );
    assert.doesNotMatch(await status(), /packets\)/);
    // Ctrl+A in the filter bar selects its text, not packets (also via the palette command).
    await page.focus("#filter-input");
    await page.keyboard.press("ControlOrMeta+a");
    assert.equal(
      await page.evaluate(() => {
        const i = /** @type {HTMLInputElement} */ (document.getElementById("filter-input"));
        return i.value.slice(i.selectionStart ?? 0, i.selectionEnd ?? 0);
      }),
      "http",
    );
    await page.evaluate(() =>
      /** @type {HTMLInputElement} */ (document.getElementById("filter-input")).setSelectionRange(
        0,
        0,
      ),
    );
    await command("selectAll");
    await page.waitForFunction(() => {
      const i = /** @type {HTMLInputElement} */ (document.getElementById("filter-input"));
      return i.value.slice(i.selectionStart ?? 0, i.selectionEnd ?? 0) === "http";
    });
    assert.ok((await page.$$("#list-rows .list-row.selected")).length <= 1);
  });

  test("Ask Copilot About This Packet / N Selected Packets (only when AI help is available)", async () => {
    await cleanView(); // AI unavailable
    await rowEl(4).click({ button: "right" });
    assert.ok(
      !(await page.isVisible("#context-menu .item:has-text('Ask Copilot')")),
      "hidden without a language model",
    );
    await page.keyboard.press("Escape");

    await post({ type: "aiAvailable", available: true });
    await rowEl(4).click({ button: "right" });
    await page.click("#context-menu .item:text-is('Ask Copilot About This Packet…')");
    await waitForHost((m) => m.type === "askAboutPackets");
    await expectHostLast(
      {
        type: "askAboutPackets",
        frames: [4],
      },
      { ofType: true },
    );

    await rowEl(7).click({ modifiers: ["ControlOrMeta"] });
    await rowEl(2).click({ modifiers: ["ControlOrMeta"] });
    await rowEl(7).click({ button: "right" }); // inside the selection: keeps it
    await page.click("#context-menu .item:text-is('Ask Copilot About 3 Selected Packets…')");
    await waitForHost((m) => m.type === "askAboutPackets" && m.frames.length === 3);
    assert.deepEqual(
      hostLog.filter((m) => m.type === "askAboutPackets").at(-1).frames,
      [2, 4, 7],
      "frame order",
    );
    await post({ type: "aiAvailable", available: false });
  });

  test("a notice isn't wiped by the validation of a filter that was already applied", async () => {
    await cleanView();
    await rowEl(1).click();
    await waitSelected(1);
    // Enter right after typing: the typing's validation is still pending (250 ms).
    await page.fill("#filter-input", "tcp");
    await page.press("#filter-input", "Enter");
    await command("nextMark"); // nothing is marked: a notice, right away
    const notice = () =>
      page.evaluate(() => document.getElementById("filter-error")?.textContent ?? "");
    await page.waitForFunction(() =>
      /No packets are marked/.test(document.getElementById("filter-error")?.textContent ?? ""),
    );
    await page.waitForTimeout(700); // past the stale validation
    assert.match(await notice(), /No packets are marked/);
  });

  test("☰ commands menu: button, groups, filter, keyboard, run, disabled entries", async () => {
    // A fresh open (no packet selected, nothing marked), then no filter and no AI.
    await reopenCapture("http.pcap");
    await cleanView();
    const menuOpen = () => page.$eval("#commands-menu", (m) => !m.classList.contains("hidden"));
    const button = () =>
      page.$eval("#filter-menu", (b) => ({
        after: b.previousElementSibling?.id,
        label: b.getAttribute("aria-label"),
        title: b.title,
        popup: b.getAttribute("aria-haspopup"),
        expanded: b.getAttribute("aria-expanded"),
        focused: document.activeElement === b,
      }));
    const items = () =>
      page.$$eval("#commands-list [role=menuitem][data-id]", (nodes) =>
        nodes.map((n) => ({
          id: n.dataset.id,
          title: n.querySelector(".title")?.textContent,
          keys: n.querySelector(".keys")?.textContent,
          disabled: n.getAttribute("aria-disabled") === "true",
          reason: n.title,
          active: n.classList.contains("active"),
          group: n.closest("[role=group]")?.getAttribute("aria-label"),
        })),
      );
    const headings = () =>
      page.$$eval("#commands-list [role=menuitem][data-group]", (nodes) =>
        nodes.map((n) => ({
          group: n.dataset.group,
          expanded: n.getAttribute("aria-expanded"),
          count: Number(n.querySelector(".count")?.textContent),
        })),
      );
    const activeId = () =>
      page.$eval("#commands-filter", (i) => {
        const id = i.getAttribute("aria-activedescendant");
        return id ? document.getElementById(id)?.dataset.id : null;
      });
    const activeGroup = () =>
      page.$eval("#commands-filter", (i) => {
        const id = i.getAttribute("aria-activedescendant");
        return id ? document.getElementById(id)?.dataset.group : null;
      });
    const GROUPS = [
      "Filters",
      "Packets",
      "Statistics",
      "Export",
      "Capture",
      "Editing",
      "Dissectors",
      "AI",
      "Other",
    ];

    let b = await button();
    assert.deepEqual(
      [b.after, b.label, b.title, b.popup, b.expanded],
      ["filter-clear", "All PCAP commands", "All PCAP commands", "menu", "false"],
    );

    // Open with a click: the headings in their order, folded, with their counts.
    await page.click("#filter-menu");
    assert.equal(await menuOpen(), true);
    assert.equal((await button()).expanded, "true");
    assert.equal(
      await page.evaluate(() => document.activeElement?.id),
      "commands-filter",
      "focus in the filter box",
    );
    assert.equal(await page.getAttribute("#commands-list", "role"), "menu");
    if (process.env.PCAP_SCREENSHOTS) {
      await page.screenshot({ path: `${process.env.PCAP_SCREENSHOTS}/commands-menu.png` });
    }
    let hs = await headings();
    assert.deepEqual(
      hs.map((h) => h.group),
      GROUPS,
    );
    assert.ok(hs.every((h) => h.expanded === "false"));
    assert.equal(
      hs.reduce((n, h) => n + h.count, 0),
      menuCommands.length,
      "the counts cover every command",
    );
    assert.equal((await items()).length, 0, "groups start folded");
    assert.equal(await activeGroup(), "Filters");

    // → opens the active heading, → again goes into it, ← back to the heading, ← folds it.
    await page.keyboard.press("ArrowRight");
    hs = await headings();
    assert.equal(hs[0].expanded, "true");
    assert.equal(await activeGroup(), "Filters", "the heading stays active");
    const filters = await items();
    assert.equal(filters.length, hs[0].count);
    assert.ok(filters.every((i) => i.group === "Filters"));
    await page.keyboard.press("ArrowRight");
    assert.equal(await activeId(), "pcapViewer.applyFilter");
    await page.keyboard.press("ArrowLeft");
    assert.equal(await activeGroup(), "Filters");
    await page.keyboard.press("ArrowLeft");
    assert.equal((await headings())[0].expanded, "false");
    assert.equal((await items()).length, 0);
    // Enter toggles a heading too; ↓ moves between headings.
    await page.keyboard.press("ArrowDown");
    assert.equal(await activeGroup(), "Packets");
    await page.keyboard.press("Enter");
    assert.equal((await headings())[1].expanded, "true");
    await page.keyboard.press("Enter");
    assert.equal((await headings())[1].expanded, "false");

    // A click on each heading opens it: every command, under its heading, in order.
    for (const g of GROUPS) {
      await page.click(`#commands-list [data-group='${g}']`);
    }
    const all = await items();
    assert.equal(all.length, menuCommands.length, "every command is listed");
    assert.deepEqual([...new Set(all.map((i) => i.group))], GROUPS);
    const byId = Object.fromEntries(all.map((i) => [i.id, i]));
    // Key bindings follow the platform the webview runs on (macOS CI shows ⌘ and ⌥).
    const mac = await page.evaluate(() =>
      /Mac|iPhone|iPad/i.test(window.navigator.platform || window.navigator.userAgent),
    );
    assert.equal(mac, process.platform === "darwin");
    assert.equal(byId["pcapViewer.applyFilter"].keys, mac ? "⌘/" : "Ctrl+/");
    assert.equal(byId["pcapViewer.goBack"].keys, mac ? "⌥←" : "Alt+Left");
    assert.equal(byId["pcapViewer.statistics.conversations"].keys, "");
    // What can't run now is disabled, with the reason.
    assert.equal(byId["pcapViewer.toggleMark"].disabled, true);
    assert.equal(byId["pcapViewer.toggleMark"].reason, "Select a packet first");
    assert.equal(byId["pcapViewer.stopCapture"].reason, "No capture is running");
    assert.match(byId["pcapViewer.summarizeCapture"].reason, /AI help isn't available/);
    assert.equal(byId["pcapViewer.clearFilter"].reason, "No display filter is applied");
    assert.equal(byId["pcapViewer.statistics.conversations"].disabled, false);
    assert.equal(byId["pcapViewer.savedFilters"], undefined, "excluded");
    assert.equal(await activeGroup(), "Other", "the heading clicked last stays active");

    // A disabled entry sends nothing (click or Enter); the hint says why.
    const runs = () => hostLog.filter((m) => m.type === "runCommand").length;
    // (force: Playwright won't click an aria-disabled element; a person can.)
    await page.click("#commands-list [data-id='pcapViewer.toggleMark']", { force: true });
    assert.equal(await menuOpen(), true, "stays open");
    assert.equal(
      await page.textContent("#commands-menu .command-hint"),
      "Mark/Unmark Selected Packets: Select a packet first",
    );
    assert.equal(runs(), 0);

    // Typing filters (title, heading or category) over every group, folded or not; the
    // headings are then labels, and the arrows, Home/End move over the matches; Esc closes.
    await page.click("#commands-list [data-group='Statistics']"); // (fold one)
    await page.fill("#commands-filter", "statistics conv");
    assert.deepEqual(
      (await items()).map((i) => i.id),
      ["pcapViewer.statistics.conversations"],
    );
    assert.deepEqual(await headings(), [], "headings are labels while searching");
    assert.deepEqual(
      await page.$$eval("#commands-list .heading", (h) => h.map((x) => x.textContent)),
      ["Statistics"],
    );
    await page.fill("#commands-filter", "EXPORT");
    const exports = await items();
    assert.ok(exports.length >= 7 && exports.every((i) => /export/i.test(`${i.title} ${i.group}`)));
    assert.equal(await activeId(), exports.find((i) => !i.disabled).id);
    await page.keyboard.press("End");
    assert.equal(await activeId(), exports.at(-1).id);
    await page.keyboard.press("ArrowDown"); // wraps
    assert.equal(await activeId(), exports[0].id);
    await page.keyboard.press("ArrowUp");
    assert.equal(await activeId(), exports.at(-1).id);
    await page.keyboard.press("Home");
    assert.equal(await activeId(), exports[0].id);
    await page.fill("#commands-filter", "no such command");
    assert.equal((await items()).length, 0);
    assert.equal(await page.textContent("#commands-menu .command-hint"), "No matching commands");
    await page.keyboard.press("Escape");
    assert.equal(await menuOpen(), false);
    b = await button();
    assert.deepEqual([b.expanded, b.focused], ["false", true], "focus back on the button");

    // Keyboard: Enter opens it, typing filters, Enter runs the entry; focus comes back.
    await page.keyboard.press("Enter");
    assert.equal(await menuOpen(), true);
    await page.keyboard.type("protocol hier");
    await page.keyboard.press("Enter");
    await waitForHost((m) => m.type === "runCommand");
    await expectHostLast(
      {
        type: "runCommand",
        id: "pcapViewer.statistics.protocolHierarchy",
      },
      { ofType: true },
    );
    assert.equal(await menuOpen(), false);
    assert.equal((await button()).focused, true);

    // Space opens it too, with the groups left open still open (Statistics was folded);
    // ↓ goes from the Filters heading to Apply, ↓ to the disabled Clear (Enter sends nothing),
    // ↓ again runs Save.
    await page.keyboard.press(" ");
    assert.equal(await menuOpen(), true);
    assert.deepEqual(
      (await headings()).filter((h) => h.expanded === "false").map((h) => h.group),
      ["Statistics"],
      "open groups are remembered",
    );
    assert.equal(await activeGroup(), "Filters");
    await page.keyboard.press("ArrowDown");
    assert.equal(await activeId(), "pcapViewer.applyFilter");
    await page.keyboard.press("ArrowDown");
    assert.equal(await activeId(), "pcapViewer.clearFilter");
    await page.keyboard.press("Enter");
    assert.equal(await menuOpen(), true);
    assert.equal(runs(), 1);
    await page.keyboard.press("ArrowDown");
    assert.equal(await activeId(), "pcapViewer.saveFilter");
    await page.keyboard.press("Enter");
    await waitForHost((m) => m.type === "runCommand" && m.id === "pcapViewer.saveFilter");

    // A click outside closes it; with a selected packet the entry is enabled and runs.
    await page.click("#filter-menu");
    await page.mouse.click(5, 300);
    assert.equal(await menuOpen(), false);
    await rowEl(2).click();
    await waitSelected(2);
    await page.click("#filter-menu");
    assert.equal((await items()).find((i) => i.id === "pcapViewer.toggleMark").disabled, false);
    await page.click("#commands-list [data-id='pcapViewer.toggleMark']");
    await waitForHost((m) => m.type === "runCommand" && m.id === "pcapViewer.toggleMark");
    assert.equal(runs(), 3);
    await page.keyboard.press("Escape");
  });

  test("☰ does not squeeze the filter input on a narrow editor", async () => {
    try {
      for (const width of [320, 480, 800]) {
        await page.setViewportSize({ width, height: 600 });
        const box = await page.$eval("#filter-input", (i) => i.getBoundingClientRect().width);
        const menu = await page.$eval("#filter-menu", (m) => {
          const r = m.getBoundingClientRect();
          return { right: r.right, visible: r.width > 0 };
        });
        assert.ok(box >= Math.min(180, width - 80), `input ${box}px wide at ${width}px`);
        assert.ok(menu.visible && menu.right <= width, `☰ inside the window at ${width}px`);
        if (process.env.PCAP_SCREENSHOTS) {
          await page.screenshot({
            path: `${process.env.PCAP_SCREENSHOTS}/filter-bar-${width}.png`,
          });
        }
      }
    } finally {
      await page.setViewportSize({ width: 1200, height: 800 });
    }
  });

  test("filter buttons: hidden without any, apply on click, pressed state, add and edit", async () => {
    await cleanView();
    await post({ type: "filterButtons", buttons: [] });
    assert.equal(await page.isHidden("#filter-buttons"), true, "no buttons: no bar");

    await post({
      type: "filterButtons",
      buttons: [
        { label: "HTTP", filter: "http" },
        { label: "Handshake", filter: "tcp.flags.syn == 1", comment: "SYN and SYN/ACK" },
      ],
    });
    await page.waitForSelector("#filter-buttons button.filter-button");
    const bar = await page.$eval("#filter-buttons", (b) => ({
      role: b.getAttribute("role"),
      label: b.getAttribute("aria-label"),
      afterFilterBar: b.previousElementSibling?.id,
      buttons: [...b.querySelectorAll("button")].map((x) => ({
        text: x.textContent,
        title: x.title,
        pressed: x.getAttribute("aria-pressed"),
      })),
    }));
    assert.deepEqual(
      { role: bar.role, label: bar.label, after: bar.afterFilterBar },
      { role: "toolbar", label: "Filter buttons", after: "filter-bar" },
    );
    assert.deepEqual(bar.buttons, [
      { text: "HTTP", title: "http", pressed: "false" },
      { text: "Handshake", title: "SYN and SYN/ACK\ntcp.flags.syn == 1", pressed: "false" },
      {
        text: "+",
        title: "Add a filter button for the display filter in the filter bar…",
        pressed: null,
      },
    ]);

    // A click applies the button's filter and marks it.
    await page.click("#filter-buttons button:text-is('Handshake')");
    await page.waitForFunction(() =>
      /Displayed: 2\b/.test(document.querySelector("#status-left").textContent),
    );
    assert.equal(await page.inputValue("#filter-input"), "tcp.flags.syn == 1");
    await page.waitForFunction(
      () =>
        document
          .querySelector("#filter-buttons button[data-index='1']")
          .getAttribute("aria-pressed") === "true",
    );
    assert.equal(
      await page.getAttribute("#filter-buttons button[data-index='0']", "aria-pressed"),
      "false",
    );

    // "+" asks the host to add the filter bar's filter; right-click (or Shift+F10) edits.
    // (The value is set without typing: typing opens suggestions over the buttons.)
    await page.$eval("#filter-input", (input) => {
      /** @type {HTMLInputElement} */ (input).value = "dns";
    });
    await page.click("#filter-button-add");
    await waitForHost((m) => m.type === "addFilterButton");
    await expectHostLast(
      {
        type: "addFilterButton",
        filter: "dns",
      },
      { ofType: true },
    );
    await page.click("#filter-buttons button:text-is('HTTP')", { button: "right" });
    await waitForHost((m) => m.type === "editFilterButton");
    await page.focus("#filter-buttons button:text-is('Handshake')");
    await page.keyboard.press("Shift+F10");
    await waitForHost((m) => m.type === "editFilterButton" && m.index === 1);
    assert.deepEqual(
      hostLog.filter((m) => m.type === "editFilterButton").map((m) => [m.index, m.filter]),
      [
        [0, "http"],
        [1, "tcp.flags.syn == 1"],
      ],
    );
    if (process.env.PCAP_SCREENSHOTS) {
      await page.screenshot({ path: `${process.env.PCAP_SCREENSHOTS}/filter-buttons.png` });
    }

    // Clearing the filter releases the button; removing every button hides the bar.
    await cleanView();
    assert.equal(
      await page.getAttribute("#filter-buttons button[data-index='1']", "aria-pressed"),
      "false",
    );
    await post({ type: "filterButtons", buttons: [] });
    assert.equal(await page.isHidden("#filter-buttons"), true);
  });

  test("the busy bar goes away once a sort is done", async () => {
    await cleanView();
    // First sort by Info: the backend builds the order and reports progress.
    await page.click("#list-header > div[data-id='info']");
    await page.waitForFunction(() =>
      document.querySelector("#list-header > div[data-id='info'] .sort-indicator"),
    );
    await page.waitForFunction(
      () => document.querySelectorAll("#list-rows .list-row:not(.loading)").length === 11,
    );
    await page.waitForFunction(
      () => document.getElementById("busy-bar")?.classList.contains("hidden"),
      null,
      { timeout: 5000 },
    );
    await page.click("#list-header > div[data-id='info']");
    await page.click("#list-header > div[data-id='info']"); // sort off
    await page.waitForFunction(() =>
      document.getElementById("busy-bar")?.classList.contains("hidden"),
    );
  });

  test("the progress bar: indexing, indeterminate, resuming, done; with ARIA attributes", async () => {
    // The host's index events, posted by hand (the backend has the whole capture already).
    const info = await client.request(
      "open",
      { path: path.join(ROOT, "test", "fixtures", "http.pcap"), columns: ["tcp.stream"] },
      { timeoutMs: 0 },
    );
    const bar = () =>
      page.$eval("#busy-bar", (b) => ({
        hidden: b.classList.contains("hidden"),
        indeterminate: b.classList.contains("indeterminate"),
        secondary: b.classList.contains("secondary"),
        role: b.getAttribute("role"),
        min: b.getAttribute("aria-valuemin"),
        max: b.getAttribute("aria-valuemax"),
        now: b.getAttribute("aria-valuenow"),
        label: b.getAttribute("aria-label"),
        width: /** @type {HTMLElement} */ (b.querySelector(".progress-fill")).style.width,
        next: b.nextElementSibling?.id,
        afterFilterBar: !!(
          document.getElementById("filter-bar").compareDocumentPosition(b) &
          b.DOCUMENT_POSITION_FOLLOWING
        ),
      }));
    const status = () => page.textContent("#status-left");
    // A resumed open: 4 saved rows shown at once, the pass re-reads them first.
    await post({
      type: "init",
      info: { ...info, frames: 4, indexing: true, resumedAt: 4 },
      columns: customCols,
      layout,
      timeFormat: "relative",
      quickDetail: { after: 20000, window: 300 },
      filter: "",
      history: [],
      savedFilters,
      elapsedMs: 1,
      names: "Names: MAC",
    });
    await page.waitForFunction(() =>
      /Resuming/.test(document.getElementById("status-left").textContent),
    );
    let b = await bar();
    assert.equal(b.hidden, false);
    assert.equal(b.secondary, true, "a quieter bar while catching up");
    assert.equal(b.indeterminate, true, "no fraction yet");
    assert.equal(b.now, null, "no aria-valuenow while indeterminate");
    assert.deepEqual(
      [b.role, b.min, b.max, b.label],
      ["progressbar", "0", "100", "Resuming indexing"],
    );
    assert.deepEqual(
      [b.afterFilterBar, b.next],
      [true, "main"],
      "between the filter bar and the list",
    );
    assert.match(await status(), /Resuming… re-reading packets 1–4 \(already shown\)/);

    await post({
      type: "indexProgress",
      frames: 4,
      fraction: 0.2,
      phase: "catching-up",
      resumedAt: 4,
    });
    await page.waitForFunction(
      () => document.getElementById("busy-bar").getAttribute("aria-valuenow") === "20",
    );
    b = await bar();
    assert.deepEqual([b.secondary, b.indeterminate, b.width], [true, false, "20%"]);

    // Past the saved rows: a normal determinate bar that advances.
    await post({
      type: "indexProgress",
      frames: 6,
      fraction: 0.42,
      phase: "indexing",
      resumedAt: 4,
    });
    await page.waitForFunction(
      () => document.getElementById("busy-bar").getAttribute("aria-valuenow") === "42",
    );
    b = await bar();
    assert.deepEqual(
      [b.hidden, b.secondary, b.indeterminate, b.width, b.label],
      [false, false, false, "42%", "Indexing packets"],
    );
    assert.match(await status(), /Indexing… 42% · 6 packets/);
    await post({ type: "indexProgress", frames: 9, fraction: 0.8, phase: "indexing" });
    await page.waitForFunction(
      () => document.getElementById("busy-bar").getAttribute("aria-valuenow") === "80",
    );
    assert.equal((await bar()).width, "80%");

    // Progress that can't be estimated (a compressed capture): indeterminate.
    await post({ type: "indexProgress", frames: 10, fraction: null, phase: "indexing" });
    await page.waitForFunction(() =>
      document.getElementById("busy-bar").classList.contains("indeterminate"),
    );
    b = await bar();
    assert.deepEqual([b.hidden, b.now, b.width], [false, null, ""]);
    assert.match(await status(), /Indexing… 10 packets/);

    await post({ type: "indexDone", info });
    await page.waitForFunction(() =>
      document.getElementById("busy-bar").classList.contains("hidden"),
    );
    b = await bar();
    assert.deepEqual([b.indeterminate, b.secondary, b.now], [false, false, null]);
    await page.waitForFunction(
      () => document.querySelectorAll("#list-rows .list-row:not(.loading)").length === 11,
    );
    assert.doesNotMatch(await status(), /Indexing|Resuming/);
  });

  test("late packets: a quick view first, marked approximate, then the exact view replaces it", async () => {
    // Reload the capture (as the host does): the backend's detail cache starts empty.
    const reopen = async (quickDetail) => {
      const info = await client.request(
        "open",
        { path: path.join(ROOT, "test", "fixtures", "http.pcap"), columns: ["tcp.stream"] },
        { timeoutMs: 0 },
      );
      await post({
        type: "init",
        info,
        columns: customCols,
        layout,
        timeFormat: "relative",
        quickDetail,
        filter: "",
        history: [],
        savedFilters,
        elapsedMs: 1,
        names: "Names: MAC",
      });
      await page.waitForFunction(
        () => document.querySelectorAll("#list-rows .list-row:not(.loading)").length === 11,
      );
    };
    const note = () =>
      page.evaluate(() => {
        const n = document.getElementById("detail-note");
        return n?.classList.contains("hidden") ? "" : (n?.textContent ?? "");
      });
    const firstLabel = () =>
      page.evaluate(
        () => document.querySelector("#detail-tree .node-row .label")?.textContent ?? "",
      );
    await reopen({ after: 5, window: 3 });
    exactDetailDelayMs = 1500;
    detailRequests.length = 0;
    await rowEl(9).click();
    await page.waitForFunction(
      () => !document.getElementById("detail-note")?.classList.contains("hidden"),
    );
    assert.match(
      await note(),
      /^Quick view: only packets 7–9 were dissected, so reassembly, TCP analysis .* Loading the exact view$/,
    );
    assert.match(await firstLabel(), /^Frame 9:/);
    assert.deepEqual(detailRequests, [{ number: 9 }, { number: 9, mode: "quick", window: 3 }]);
    await page.waitForFunction(
      () => document.getElementById("detail-note")?.classList.contains("hidden"),
      null,
      { timeout: 5000 },
    );
    assert.match(await firstLabel(), /^Frame 9:/, "the exact view replaced it");

    // Early packets (up to pcapViewer.quickDetail.after) only get the exact view.
    exactDetailDelayMs = 0;
    detailRequests.length = 0;
    await rowEl(4).click();
    await page.waitForFunction(() =>
      /^Frame 4:/.test(document.querySelector("#detail-tree .node-row .label")?.textContent ?? ""),
    );
    assert.deepEqual(detailRequests, [{ number: 4 }]);
    // after = 0 turns quick views off.
    await post({ type: "quickDetail", quickDetail: { after: 0, window: 3 } });
    detailRequests.length = 0;
    await rowEl(10).click();
    await page.waitForFunction(() =>
      /^Frame 10:/.test(document.querySelector("#detail-tree .node-row .label")?.textContent ?? ""),
    );
    assert.deepEqual(detailRequests, [{ number: 10 }]);
    assert.equal(await note(), "");
    await reopen({ after: 20000, window: 300 });
  });

  test("streaming open and streaming filters on a big capture", async function () {
    this.timeout(180_000);
    const venv = path.join(
      ROOT,
      ".venv",
      process.platform === "win32" ? "Scripts/python.exe" : "bin/python",
    );
    const py = process.env.PCAP_VIEWER_PYTHON ?? venv;
    const big = path.join(os.tmpdir(), `pcapviewer-e2e-${process.pid}.pcap`);
    // Big enough that indexing and filtering take a few seconds (the small fixtures finish before the first batch).
    const gen = spawnSync(
      py,
      [path.join(ROOT, "test", "fixtures", "generate.py"), "--large", "150000", big],
      { encoding: "utf8" },
    );
    if (gen.status !== 0) {
      console.warn(
        `skipping streaming e2e: could not generate a capture (${gen.stderr || gen.error})`,
      );
      this.skip();
    }
    const status = () => page.textContent("#status-left");
    const notice = () => page.textContent("#filter-error");
    const stopButton = () => page.$eval("#filter-cancel", (b) => !b.classList.contains("hidden"));
    /** The first number after `label` (a regular expression) in the status bar. */
    const count = async (label) =>
      Number(new RegExp(`${label}([\\d,]+)`).exec(await status())?.[1].replace(/,/g, "") ?? NaN);
    /** Scroll to the end, so the last (short) page is cached, then wait for the list to grow past it. */
    const growsAtTheEnd = async (label) => {
      const before = await count(label);
      await page.evaluate(() => {
        const v = /** @type {HTMLElement} */ (document.getElementById("list-viewport"));
        v.scrollTop = v.scrollHeight;
      });
      await page.waitForFunction(
        ([label, before]) => {
          const m = new RegExp(`${label}([\\d,]+)`).exec(
            document.querySelector("#status-left")?.textContent ?? "",
          );
          return !!m && Number(m[1].replace(/,/g, "")) > before;
        },
        [label, before],
      );
    };
    /** Text of column `id` in the first loaded rows (columns may have been moved by earlier tests). */
    const column = (id, n = 5) =>
      page.evaluate(
        ([id, n]) => {
          const at = [...document.querySelectorAll("#list-header > div")].findIndex(
            (h) => /** @type {HTMLElement} */ (h).dataset.id === id,
          );
          return [...document.querySelectorAll("#list-rows .list-row:not(.loading)")]
            .slice(0, n)
            .map((r) => r.children[at]?.textContent ?? "");
        },
        [id, n],
      );
    const stop = client.onNotification("index", (p) => {
      void post(
        p.event === "progress"
          ? { type: "indexProgress", frames: p.frames, fraction: p.fraction ?? null, view: p.view }
          : {
              type: "indexDone",
              info: p.info,
              error: p.event === "failed" ? p.message : undefined,
              view: p.view,
            },
      );
    });
    try {
      // Coloring rules go with open: the index pass evaluates them, so rows come colored.
      const colorRules = [
        { name: "DNS", filter: "dns", foreground: "#12272e", background: "#c8e2ff" },
        { name: "TCP", filter: "tcp", foreground: "#000000", background: "#e7e6ff" },
      ];
      const coloring = {
        rules: colorRules.map(({ filter, foreground, background }) => ({
          filter,
          foreground,
          background,
        })),
      };
      const info = await client.request(
        "open",
        { path: big, stream: true, coloring, prefs: { "tcp.analyze_sequence_numbers": false } },
        { timeoutMs: 0 },
      );
      assert.equal(info.indexing, true);
      assert.ok(info.frames > 0 && info.frames < 150_000);
      assert.ok(info.coloring?.coloringId > 0, "colored by the index pass");
      await post({
        type: "init",
        info,
        columns: customCols,
        layout,
        timeFormat: "relative",
        quickDetail: { after: 20000, window: 300 },
        filter: "",
        history: [],
        savedFilters,
        elapsedMs: 1,
        names: "Names: MAC",
      });
      await post({
        type: "coloring",
        coloringId: info.coloring.coloringId,
        rules: colorRules.map(({ name, foreground, background }) => ({
          name,
          foreground,
          background,
        })),
      });
      await page.waitForFunction(() =>
        /^Indexing… (\d+% · )?[\d,]+ packets/.test(
          document.querySelector("#status-left")?.textContent ?? "",
        ),
      );
      await page.waitForFunction(
        () =>
          document.querySelector("#list-rows .list-row:not(.loading)")?.children[0]?.textContent ===
          "1",
      );
      await page.waitForFunction(
        () =>
          document.querySelector("#list-rows .list-row:not(.loading)")?.style.backgroundColor ===
          "rgb(200, 226, 255)",
      );
      assert.match(await status(), /^Indexing…/, "colored while still indexing");
      assert.doesNotMatch(await status(), /Coloring/, "no separate coloring pass");
      await growsAtTheEnd("Indexing… (?:\\d+% · )?");
      await page.evaluate(() => {
        /** @type {HTMLElement} */ (document.getElementById("list-viewport")).scrollTop = 0;
      });

      // A filter starts at once, over the packets indexed so far.
      await page.fill("#filter-input", "dns");
      await page.press("#filter-input", "Enter");
      await page.waitForFunction(() =>
        /^Indexing… .* · (Filtering… [\d,]+ matches so far|Displayed: [\d,]+)/.test(
          document.querySelector("#status-left")?.textContent ?? "",
        ),
      );
      await page.waitForFunction(
        () => document.querySelectorAll("#list-rows .list-row:not(.loading)").length > 0,
      );
      assert.deepEqual([...new Set(await column("protocol"))], ["DNS"]);
      await page.click("#list-header > div[data-id='length']");
      await page.waitForFunction(() =>
        /Sorting is available when indexing finishes/.test(
          document.getElementById("filter-error")?.textContent ?? "",
        ),
      );
      assert.equal(await page.$("#list-header .sort-indicator"), null, "not sorted");
      // When indexing is done, every match is shown.
      await page.waitForFunction(
        () =>
          /^Packets: 150,000 · Displayed: [\d,]+ \(33\.\d%\)/.test(
            document.querySelector("#status-left")?.textContent ?? "",
          ),
        null,
        { timeout: 120_000 },
      );
      assert.doesNotMatch(await status(), /Indexing|Filtering/);

      // A new filter streams its matches; ■ stops it and keeps what was found.
      await page.fill("#filter-input", "tcp");
      await page.press("#filter-input", "Enter");
      await page.waitForFunction(() =>
        /Filtering… [\d,]+ matches so far/.test(
          document.querySelector("#status-left")?.textContent ?? "",
        ),
      );
      await growsAtTheEnd("Filtering… ");
      assert.equal(await stopButton(), true);
      await page.click("#filter-cancel");
      await page.waitForFunction(() =>
        /^Filter stopped: showing the [\d,]+ matches found so far\.$/.test(
          document.getElementById("filter-error")?.textContent ?? "",
        ),
      );
      assert.match(await status(), /Displayed: [\d,]+ \([\d.]+%, filter stopped early\)/);
      assert.equal(await stopButton(), false);
      const stoppedAt = Number(/Displayed: ([\d,]+)/.exec(await status())?.[1].replace(/,/g, ""));
      assert.ok(stoppedAt > 0 && stoppedAt < 100_000, `stopped at ${stoppedAt}`);

      // Sorting while a filter runs applies when it's done.
      await page.fill("#filter-input", "tcp");
      await page.press("#filter-input", "Enter");
      await page.waitForFunction(() =>
        /Filtering…/.test(document.querySelector("#status-left")?.textContent ?? ""),
      );
      await page.click("#list-header > div[data-id='length']");
      assert.match(await notice(), /The list is sorted when the filter finishes/);
      await page.waitForFunction(
        () =>
          /^Packets: 150,000 · Displayed: [\d,]+ \(66\.\d%\)/.test(
            document.querySelector("#status-left")?.textContent ?? "",
          ),
        null,
        { timeout: 60_000 },
      );
      await page.waitForFunction(
        () =>
          document.querySelector("#list-rows .list-row:not(.loading)")?.children[0]?.textContent !==
          "2",
      );
      const lengths = (await column("length")).map(Number);
      assert.deepEqual(
        lengths,
        [...lengths].sort((a, b) => a - b),
        `sorted by length: ${lengths}`,
      );
      await page.click("#list-header > div[data-id='length']");
      await page.click("#list-header > div[data-id='length']"); // back to capture order
    } finally {
      stop();
      // Windows can't delete a file that is open: close the capture first (closing
      // cancels its passes and waits for them), then retry while a last tshark exits.
      await client.request("close", {}).catch(() => undefined);
      fs.rmSync(big, { force: true, maxRetries: 20, retryDelay: 250 });
    }
    // Back to the small capture for the other tests.
    const info = await client.request(
      "open",
      { path: path.join(ROOT, "test", "fixtures", "http.pcap"), columns: ["tcp.stream"] },
      { timeoutMs: 0 },
    );
    await post({
      type: "init",
      info,
      columns: customCols,
      layout,
      timeFormat: "relative",
      quickDetail: { after: 20000, window: 300 },
      filter: "",
      history: [],
      savedFilters,
      elapsedMs: 1,
      names: "Names: MAC",
    });
    await page.fill("#filter-input", "");
    await page.waitForFunction(
      () => document.querySelectorAll("#list-rows .list-row:not(.loading)").length === 11,
    );
  });

  test("name resolution: status link, addresses as tooltips and in cell filters", async () => {
    await cleanView();
    assert.equal(await page.textContent("#status-names"), "Names: MAC");
    await page.click("#status-names");
    await expectHostLast({ type: "pickNameResolution" });
    const names = { mac: true, network: true, capturedDns: true, transport: true };
    try {
      await reopenCapture("mixed.pcapng", { names }, "Names: MAC, network (capture), ports");
      assert.equal(await page.textContent("#status-names"), "Names: MAC, network (capture), ports");
      const source = rowEl(11).locator("div").nth(2);
      assert.equal(await source.textContent(), "example.com");
      assert.equal(await source.getAttribute("title"), "93.184.216.34");
      assert.ok(
        !(await rowEl(12).locator("div").nth(2).getAttribute("title")),
        "an address: no tooltip",
      );
      await source.click({ button: "right" });
      await page.click("#context-menu .item:text-is('Prepare as Filter')");
      assert.equal(await page.inputValue("#filter-input"), "ip.src == 93.184.216.34");
      const broadcast = rowEl(1).locator("div").nth(3);
      assert.equal(await broadcast.textContent(), "Broadcast");
      await broadcast.click({ button: "right" });
      await page.click("#context-menu .item:text-is('Prepare as Filter')");
      assert.equal(await page.inputValue("#filter-input"), "eth.dst == ff:ff:ff:ff:ff:ff");
    } finally {
      await page.fill("#filter-input", "");
      await reopenCapture("http.pcap");
    }
  });

  test("packet comments: row stripe and tooltip, comment bar, edit, delete, add", async () => {
    await cleanView();
    try {
      await reopenCapture("comments.pcapng");
      await page.waitForFunction(() =>
        document.querySelectorAll("#list-rows .list-row")[1]?.classList.contains("has-comment"),
      );
      assert.equal(
        await rowEl(2).locator("div").nth(0).getAttribute("title"),
        "SYN-ACK from the server",
      );
      assert.ok(!(await rowEl(1).getAttribute("class")).includes("has-comment"));

      await rowEl(4).click();
      await page.waitForFunction(
        () => !document.querySelector("#comment-bar").classList.contains("hidden"),
      );
      assert.equal(
        await page.textContent("#comment-text"),
        "The request\nsecond line\twith a tab",
        "multi-line, shown as is",
      );
      assert.ok(await page.isHidden("#comment-edited"));

      await page.click("#comment-edit");
      assert.equal(await page.inputValue("#comment-input"), "The request\nsecond line\twith a tab");
      await page.fill("#comment-input", "edited request");
      await page.press("#comment-input", "Control+Enter");
      await expectHostLast({ type: "setComment", frame: 4, text: "edited request" });
      await page.waitForFunction(
        () => document.querySelector("#comment-text").textContent === "edited request",
      );
      assert.ok(await page.isVisible("#comment-edited"), "unsaved");
      await page.waitForFunction(() =>
        document.querySelectorAll("#list-rows .list-row")[3]?.classList.contains("comment-edited"),
      );

      await page.click("#comment-delete");
      await expectHostLast({ type: "setComment", frame: 4, text: "" });
      await page.waitForFunction(
        () => document.querySelector("#comment-text").textContent === "(comment deleted)",
      );

      // Add one from the row menu; Esc cancels, Apply adds.
      await rowEl(1).click({ button: "right" });
      await page.click("#context-menu .item:text-is('Add Packet Comment…')");
      await page.waitForFunction(() => document.activeElement?.id === "comment-input");
      await page.keyboard.press("Escape");
      assert.ok(await page.isHidden("#comment-editor"));
      await post({ type: "command", command: "editPacketComment" }); // Ctrl+Alt+C
      await page.waitForFunction(() => document.activeElement?.id === "comment-input");
      await page.keyboard.type("first packet");
      await page.click("#comment-apply");
      await expectHostLast({ type: "setComment", frame: 1, text: "first packet" });
      await page.waitForFunction(() =>
        document.querySelectorAll("#list-rows .list-row")[0]?.classList.contains("has-comment"),
      );
      assert.equal(await rowEl(1).locator("div").nth(0).getAttribute("title"), "first packet");
    } finally {
      for (const key of Object.keys(commentEdits)) {
        delete commentEdits[key];
      }
      await reopenCapture("http.pcap");
    }
  });

  test("live capture: the status bar shows it, the list follows new packets, Stop", async () => {
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "pcapviewer-e2e-capture-"));
    // Like PcapEditorSession: "index" and "capture" notifications go to the viewer.
    const stopIndex = client.onNotification("index", (p) =>
      post(
        p.event === "progress"
          ? { type: "indexProgress", frames: p.frames, fraction: p.fraction ?? null, view: p.view }
          : {
              type: "indexDone",
              info: p.info,
              error: p.event === "failed" ? p.message : undefined,
              view: p.view,
            },
      ),
    );
    const stopCapture = client.onNotification("capture", (p) =>
      post({ type: "captureEvent", ...p }),
    );
    try {
      await page.setViewportSize({ width: 1200, height: 500 }); // (so the list must scroll)
      const info = await client.request(
        "capture_start",
        { dest: path.join(tmp, "live.pcapng"), interfaces: ["fake0"], columns: ["tcp.stream"] },
        { timeoutMs: 0 },
      );
      assert.equal(info.capture.running, true);
      await post({
        type: "init",
        info,
        columns: customCols,
        layout,
        timeFormat: "relative",
        quickDetail: { after: 20000, window: 300 },
        filter: "",
        history: [],
        savedFilters,
        elapsedMs: 1,
        names: "Names: MAC",
      });
      await page.waitForSelector("#status-capture:not(.hidden)");
      assert.match(await page.textContent("#capture-text"), /^Capturing on fake0 · 0:0\d · /);
      assert.ok(await page.isVisible("#capture-stop"));
      await page.waitForFunction(() =>
        /Packets: ([2-9]\d|1[5-9])/.test(document.querySelector("#status-left").textContent),
      );
      assert.doesNotMatch(await page.textContent("#status-left"), /Indexing/);
      // The end of the list was in view: it stays in view as packets arrive.
      const atEnd = () =>
        page.$eval(
          "#list-viewport",
          (v) => v.scrollTop > 0 && v.scrollTop + v.clientHeight >= v.scrollHeight - 30,
        );
      await page.waitForFunction(() => {
        const v = document.getElementById("list-viewport");
        return v.scrollTop > 0 && v.scrollTop + v.clientHeight >= v.scrollHeight - 30;
      });
      assert.ok(await atEnd());
      await page.waitForFunction(
        () => document.querySelectorAll("#list-rows .list-row:not(.loading)").length > 0,
      );
      // Sorting waits for the end of the capture.
      await page.click('#list-header > div[data-id="length"]');
      assert.match(await page.textContent("#filter-error"), /when the capture stops/);
      await page.click("#capture-stop");
      await waitForHost((m) => m.type === "stopCapture");
      await page.waitForFunction(() =>
        document.querySelector("#status-capture").classList.contains("stopped"),
      );
      assert.match(await page.textContent("#capture-text"), /^Captured on fake0 in 0:0\d/);
      assert.equal(await page.isVisible("#capture-stop"), false);
      await page.waitForFunction(() =>
        /^Packets: \d+$/.test(document.querySelector("#status-left").textContent.split(" · ")[0]),
      );
    } finally {
      stopIndex();
      stopCapture();
      await page.setViewportSize({ width: 1200, height: 800 });
      await reopenCapture("http.pcap");
    }
    assert.equal(await page.isVisible("#status-capture"), false, "a plain file: no capture");
  });

  test("no script errors or CSP violations", () => {
    assert.deepEqual(pageErrors, []);
    assert.deepEqual(cspViolations, []);
  });
});
