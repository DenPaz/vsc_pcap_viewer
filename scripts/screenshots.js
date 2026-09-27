/**
 * Screenshots for the README and the Marketplace page (media/screenshots/):
 * the real webview pages in Chromium with VS Code's Dark Modern colors,
 * driven by the real backend and tshark on media/sample.pcapng, like the
 * Chromium tests (test/webview/harness.js). Needs `pnpm run compile` first.
 * Set CHROMIUM_PATH to use another Chromium build.
 *
 *   node scripts/screenshots.js
 */
const fs = require("node:fs");
const path = require("node:path");
const {
  ROOT,
  loadDeps,
  serveWebview,
  renderEditorHtml,
  renderPanelHtml,
  startBackend,
} = require("../test/webview/harness");

const OUT = path.join(ROOT, "media", "screenshots");
const SAMPLE = path.join(ROOT, "media", "sample.pcapng");
const VIEWPORT = { width: 1280, height: 760 };

/** VS Code's Dark Modern theme, for the variables the webviews use. */
const DARK_MODERN = {
  "font-family": "system-ui, 'Segoe UI', Ubuntu, 'Droid Sans', sans-serif",
  "font-size": "13px",
  "editor-font-family": "Consolas, 'DejaVu Sans Mono', 'Courier New', monospace",
  "editor-font-size": "13px",
  foreground: "#cccccc",
  descriptionForeground: "#9d9d9d",
  errorForeground: "#f85149",
  focusBorder: "#0078d4",
  "icon-foreground": "#cccccc",
  "widget-border": "#313131",
  "widget-shadow": "rgba(0, 0, 0, 0.36)",
  "sash-hoverBorder": "#0078d4",
  "textLink-foreground": "#4daafc",
  "textPreformat-foreground": "#d0d0d0",
  "textBlockQuote-background": "#2b2b2b",
  "editor-background": "#1f1f1f",
  "editor-foreground": "#cccccc",
  "editor-selectionBackground": "#264f78",
  "editor-selectionForeground": "#ffffff",
  "editor-inactiveSelectionBackground": "#3a3d41",
  "editorLineNumber-foreground": "#6e7681",
  "editorWidget-background": "#202020",
  "editorWidget-border": "#313131",
  "editorWarning-foreground": "#cca700",
  "editorInfo-foreground": "#3794ff",
  "editorHoverWidget-background": "#202020",
  "editorHoverWidget-foreground": "#cccccc",
  "editorHoverWidget-border": "#454545",
  "editorSuggestWidget-background": "#202020",
  "editorSuggestWidget-foreground": "#cccccc",
  "editorSuggestWidget-border": "#454545",
  "editorSuggestWidget-highlightForeground": "#2aaaff",
  "editorGroupHeader-tabsBackground": "#181818",
  "input-background": "#313131",
  "input-foreground": "#cccccc",
  "input-border": "#3c3c3c",
  "inputValidation-errorBackground": "#5a1d1d",
  "inputValidation-errorForeground": "#cccccc",
  "inputValidation-errorBorder": "#be1100",
  "dropdown-background": "#313131",
  "dropdown-foreground": "#cccccc",
  "dropdown-border": "#3c3c3c",
  "button-background": "#0078d4",
  "button-foreground": "#ffffff",
  "button-hoverBackground": "#026ec1",
  "button-border": "rgba(255, 255, 255, 0.07)",
  "button-secondaryBackground": "#313131",
  "button-secondaryForeground": "#cccccc",
  "button-secondaryHoverBackground": "#3c3c3c",
  "list-hoverBackground": "#2a2d2e",
  "list-activeSelectionBackground": "#04395e",
  "list-activeSelectionForeground": "#ffffff",
  "list-inactiveSelectionBackground": "#37373d",
  "list-inactiveSelectionForeground": "#cccccc",
  "list-focusOutline": "#0078d4",
  "menu-background": "#1f1f1f",
  "menu-foreground": "#cccccc",
  "menu-border": "#454545",
  "menu-selectionBackground": "#0078d4",
  "menu-selectionForeground": "#ffffff",
  "menu-separatorBackground": "#454545",
  "tab-activeBackground": "#1f1f1f",
  "tab-activeForeground": "#ffffff",
  "tab-inactiveBackground": "#181818",
  "tab-inactiveForeground": "#9d9d9d",
  "toolbar-hoverBackground": "rgba(90, 93, 94, 0.31)",
  "toolbar-activeBackground": "rgba(99, 102, 103, 0.31)",
  "panel-border": "#2b2b2b",
  "progressBar-background": "#0078d4",
  "charts-blue": "#3794ff",
  "charts-red": "#f14c4c",
  "testing-iconPassed": "#73c991",
};

/** Apply the theme the way VS Code does (variables on <html>, a class on <body>). */
function applyTheme(page) {
  return page.evaluate((vars) => {
    for (const [k, v] of Object.entries(vars)) {
      document.documentElement.style.setProperty(`--vscode-${k}`, v);
    }
    document.body.classList.add("vscode-dark");
  }, DARK_MODERN);
}

/** Forward the webview's rpc messages to the backend (see src/pcapEditor.ts). */
function forwardRpc(client, post, msg) {
  client.request(msg.method, msg.params, { timeoutMs: 0 }).then(
    (result) => post({ type: "rpcResult", id: msg.id, result }),
    (err) =>
      post({ type: "rpcError", id: msg.id, error: { code: err.code, message: err.message } }),
  );
}

async function editorPage(browser, origin, client, rules) {
  const page = await browser.newPage({ viewport: VIEWPORT });
  // (answers can still arrive after the page closed)
  const post = (m) => page.evaluate((x) => window.postMessage(x, "*"), m).catch(() => undefined);
  await page.exposeFunction("__toHost", async (raw) => {
    const msg = JSON.parse(raw);
    if (msg.type === "ready") {
      const info = await client.request(
        "open",
        {
          path: SAMPLE,
          coloring: {
            rules: rules.map((r) => ({
              filter: r.filter,
              foreground: r.foreground,
              background: r.background,
            })),
          },
        },
        { timeoutMs: 0 },
      );
      await post({
        type: "init",
        info,
        columns: [],
        layout: { order: [], hidden: [] },
        timeFormat: "relative",
        quickDetail: { after: 20000, window: 300 },
        filter: "",
        history: ["tcp.port == 80", "dns.flags.rcode != 0"],
        savedFilters: [{ name: "Web", filter: "http || tls" }],
        elapsedMs: 40,
        names: "Names: off",
      });
      await post({ type: "coloring", coloringId: info.coloring.coloringId, rules });
    } else if (msg.type === "rpc") {
      forwardRpc(client, post, msg);
    }
  });
  await page.setContent(renderEditorHtml(origin), { waitUntil: "load" });
  await applyTheme(page);
  await page.waitForSelector("#overlay.hidden", { state: "attached" });
  await page.waitForSelector("#list-rows .list-row");
  return page;
}

async function main() {
  const deps = loadDeps();
  if (!deps) {
    throw new Error("run `pnpm run compile` first (and install playwright-core)");
  }
  fs.mkdirSync(OUT, { recursive: true });
  const pkg = JSON.parse(fs.readFileSync(path.join(ROOT, "package.json"), "utf8"));
  const rules = pkg.contributes.configuration.properties["pcapViewer.coloringRules"].default;
  const server = await serveWebview();
  const origin = `http://127.0.0.1:${server.address().port}`;
  const client = await startBackend(deps);
  const browser = await deps.chromium.launch(
    process.env.CHROMIUM_PATH ? { executablePath: process.env.CHROMIUM_PATH } : {},
  );
  try {
    // 1. The viewer: an HTTP response reassembled from two segments, its tree open.
    let page = await editorPage(browser, origin, client, rules);
    await page.click("#list-rows .list-row >> nth=15");
    await page.waitForSelector("#detail-tree .node-row:has-text('Hypertext Transfer Protocol')");
    await page.click("#detail-tree .node-row:has-text('Hypertext Transfer Protocol') .twisty");
    await page.click("#detail-tree .node-row:has-text('Content-Type')");
    await page.screenshot({ path: path.join(OUT, "viewer.png") });

    // 2. Filter autocomplete from tshark's field list.
    await page.click("#filter-input");
    await page.keyboard.type("dns.flags.r", { delay: 20 });
    await page.waitForSelector("#suggest:not(.hidden) .suggest-item");
    await page.screenshot({ path: path.join(OUT, "filter.png") });
    await page.close();

    // 3. Protocol hierarchy statistics.
    page = await browser.newPage({ viewport: { width: 1000, height: 380 } });
    // (answers can still arrive after the page closed)
    const post = (m) => page.evaluate((x) => window.postMessage(x, "*"), m).catch(() => undefined);
    await page.exposeFunction("__toHost", async (raw) => {
      const msg = JSON.parse(raw);
      if (msg.type === "ready") {
        await post({ type: "init", kind: "phs", title: "Protocol Hierarchy", filter: "" });
      } else if (msg.type === "query") {
        const table = await client.request("stats", { kind: "phs", filter: "" });
        await post({ type: "result", id: msg.id, table });
      }
    });
    await page.setContent(renderPanelHtml(origin, "stats.js"), { waitUntil: "load" });
    await applyTheme(page);
    await page.waitForSelector("table.stats tbody tr");
    await page.screenshot({ path: path.join(OUT, "statistics.png") });
  } finally {
    await browser.close();
    await client.dispose();
    server.close();
  }
  console.log(`screenshots written to ${path.relative(ROOT, OUT)}`);
}

main().catch((err) => {
  console.error(err);
  process.exitCode = 1;
});
