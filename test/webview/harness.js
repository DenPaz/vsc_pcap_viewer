/**
 * Shared scaffolding for the Chromium end-to-end tests: serves src/webview
 * over HTTP (so the page CSP can allow it as `cspSource`), renders the editor
 * and panel pages exactly like the extension does, stubs acquireVsCodeApi,
 * and starts the real Python backend.
 */
const crypto = require("node:crypto");
const fs = require("node:fs");
const http = require("node:http");
const path = require("node:path");
const { spawnSync } = require("node:child_process");

const ROOT = path.resolve(__dirname, "../..");
const WEBVIEW = path.join(ROOT, "src", "webview");
const FIXTURES = path.join(ROOT, "test", "fixtures");
const HAVE_TSHARK = spawnSync("tshark", ["--version"]).status === 0;

/** playwright-core + the compiled BackendClient, or null when unavailable. */
function loadDeps() {
  try {
    const { chromium } = require("playwright-core");
    const { BackendClient, findPython } = require(path.join(ROOT, "out", "src", "backendClient.js"));
    return { chromium, BackendClient, findPython };
  } catch {
    return null;
  }
}

function serveWebview() {
  const types = { ".js": "text/javascript", ".css": "text/css" };
  const server = http.createServer((req, res) => {
    const file = path.join(WEBVIEW, path.basename(new URL(req.url, "http://x").pathname));
    if (!file.startsWith(WEBVIEW) || !fs.existsSync(file)) {
      res.writeHead(404).end();
      return;
    }
    res.writeHead(200, { "content-type": types[path.extname(file)] || "application/octet-stream" });
    fs.createReadStream(file).pipe(res);
  });
  return new Promise((resolve) => server.listen(0, "127.0.0.1", () => resolve(server)));
}

/** Stand-in for VS Code's acquireVsCodeApi, bridged to `window.__toHost` (page.exposeFunction). */
function stubScript(nonce) {
  return `<script nonce="${nonce}">
    window.acquireVsCodeApi = () => ({
      postMessage: (m) => window.__toHost(JSON.stringify(m)),
      getState: () => undefined,
      setState: () => undefined,
    });
  </script>`;
}

/** The capture editor page (src/webview/index.html), as pcapEditor.ts renders it. */
function renderEditorHtml(origin) {
  const nonce = crypto.randomBytes(16).toString("base64");
  const values = { cspSource: origin, nonce, stylesUri: `${origin}/styles.css`, libUri: `${origin}/lib.js`, mainUri: `${origin}/main.js` };
  return fs
    .readFileSync(path.join(WEBVIEW, "index.html"), "utf8")
    .replace(/\{\{(\w+)\}\}/g, (_m, k) => values[k])
    .replace("<script", `${stubScript(nonce)}\n  <script`);
}

/** A statistics / follow panel page, mirroring src/panels/panelHtml.ts. */
function renderPanelHtml(origin, script) {
  const nonce = crypto.randomBytes(16).toString("base64");
  const csp = `default-src 'none'; img-src ${origin} data:; style-src ${origin}; font-src ${origin}; script-src 'nonce-${nonce}'`;
  return `<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8">
  <meta http-equiv="Content-Security-Policy" content="${csp}">
  <link rel="stylesheet" href="${origin}/styles.css"><link rel="stylesheet" href="${origin}/panel.css">
  </head><body class="panel"><div id="app"></div>
  ${stubScript(nonce)}
  <script nonce="${nonce}" src="${origin}/lib.js"></script>
  <script nonce="${nonce}" src="${origin}/${script}"></script>
  </body></html>`;
}

/** Start the backend with PCAP_VIEWER_PYTHON, else the uv .venv interpreter. */
async function startBackend(deps) {
  const venv = path.join(ROOT, ".venv", process.platform === "win32" ? "Scripts/python.exe" : "bin/python");
  const py = deps.findPython(process.env.PCAP_VIEWER_PYTHON ?? (fs.existsSync(venv) ? venv : undefined));
  if ("error" in py) {
    throw new Error(py.error);
  }
  const client = new deps.BackendClient({
    python: py.python,
    backendDir: path.join(ROOT, "backend"),
    logger: { info() {}, warn() {}, error: (m) => console.error(m) },
  });
  client.start();
  await client.request("initialize", {});
  return client;
}

/** A page that records script errors and CSP violations. */
async function newPage(browser) {
  const page = await browser.newPage({ viewport: { width: 1200, height: 800 } });
  const problems = { errors: [], csp: [] };
  page.on("pageerror", (err) => problems.errors.push(err.message));
  page.on("console", (m) => {
    if (/Content Security Policy/i.test(m.text())) {
      problems.csp.push(m.text());
    }
  });
  const post = (msg) => page.evaluate((m) => window.postMessage(m, "*"), msg);
  return { page, problems, post };
}

module.exports = { ROOT, WEBVIEW, FIXTURES, HAVE_TSHARK, loadDeps, serveWebview, renderEditorHtml, renderPanelHtml, startBackend, newPage };
