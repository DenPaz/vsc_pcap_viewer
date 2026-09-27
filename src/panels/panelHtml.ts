import * as crypto from "node:crypto";
import * as vscode from "vscode";

/** Folder holding the webview assets (shared by the editor and the panels). */
export function webviewRoot(context: vscode.ExtensionContext): vscode.Uri {
  return vscode.Uri.joinPath(context.extensionUri, "src", "webview");
}

/**
 * HTML shell for an auxiliary panel (statistics, follow stream): the same
 * strict CSP as the editor, the shared stylesheet, `lib.js`, and one script.
 */
export function panelHtml(
  webview: vscode.Webview,
  root: vscode.Uri,
  script: string,
  title: string,
): string {
  const nonce = crypto.randomBytes(16).toString("base64");
  const uri = (name: string) => webview.asWebviewUri(vscode.Uri.joinPath(root, name)).toString();
  const csp = [
    "default-src 'none'",
    `img-src ${webview.cspSource} data:`,
    `style-src ${webview.cspSource}`,
    `font-src ${webview.cspSource}`,
    `script-src 'nonce-${nonce}'`,
  ].join("; ");
  const esc = (s: string) => s.replace(/[&<>"]/g, (c) => `&#${c.charCodeAt(0)};`);
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta http-equiv="Content-Security-Policy" content="${csp}">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <link rel="stylesheet" href="${uri("styles.css")}">
  <link rel="stylesheet" href="${uri("panel.css")}">
  <title>${esc(title)}</title>
</head>
<body class="panel">
  <div id="app"></div>
  <script nonce="${nonce}" src="${uri("lib.js")}"></script>
  <script nonce="${nonce}" src="${uri(script)}"></script>
</body>
</html>`;
}
