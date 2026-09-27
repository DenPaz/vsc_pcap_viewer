import * as vscode from "vscode";
import { BackendClient, findPython } from "../backendClient";
import { readSettings } from "../config";
import type { PcapEditorProvider } from "../pcapEditor";

/**
 * Run `fn` with a backend: the active capture's, or a short-lived one when no
 * capture is open (merging needs no open capture, only tshark's tools).
 */
export async function withBackend<T>(
  provider: PcapEditorProvider,
  context: vscode.ExtensionContext,
  log: vscode.LogOutputChannel,
  fn: (b: BackendClient) => Promise<T>,
): Promise<T> {
  const active = provider.activeSession?.backend;
  if (active?.running) {
    return fn(active);
  }
  const settings = readSettings();
  const py = findPython(settings.pythonPath || undefined);
  if ("error" in py) {
    throw new Error(py.error);
  }
  const client = new BackendClient({
    python: py.python,
    backendDir: vscode.Uri.joinPath(context.extensionUri, "backend").fsPath,
    logger: { info: (m) => log.info(m), warn: (m) => log.warn(m), error: (m) => log.error(m) },
  });
  try {
    client.start();
    await client.request(
      "initialize",
      { tsharkPath: settings.tsharkPath || undefined },
      { timeoutMs: 30_000 },
    );
    return await fn(client);
  } finally {
    await client.dispose();
  }
}
