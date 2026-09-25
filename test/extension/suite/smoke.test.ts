/**
 * Smoke test inside a real VS Code instance: open a fixture capture with the
 * custom editor and check that the backend indexed it and answers requests.
 */
import * as assert from "node:assert/strict";
import * as path from "node:path";
import * as vscode from "vscode";
import type { PcapViewerApi } from "../../../src/extension";

const FIXTURES = path.resolve(__dirname, "../../../../test/fixtures");

async function waitFor<T>(fn: () => T | undefined, timeoutMs = 30_000): Promise<T> {
  const start = Date.now();
  for (;;) {
    const value = fn();
    if (value !== undefined) {
      return value;
    }
    if (Date.now() - start > timeoutMs) {
      throw new Error("timed out waiting for condition");
    }
    await new Promise((r) => setTimeout(r, 100));
  }
}

suite("PCAP Viewer smoke test", () => {
  test("opens a capture and the backend responds", async () => {
    const ext = vscode.extensions.all.find((e) => e.packageJSON.name === "pcap-viewer");
    assert.ok(ext, "extension is installed");
    const api = (await ext.activate()) as PcapViewerApi;

    const uri = vscode.Uri.file(path.join(FIXTURES, "http.pcap"));
    await vscode.commands.executeCommand("vscode.openWith", uri, "pcapViewer.editor");

    const session = await waitFor(() => api.provider.allSessions.find((s) => s.uri.fsPath === uri.fsPath));
    const info = await waitFor(() => session.openInfo);
    assert.equal(info.frames, 11);

    const backend = session.backend;
    assert.ok(backend?.running);
    const page = await backend.request<{ rows: { number: number }[] }>("list_packets", { offset: 0, limit: 5 });
    assert.equal(page.rows.length, 5);
    const detail = await backend.request<{ tree: unknown[] }>("packet_detail", { number: 4 });
    assert.ok(detail.tree.length > 0);

    // Closing the editor must stop the backend process.
    await vscode.commands.executeCommand("workbench.action.closeAllEditors");
    await waitFor(() => (backend.running ? undefined : true), 10_000);
  });
});
