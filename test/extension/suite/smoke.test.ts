/**
 * Smoke test inside a real VS Code instance: open a fixture capture with the
 * custom editor and check that the backend indexed it and answers requests.
 */
import * as assert from "node:assert/strict";
import * as path from "node:path";
import * as vscode from "vscode";
import type { PcapViewerApi } from "../../../src/extension";
// Same module instances as the extension's (both load out/src/panels/*.js).
import { FollowPanel } from "../../../src/panels/followPanel";
import { StatsPanel } from "../../../src/panels/statsPanel";

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

async function waitForAsync<T>(fn: () => Promise<T | undefined>, timeoutMs = 30_000): Promise<T> {
  const start = Date.now();
  for (;;) {
    const value = await fn();
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

    // The default coloring rules are applied in the background after open.
    const colored = await waitForAsync(async () => {
      const rows = await backend.request<{ rows: { color?: number }[]; coloringId: number }>("list_packets", { offset: 0, limit: 11 });
      return rows.coloringId > 0 ? rows : undefined;
    });
    assert.ok(colored.rows.every((r) => typeof r.color === "number"), "every packet of http.pcap matches a default rule");

    const commands = await vscode.commands.getCommands(true);
    for (const id of [
      "pcapViewer.reloadDissectors",
      "pcapViewer.newLuaDissector",
      "pcapViewer.openDissectorsFolder",
      "pcapViewer.decodeAs",
      "pcapViewer.manageDecodeAs",
      "pcapViewer.exportFiltered",
      "pcapViewer.exportPacketList",
      "pcapViewer.exportPacketBytes",
      "pcapViewer.colorizeWithFilter",
      "pcapViewer.toggleColoring",
      "pcapViewer.manageColoringRules",
    ]) {
      assert.ok(commands.includes(id), `${id} is registered`);
    }

    // Follow stream and statistics panels talk to the same backend.
    await vscode.commands.executeCommand("pcapViewer.followTcpStream", 4);
    const follow = await waitFor(() => [...FollowPanel.panels][0]?.current);
    assert.equal(follow.stream, 0);
    assert.deepEqual(follow.bytes, [90, 491]);
    session.reveal();
    await vscode.commands.executeCommand("pcapViewer.statistics.conversations");
    const stats = await waitFor(() => StatsPanel.all.find((p) => p.kind === "conversations" && p.session === session));

    // With a second capture focused, focusing the first capture's panel must
    // make the first capture the target of capture commands again.
    const other = vscode.Uri.file(path.join(FIXTURES, "dns.pcap"));
    await vscode.commands.executeCommand("vscode.openWith", other, "pcapViewer.editor");
    await waitFor(() => (api.provider.activeSession?.uri.fsPath === other.fsPath ? true : undefined));
    stats.panel.reveal(undefined, false);
    await waitFor(() => (api.provider.activeSession === session ? true : undefined));

    // Closing the editor must stop the backend process (and close its panels).
    await vscode.commands.executeCommand("workbench.action.closeAllEditors");
    await waitFor(() => (backend.running ? undefined : true), 10_000);
  });
});
