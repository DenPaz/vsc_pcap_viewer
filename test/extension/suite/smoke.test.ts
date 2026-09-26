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
      "pcapViewer.suggestFilter",
      "pcapViewer.find",
      "pcapViewer.findNext",
      "pcapViewer.findPrevious",
      "pcapViewer.goBack",
      "pcapViewer.goForward",
      "pcapViewer.nextInConversation",
      "pcapViewer.previousInConversation",
      "pcapViewer.firstPacket",
      "pcapViewer.lastPacket",
      "pcapViewer.toggleMark",
      "pcapViewer.nextMark",
      "pcapViewer.previousMark",
      "pcapViewer.unmarkAll",
      "pcapViewer.exportMarked",
      "pcapViewer.toggleTimeReference",
      "pcapViewer.timeFormat",
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

  test("file types: capture files open in the viewer, generic extensions only on request", async () => {
    const ext = vscode.extensions.all.find((e) => e.packageJSON.name === "pcap-viewer");
    const api = (await ext!.activate()) as PcapViewerApi;
    const formats = path.join(FIXTURES, "formats");
    // What VS Code itself resolved for a plain "open" (this checks the selector globs).
    const openedAs = async (name: string): Promise<string> => {
      const uri = vscode.Uri.file(path.join(formats, name));
      await vscode.commands.executeCommand("vscode.open", uri);
      const input = await waitFor(() => {
        const i = vscode.window.tabGroups.activeTabGroup.activeTab?.input as { uri?: vscode.Uri } | undefined;
        return i?.uri?.fsPath === uri.fsPath ? i : undefined;
      });
      return input instanceof vscode.TabInputCustom ? input.viewType : "other";
    };

    const defaults = ["http.pcap.gz", "mixed.pcapng.gz", "http.pcap.zst", "mixed.pcapng.zst", "http.pcap.lz4", "mixed.pcapng.lz4",
      "mixed.ntar", "trace.pcap1", "http.snoop", "http.erf", "hci.pklg", "hci.btsnoop"];
    for (const name of defaults) {
      assert.equal(await openedAs(name), "pcapViewer.editor", name);
      await vscode.commands.executeCommand("workbench.action.closeActiveEditor");
    }
    for (const name of ["capture.1", "capture.log", "capture.dmp", "capture.trc", "capture.ber", "notes.log"]) {
      assert.equal(await openedAs(name), "other", `${name} must not open in the viewer by default`);
      await vscode.commands.executeCommand("workbench.action.closeActiveEditor");
    }

    // A compressed capture is indexed like any other.
    const gz = vscode.Uri.file(path.join(formats, "http.pcap.gz"));
    await vscode.commands.executeCommand("vscode.open", gz);
    const gzSession = await waitFor(() => api.provider.allSessions.find((s) => s.uri.fsPath === gz.fsPath && s.openInfo));
    assert.equal(gzSession.openInfo?.frames, 11);

    // "Reopen Editor With…" offers the viewer for generic extensions.
    const log = vscode.Uri.file(path.join(formats, "capture.log"));
    await vscode.commands.executeCommand("vscode.openWith", log, "pcapViewer.editorOptional");
    const logSession = await waitFor(() => api.provider.allSessions.find((s) => s.uri.fsPath === log.fsPath && s.openInfo));
    assert.equal(logSession.openInfo?.frames, 26);

    await vscode.commands.executeCommand("workbench.action.closeAllEditors");
    await waitFor(() => (api.provider.allSessions.length ? undefined : true), 10_000);
  });
});
