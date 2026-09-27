/**
 * Smoke test inside a real VS Code instance: open a fixture capture with the
 * custom editor and check that the backend indexed it and answers requests.
 */
import * as assert from "node:assert/strict";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import * as vscode from "vscode";
import type { PcapViewerApi } from "../../../src/extension";
// Same module instances as the extension's (both load out/src/panels/*.js).
import { FlowGraphPanel } from "../../../src/panels/flowGraphPanel";
import { FollowPanel } from "../../../src/panels/followPanel";
import { ObjectsPanel } from "../../../src/panels/objectsPanel";
import { StatsPanel } from "../../../src/panels/statsPanel";
import { TcpGraphPanel } from "../../../src/panels/tcpGraphPanel";

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

/** The open result once indexing is done (a streaming open first reports the rows published so far). */
const indexed = (s: { openInfo?: { indexing?: boolean } }): boolean =>
  !!s.openInfo && !s.openInfo.indexing;

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

    const session = await waitFor(() =>
      api.provider.allSessions.find((s) => s.uri.fsPath === uri.fsPath),
    );
    const info = await waitFor(() => (indexed(session) ? session.openInfo : undefined));
    assert.equal(info.frames, 11);

    const backend = session.backend;
    assert.ok(backend?.running);
    const page = await backend.request<{ rows: { number: number }[] }>("list_packets", {
      offset: 0,
      limit: 5,
    });
    assert.equal(page.rows.length, 5);
    const detail = await backend.request<{ tree: unknown[] }>("packet_detail", { number: 4 });
    assert.ok(detail.tree.length > 0);

    // The default coloring rules are applied in the background after open.
    const colored = await waitForAsync(async () => {
      const rows = await backend.request<{ rows: { color?: number }[]; coloringId: number }>(
        "list_packets",
        { offset: 0, limit: 11 },
      );
      return rows.coloringId > 0 ? rows : undefined;
    });
    assert.ok(
      colored.rows.every((r) => typeof r.color === "number"),
      "every packet of http.pcap matches a default rule",
    );

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
      "pcapViewer.exportSelected",
      "pcapViewer.selectAll",
      "pcapViewer.askAboutPackets",
      "pcapViewer.clearIndexCache",
      "pcapViewer.setTlsKeyLogFile",
      "pcapViewer.exportDissections",
      "pcapViewer.mergeCaptures",
      "pcapViewer.exportObjects",
      "pcapViewer.nameResolution",
      "pcapViewer.editPacketComment",
      "pcapViewer.deletePacketComment",
      "pcapViewer.deleteAllPacketComments",
      "pcapViewer.statistics.flowGraph",
      "pcapViewer.statistics.tcpStreamGraph",
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
    const stats = await waitFor(() =>
      StatsPanel.all.find((p) => p.kind === "conversations" && p.session === session),
    );

    // Export Objects lists what the capture carried (tshark's --export-objects).
    session.reveal();
    await vscode.commands.executeCommand("pcapViewer.exportObjects");
    const objects = await waitFor(
      () => ObjectsPanel.all.find((p) => p.session === session)?.objects,
    );
    assert.deepEqual(
      objects.map((o) => [o.name, o.frame]),
      [["index.html", 7]],
    );

    // With a second capture focused, focusing the first capture's panel must
    // make the first capture the target of capture commands again.
    const other = vscode.Uri.file(path.join(FIXTURES, "dns.pcap"));
    await vscode.commands.executeCommand("vscode.openWith", other, "pcapViewer.editor");
    await waitFor(() =>
      api.provider.activeSession?.uri.fsPath === other.fsPath ? true : undefined,
    );
    stats.panel.reveal(undefined, false);
    await waitFor(() => (api.provider.activeSession === session ? true : undefined));

    // Closing the editor must stop the backend process (and close its panels).
    await vscode.commands.executeCommand("workbench.action.closeAllEditors");
    await waitFor(() => (backend.running ? undefined : true), 10_000);
  });

  test("packet comments: an edit makes the capture dirty, undo and save work", async () => {
    const ext = vscode.extensions.all.find((e) => e.packageJSON.name === "pcap-viewer");
    const api = (await ext!.activate()) as PcapViewerApi;
    // A copy: saving writes the comments into the file.
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "pcap-smoke-"));
    const file = path.join(dir, "comments.pcapng");
    fs.copyFileSync(path.join(FIXTURES, "comments.pcapng"), file);
    const uri = vscode.Uri.file(file);
    await vscode.commands.executeCommand("vscode.openWith", uri, "pcapViewer.editor");
    const session = await waitFor(() =>
      api.provider.allSessions.find((s) => s.uri.fsPath === uri.fsPath && indexed(s)),
    );
    const comment = async (frame: number): Promise<string | undefined> => {
      const res = await session.backend?.request<{ comments: Record<string, string> }>(
        "packet_comments",
        { frames: [frame] },
      );
      return res?.comments[String(frame)];
    };
    assert.equal(await comment(2), "SYN-ACK from the server");
    const dirty = () => vscode.window.tabGroups.activeTabGroup.activeTab?.isDirty;
    assert.equal(dirty(), false);

    session.editComments(new Map([[1, "from the smoke test"]]), "Edit Packet Comment");
    await waitFor(() => (dirty() ? true : undefined));
    await waitForAsync(async () =>
      (await comment(1)) === "from the smoke test" ? true : undefined,
    );
    await vscode.commands.executeCommand("undo");
    await waitFor(() => (dirty() === false ? true : undefined));
    await waitForAsync(async () => ((await comment(1)) === undefined ? true : undefined));

    session.editComments(new Map([[1, "saved"]]), "Edit Packet Comment");
    await waitFor(() => (dirty() ? true : undefined));
    const before = fs.statSync(file).mtimeMs;
    await vscode.commands.executeCommand("workbench.action.files.save");
    await waitFor(() => (dirty() === false ? true : undefined));
    assert.ok(fs.statSync(file).mtimeMs > before || fs.statSync(file).size > 0, "written");
    assert.equal(await comment(1), "saved", "now in the file");
    assert.ok(fs.readFileSync(file).includes(Buffer.from("saved")));

    // The flow graph and TCP stream graph panels talk to the same backend.
    await vscode.commands.executeCommand("pcapViewer.statistics.flowGraph");
    const flow = await waitFor(
      () => FlowGraphPanel.all.find((p) => p.session === session)?.firstPage,
    );
    assert.equal(flow.total, 11);
    assert.deepEqual(flow.nodes, ["192.168.1.10", "93.184.216.34"]);
    session.reveal();
    await vscode.commands.executeCommand("pcapViewer.statistics.tcpStreamGraph", 4);
    const graph = await waitFor(
      () => TcpGraphPanel.all.find((p) => p.session === session)?.current,
    );
    assert.equal(graph.stream, 0);
    assert.equal(graph.points.length, 11);

    await vscode.commands.executeCommand("workbench.action.closeAllEditors");
    await waitFor(() => (api.provider.allSessions.length ? undefined : true), 10_000);
    fs.rmSync(dir, { recursive: true, force: true });
  });

  test("live capture: an unsaved capture that fills, stops, saves elsewhere and is discarded", async () => {
    const ext = vscode.extensions.all.find((e) => e.packageJSON.name === "pcap-viewer");
    const api = (await ext!.activate()) as PcapViewerApi;
    const uri = await vscode.commands.executeCommand<vscode.Uri | undefined>(
      "pcapViewer.startCapture",
      { interfaces: ["fake0"] },
    );
    assert.ok(uri, "the capture opened");
    const session = await waitFor(() =>
      api.provider.allSessions.find((s) => s.uri.fsPath === uri.fsPath && s.capturing),
    );
    assert.ok(session.document.temporary);
    const dirty = () => vscode.window.tabGroups.activeTabGroup.activeTab?.isDirty;
    await waitFor(() => (dirty() ? true : undefined));
    await waitForAsync(async () => {
      const page = await session.backend?.request<{ total: number }>("list_packets", {
        offset: 0,
        limit: 5,
      });
      return page && page.total >= 3 ? true : undefined;
    });
    await vscode.commands.executeCommand("pcapViewer.stopCapture");
    await waitFor(() => (indexed(session) && !session.capturing ? true : undefined));
    const frames = session.openInfo!.frames;
    assert.ok(frames >= 3 && frames <= 26, `${frames} packets`);

    // Save As writes the capture elsewhere (the dialog is VS Code's; call the provider).
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "pcap-smoke-capture-"));
    const saved = vscode.Uri.file(path.join(dir, "saved.pcapng"));
    await api.provider.saveCustomDocumentAs(
      session.document,
      saved,
      new vscode.CancellationTokenSource().token,
    );
    assert.ok(fs.statSync(saved.fsPath).size > 0);

    // Closing without saving discards the temporary capture (a few seconds later).
    await vscode.commands.executeCommand("workbench.action.revertAndCloseActiveEditor");
    await waitFor(() => (api.provider.allSessions.length ? undefined : true), 10_000);
    await waitFor(() => (fs.existsSync(uri.fsPath) ? undefined : true), 20_000);
    fs.rmSync(dir, { recursive: true, force: true });
  });

  test("changing name resolution re-indexes open captures", async () => {
    const ext = vscode.extensions.all.find((e) => e.packageJSON.name === "pcap-viewer");
    const api = (await ext!.activate()) as PcapViewerApi;
    const uri = vscode.Uri.file(path.join(FIXTURES, "http.pcap"));
    await vscode.commands.executeCommand("vscode.openWith", uri, "pcapViewer.editor");
    const session = await waitFor(() =>
      api.provider.allSessions.find((s) => s.uri.fsPath === uri.fsPath && indexed(s)),
    );
    // The Info of frame 2, read from whichever backend the session has (it restarts on reload).
    const info = async (): Promise<string | undefined> => {
      try {
        const page = await session.backend?.request<{ rows: { cells: string[] }[] }>(
          "list_packets",
          { offset: 1, limit: 1 },
        );
        return page?.rows[0]?.cells[6];
      } catch {
        return undefined;
      }
    };
    assert.match(await waitForAsync(info), /^80 → 50000 /);
    const cfg = vscode.workspace.getConfiguration("pcapViewer");
    await cfg.update("nameResolution.transport", true, vscode.ConfigurationTarget.Global);
    try {
      await waitForAsync(async () =>
        (await info())?.startsWith("http(80) → 50000") ? true : undefined,
      );
      assert.ok(session.names.transport);
    } finally {
      await cfg.update("nameResolution.transport", undefined, vscode.ConfigurationTarget.Global);
    }
    await vscode.commands.executeCommand("workbench.action.closeAllEditors");
    await waitFor(() => (api.provider.allSessions.length ? undefined : true), 10_000);
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
        const i = vscode.window.tabGroups.activeTabGroup.activeTab?.input as
          { uri?: vscode.Uri } | undefined;
        return i?.uri?.fsPath === uri.fsPath ? i : undefined;
      });
      return input instanceof vscode.TabInputCustom ? input.viewType : "other";
    };

    const defaults = [
      "http.pcap.gz",
      "mixed.pcapng.gz",
      "http.pcap.zst",
      "mixed.pcapng.zst",
      "http.pcap.lz4",
      "mixed.pcapng.lz4",
      "mixed.ntar",
      "trace.pcap1",
      "http.snoop",
      "http.erf",
      "hci.pklg",
      "hci.btsnoop",
    ];
    for (const name of defaults) {
      assert.equal(await openedAs(name), "pcapViewer.editor", name);
      await vscode.commands.executeCommand("workbench.action.closeActiveEditor");
    }
    for (const name of [
      "capture.1",
      "capture.log",
      "capture.dmp",
      "capture.trc",
      "capture.ber",
      "notes.log",
    ]) {
      assert.equal(await openedAs(name), "other", `${name} must not open in the viewer by default`);
      await vscode.commands.executeCommand("workbench.action.closeActiveEditor");
    }

    // A compressed capture is indexed like any other.
    const gz = vscode.Uri.file(path.join(formats, "http.pcap.gz"));
    await vscode.commands.executeCommand("vscode.open", gz);
    const gzSession = await waitFor(() =>
      api.provider.allSessions.find((s) => s.uri.fsPath === gz.fsPath && indexed(s)),
    );
    assert.equal(gzSession.openInfo?.frames, 11);

    // "Reopen Editor With…" offers the viewer for generic extensions.
    const log = vscode.Uri.file(path.join(formats, "capture.log"));
    await vscode.commands.executeCommand("vscode.openWith", log, "pcapViewer.editorOptional");
    const logSession = await waitFor(() =>
      api.provider.allSessions.find((s) => s.uri.fsPath === log.fsPath && indexed(s)),
    );
    assert.equal(logSession.openInfo?.frames, 26);

    await vscode.commands.executeCommand("workbench.action.closeAllEditors");
    await waitFor(() => (api.provider.allSessions.length ? undefined : true), 10_000);
  });
});
