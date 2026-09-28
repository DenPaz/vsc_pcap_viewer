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
import { VoipPanel } from "../../../src/panels/voipPanel";

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
  test("opens a capture and the backend responds", async function () {
    // The first open pays for every cold start (the webview, Python, the
    // backend, tshark's first run): close to 30 s on a slow Windows runner.
    this.timeout(120_000);
    const ext = vscode.extensions.all.find((e) => e.packageJSON.name === "pcap-viewer");
    assert.ok(ext, "extension is installed");
    const api = (await ext.activate()) as PcapViewerApi;

    const uri = vscode.Uri.file(path.join(FIXTURES, "http.pcap"));
    await vscode.commands.executeCommand("vscode.openWith", uri, "pcapViewer.editor");

    const session = await waitFor(() =>
      api.provider.allSessions.find((s) => s.uri.fsPath === uri.fsPath),
    );
    const info = await waitFor(() => (indexed(session) ? session.openInfo : undefined), 90_000);
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
      "pcapViewer.summarizeCapture",
      "pcapViewer.askAboutAnomaly",
      "pcapViewer.checkEnvironment",
      "pcapViewer.openSample",
      "pcapViewer.openWalkthrough",
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
      "pcapViewer.statistics.voipCalls",
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
    // VoIP Calls: this capture has neither SIP nor RTP.
    session.reveal();
    await vscode.commands.executeCommand("pcapViewer.statistics.voipCalls");
    const voip = await waitFor(() => VoipPanel.all.find((p) => p.session === session)?.calls);
    assert.deepEqual(voip, { calls: [], streams: [], heuristic: false });

    // The ☰ menu: a listed command runs on this capture; anything else is ignored.
    assert.ok(session.menuCommands.some((c) => c.id === "pcapViewer.statistics.endpoints"));
    assert.equal(await session.runMenuCommand("pcapViewer.statistics.endpoints"), true);
    const endpoints = await waitFor(() =>
      StatsPanel.all.find((p) => p.kind === "endpoints" && p.session === session),
    );
    assert.equal(endpoints.session, session);
    const editors = vscode.window.tabGroups.all.flatMap((g) => g.tabs).length;
    for (const id of ["workbench.action.closeAllEditors", "pcapViewer.savedFilters", 42]) {
      assert.equal(await session.runMenuCommand(id), false, `${String(id)} is not run`);
    }
    assert.equal(
      vscode.window.tabGroups.all.flatMap((g) => g.tabs).length,
      editors,
      "nothing was closed",
    );
    // Leave the window as the later tests expect it: just the capture editor.
    endpoints.panel.dispose();
    await waitFor(() => (StatsPanel.all.includes(endpoints) ? undefined : true));

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

  test("language model tools: registered, and answering, where VS Code has the API", async function () {
    const ext = vscode.extensions.all.find((e) => e.packageJSON.name === "pcap-viewer");
    const api = (await ext!.activate()) as PcapViewerApi;
    type Result = { content: { value?: string }[] };
    const lm = vscode.lm as unknown as {
      registerTool?: unknown;
      tools?: readonly { name: string }[];
      invokeTool?: (
        name: string,
        options: { input: object; toolInvocationToken: undefined },
      ) => Thenable<Result>;
    };
    if (typeof lm.registerTool !== "function") {
      this.skip(); // (VS Code before the tools API: @pcap works without them)
    }
    const names = (lm.tools ?? []).map((t) => t.name);
    for (const name of [
      "pcap_capture_info",
      "pcap_count",
      "pcap_stats",
      "pcap_field_search",
      "pcap_list_packets",
    ]) {
      assert.ok(names.includes(name), `${name} is registered`);
    }
    if (typeof lm.invokeTool !== "function") {
      return;
    }
    const uri = vscode.Uri.file(path.join(FIXTURES, "dns.pcap"));
    await vscode.commands.executeCommand("vscode.openWith", uri, "pcapViewer.editor");
    await waitFor(() =>
      api.provider.allSessions.find((s) => s.uri.fsPath === uri.fsPath && indexed(s)),
    );
    const text = async (name: string, input: object) =>
      (await lm.invokeTool!(name, { input, toolInvocationToken: undefined })).content
        .map((p) => p.value ?? "")
        .join("");
    // Field names aren't capture data: no consent needed.
    assert.match(await text("pcap_field_search", { prefix: "dns.flags.rc" }), /dns\.flags\.rcode/);
    // Counting is capture statistics: refused until the user allows it.
    assert.match(await text("pcap_count", { filter: "dns" }), /Not allowed/);
    await vscode.commands.executeCommand("workbench.action.closeAllEditors");
    await waitFor(() => (api.provider.allSessions.length ? undefined : true), 10_000);
  });

  test("setup: the environment check finds Python and tshark, and the sample opens", async () => {
    const ext = vscode.extensions.all.find((e) => e.packageJSON.name === "pcap-viewer");
    const api = (await ext!.activate()) as PcapViewerApi;
    const status = await vscode.commands.executeCommand<{
      python: { ok: boolean; version?: string; error?: string };
      tshark: { ok: boolean; version?: string; error?: string };
    }>("pcapViewer.checkEnvironment", { quiet: true });
    assert.ok(status.python.ok, status.python.error);
    assert.ok(status.tshark.ok, status.tshark.error);
    assert.match(status.tshark.version ?? "", /^\d+\.\d+\.\d+$/);

    const sample = await vscode.commands.executeCommand<vscode.Uri>("pcapViewer.openSample");
    // A copy in the extension's storage (which the test run keeps under .vscode-test/).
    assert.notEqual(sample.fsPath, path.join(ext!.extensionPath, "media", "sample.pcapng"));
    assert.equal(path.basename(path.dirname(sample.fsPath)), "samples");
    assert.equal(sample.scheme, "file", "tshark reads files");
    const session = await waitFor(() =>
      api.provider.allSessions.find((s) => s.uri.fsPath === sample.fsPath),
    );
    const info = await waitFor(() => (indexed(session) ? session.openInfo : undefined));
    assert.equal(info.frames, 26);

    const [walkthrough] = ext!.packageJSON.contributes.walkthroughs;
    assert.equal(walkthrough.id, "gettingStarted");
    // Opening it must not throw (the id is `<publisher>.<name>#gettingStarted`).
    await vscode.commands.executeCommand("pcapViewer.openWalkthrough");
    await vscode.commands.executeCommand("workbench.action.closeAllEditors");
  });

  test("a capture that isn't on disk opens as an unsaved copy", async () => {
    const ext = vscode.extensions.all.find((e) => e.packageJSON.name === "pcap-viewer");
    const api = (await ext!.activate()) as PcapViewerApi;
    // A read-only file system like Live Share's or an archive's (scheme "pcaptest").
    const bytes = fs.readFileSync(path.join(FIXTURES, "http.pcap"));
    const changed = new vscode.EventEmitter<vscode.FileChangeEvent[]>();
    const provider: vscode.FileSystemProvider = {
      onDidChangeFile: changed.event,
      watch: () => new vscode.Disposable(() => undefined),
      stat: () => ({ type: vscode.FileType.File, ctime: 0, mtime: 0, size: bytes.length }),
      readFile: () => bytes,
      readDirectory: () => [],
      createDirectory: () => undefined,
      writeFile: () => {
        throw vscode.FileSystemError.NoPermissions();
      },
      delete: () => undefined,
      rename: () => undefined,
    };
    const registration = vscode.workspace.registerFileSystemProvider("pcaptest", provider, {
      isReadonly: true,
    });
    const remote = vscode.Uri.parse("pcaptest:/shared/http.pcap");
    await vscode.commands.executeCommand("vscode.openWith", remote, "pcapViewer.editor");
    const original = await waitFor(() =>
      api.provider.allSessions.find((s) => s.uri.toString() === remote.toString()),
    );
    assert.equal(original.backend, undefined, "no backend for a file tshark can't read");

    const copy = await vscode.commands.executeCommand<vscode.Uri>("pcapViewer.openCopy", remote);
    assert.equal(path.basename(copy.fsPath), "http.pcap");
    const session = await waitFor(() =>
      api.provider.allSessions.find((s) => s.uri.fsPath === copy.fsPath),
    );
    assert.ok(session.document.temporary, "the copy is an unsaved capture");
    const info = await waitFor(() => (indexed(session) ? session.openInfo : undefined));
    assert.equal(info.frames, 11);

    await vscode.commands.executeCommand("workbench.action.revertAndCloseActiveEditor");
    await vscode.commands.executeCommand("workbench.action.closeAllEditors");
    registration.dispose();
    changed.dispose();
  });

  test("import from hex dump: text2pcap's capture opens unsaved, with no capture open", async () => {
    const ext = vscode.extensions.all.find((e) => e.packageJSON.name === "pcap-viewer");
    const api = (await ext!.activate()) as PcapViewerApi;
    await vscode.commands.executeCommand("workbench.action.closeAllEditors");
    await waitFor(() => (api.provider.allSessions.length ? undefined : true), 10_000);
    const imported = await vscode.commands.executeCommand<string | undefined>(
      "pcapViewer.importHexDump",
      { input: path.join(FIXTURES, "hexdump", "frames.txt"), options: { offsets: "hex" } },
    );
    assert.ok(imported, "the import succeeded");
    assert.equal(path.basename(imported), "frames.pcapng");
    const session = await waitFor(() =>
      api.provider.allSessions.find((s) => s.uri.fsPath === imported),
    );
    assert.ok(session.document.temporary, "the import is an unsaved capture");
    const info = await waitFor(() => (indexed(session) ? session.openInfo : undefined));
    assert.equal(info.frames, 11);

    await vscode.commands.executeCommand("workbench.action.revertAndCloseActiveEditor");
    await vscode.commands.executeCommand("workbench.action.closeAllEditors");
    await waitFor(() => (api.provider.allSessions.length ? undefined : true), 10_000);
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

  test("Lua dissectors: a capture's own choice, remembered across reloads", async () => {
    const ext = vscode.extensions.all.find((e) => e.packageJSON.name === "pcap-viewer");
    const api = (await ext!.activate()) as PcapViewerApi;
    const example = path.resolve(FIXTURES, "../../backend/dissectors/example.lua");
    const cfg = vscode.workspace.getConfiguration("pcapViewer");
    await cfg.update("luaScripts", [example], vscode.ConfigurationTarget.Global);
    const uri = vscode.Uri.file(path.join(FIXTURES, "http.pcap"));
    try {
      await vscode.commands.executeCommand("vscode.openWith", uri, "pcapViewer.editor");
      const session = await waitFor(() =>
        api.provider.allSessions.find((s) => s.uri.fsPath === uri.fsPath && indexed(s)),
      );
      await waitFor(() => (session.lua.length === 1 ? true : undefined));
      // None for this capture: it reloads without Lua, and a reload keeps the choice.
      await vscode.commands.executeCommand("pcapViewer.chooseLuaDissectors", { scripts: [] });
      await waitFor(() => (session.lua.length === 0 && indexed(session) ? true : undefined));
      await session.load();
      await waitFor(() => (indexed(session) ? true : undefined));
      assert.deepEqual(session.lua, [], "the choice is remembered");
      // All checked is the default again.
      await vscode.commands.executeCommand("pcapViewer.chooseLuaDissectors", {
        scripts: ["example.lua"],
      });
      await waitFor(() => (session.lua.length === 1 && indexed(session) ? true : undefined));
      assert.equal(path.normalize(session.lua[0]), path.normalize(example));
    } finally {
      await cfg.update("luaScripts", undefined, vscode.ConfigurationTarget.Global);
      await vscode.commands.executeCommand("workbench.action.closeAllEditors");
      await waitFor(() => (api.provider.allSessions.length ? undefined : true), 10_000);
    }
  });

  test("Open File in PCAP Viewer: any name when tshark reads it, a refusal otherwise", async () => {
    const ext = vscode.extensions.all.find((e) => e.packageJSON.name === "pcap-viewer");
    const api = (await ext!.activate()) as PcapViewerApi;
    // (The long path: on Windows os.tmpdir() can be an 8.3 name such as RUNNER~1.)
    const dir = fs.realpathSync.native(fs.mkdtempSync(path.join(os.tmpdir(), "pcap-open-")));
    const record = Buffer.from("300a020105040568656c6c6f", "hex"); // one BER value
    const trace = path.join(dir, "trace"); // a pcap without an extension
    fs.copyFileSync(path.join(FIXTURES, "http.pcap"), trace);
    fs.writeFileSync(path.join(dir, "record"), record);
    fs.writeFileSync(path.join(dir, "cdrs"), Buffer.concat([record, record, record]));
    const open = (name: string) =>
      vscode.commands.executeCommand<boolean>(
        "pcapViewer.openFile",
        vscode.Uri.file(path.join(dir, name)),
      );
    try {
      for (const [name, frames] of [
        ["trace", 11],
        ["record", 1],
      ] as const) {
        assert.equal(await open(name), true, name);
        // Compared as VS Code writes it (Windows: a lower-case drive letter).
        const file = vscode.Uri.file(path.join(dir, name)).fsPath;
        const tab = vscode.window.tabGroups.activeTabGroup.activeTab?.input;
        assert.ok(tab instanceof vscode.TabInputCustom, `${name} opens in a custom editor`);
        assert.equal(tab.viewType, "pcapViewer.editor");
        const session = await waitFor(() =>
          api.provider.allSessions.find((s) => s.uri.fsPath === file && indexed(s)),
        );
        assert.equal(session.openInfo?.frames, frames, name);
      }
      // Several BER records back to back: tshark can't read it, so it doesn't open.
      const before = api.provider.allSessions.length;
      assert.equal(await open("cdrs"), false);
      assert.equal(api.provider.allSessions.length, before);
    } finally {
      await vscode.commands.executeCommand("workbench.action.closeAllEditors");
      await waitFor(() => (api.provider.allSessions.length ? undefined : true), 10_000);
      fs.rmSync(dir, { recursive: true, force: true });
    }
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
