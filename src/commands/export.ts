import * as path from "node:path";
import * as vscode from "vscode";
import { RpcError } from "../backendClient";
import { readSettings } from "../config";
import { PcapEditorProvider, PcapEditorSession, describeError } from "../pcapEditor";
import { exportFileName } from "../settingsModel";
import { requireSession } from "./filter";

interface ExportResult {
  ok: boolean;
  path: string;
  size: number;
  packets?: number;
  bytes?: number;
  warnings?: string[];
}

function backendOf(session: PcapEditorSession) {
  const backend = session.backend;
  if (!backend?.running || !session.openInfo) {
    void vscode.window.showInformationMessage("Wait for the capture to finish loading.");
    return undefined;
  }
  return backend;
}

async function chooseDestination(session: PcapEditorSession, suffix: string, ext: string, filters: Record<string, string[]>): Promise<string | undefined> {
  const uri = await vscode.window.showSaveDialog({
    defaultUri: vscode.Uri.file(exportFileName(session.uri.fsPath, suffix, ext)),
    filters,
    saveLabel: "Export",
  });
  if (!uri) {
    return undefined;
  }
  if (uri.scheme !== "file") {
    void vscode.window.showErrorMessage("PCAP Viewer can only export to local files.");
    return undefined;
  }
  return uri.fsPath;
}

/** Run the backend's `export` with a cancellable progress notification. */
async function runExport(session: PcapEditorSession, title: string, params: Record<string, unknown>): Promise<ExportResult | undefined> {
  const backend = backendOf(session);
  if (!backend) {
    return undefined;
  }
  try {
    return await vscode.window.withProgress({ location: vscode.ProgressLocation.Notification, title, cancellable: true }, async (progress, token) => {
      let reported = 0;
      const pending = backend.send<ExportResult>("export", params, {
        timeoutMs: 0,
        onProgress: (p) => {
          if (typeof p.fraction === "number") {
            const pct = Math.round(p.fraction * 100);
            progress.report({ increment: pct - reported, message: `${pct}%` });
            reported = pct;
          }
        },
      });
      token.onCancellationRequested(() => backend.cancel(pending.id));
      return pending.promise;
    });
  } catch (err) {
    if (!(err instanceof RpcError && err.cancelled)) {
      void vscode.window.showErrorMessage(`PCAP Viewer: export failed: ${describeError(err)}`);
    }
    return undefined;
  }
}

async function reportExport(result: ExportResult, what: string, canOpen: boolean): Promise<void> {
  const name = path.basename(result.path);
  const actions = canOpen ? ["Open", "Reveal"] : ["Reveal"];
  const warning = result.warnings?.length ? ` (${result.warnings[0]})` : "";
  const choice = await vscode.window.showInformationMessage(`Exported ${what} to ${name}${warning}`, ...actions);
  const uri = vscode.Uri.file(result.path);
  if (choice === "Open") {
    await vscode.commands.executeCommand("vscode.openWith", uri, PcapEditorProvider.viewType);
  } else if (choice === "Reveal") {
    await vscode.commands.executeCommand("revealFileInOS", uri);
  }
}

function pickCaptureFormat(title: string, placeHolder = "File format") {
  return vscode.window.showQuickPick(
    [
      { label: "pcapng", description: "Wireshark's default format", ext: "pcapng" },
      { label: "pcap", description: "libpcap, for older tools", ext: "pcap" },
    ],
    { title, placeHolder },
  );
}

const plural = (n: number, word: string) => `${n.toLocaleString()} ${word}${n === 1 ? "" : "s"}`;

/** "PCAP: Export Specified Packets…": displayed / all / selected packets to pcapng or pcap. */
export async function exportFiltered(provider: PcapEditorProvider): Promise<ExportResult | undefined> {
  const session = requireSession(provider);
  if (!session || !backendOf(session)) {
    return undefined;
  }
  const filter = session.currentFilter.trim();
  const frames = session.openInfo?.frames ?? 0;
  type ScopeItem = vscode.QuickPickItem & { filter?: string; frames?: number[]; suffix: string };
  const scopes: ScopeItem[] = [
    { label: "Displayed packets", description: filter ? `filter: ${filter}` : `no display filter: all ${frames.toLocaleString()} packets`, suffix: filter ? "filtered" : "export" },
    { label: "All packets", description: `${frames.toLocaleString()} packets`, filter: "", suffix: "export" },
  ];
  const selected = session.selectedFrames;
  if (selected.length > 1) {
    scopes.push({ label: "Selected packets", description: plural(selected.length, "packet"), frames: selected, suffix: "selected" });
  } else if (session.selectedFrame !== null) {
    scopes.push({ label: "Selected packet only", description: `packet ${session.selectedFrame}`, filter: `frame.number == ${session.selectedFrame}`, suffix: `frame${session.selectedFrame}` });
  }
  const scope = await vscode.window.showQuickPick(scopes, { title: "Export Specified Packets (1/2)", placeHolder: "Which packets?" });
  if (!scope) {
    return undefined;
  }
  const format = await pickCaptureFormat("Export Specified Packets (2/2)");
  if (!format) {
    return undefined;
  }
  const dest = await chooseDestination(session, scope.suffix, format.ext, { [format.label]: [format.ext] });
  if (!dest) {
    return undefined;
  }
  const params: Record<string, unknown> = { kind: format.ext, dest };
  if (scope.frames) {
    params.frames = scope.frames;
  } else if (scope.filter !== undefined) {
    params.filter = scope.filter;
  }
  const result = await runExport(session, `Exporting packets to ${path.basename(dest)}`, params);
  if (result) {
    void reportExport(result, `${(result.packets ?? 0).toLocaleString()} packet${result.packets === 1 ? "" : "s"}`, true);
  }
  return result;
}

/** "PCAP: Export Marked Packets…": the packets marked with Ctrl+M to pcapng or pcap. */
export async function exportMarked(provider: PcapEditorProvider): Promise<ExportResult | undefined> {
  const session = requireSession(provider);
  if (!session || !backendOf(session)) {
    return undefined;
  }
  if (!session.markedCount) {
    void vscode.window.showInformationMessage("No packets are marked. Mark packets with Ctrl+M (Cmd+M) first.");
    return undefined;
  }
  const format = await pickCaptureFormat(`Export ${plural(session.markedCount, "Marked Packet")}`);
  if (!format) {
    return undefined;
  }
  const dest = await chooseDestination(session, "marked", format.ext, { [format.label]: [format.ext] });
  if (!dest) {
    return undefined;
  }
  const result = await runExport(session, `Exporting marked packets to ${path.basename(dest)}`, { kind: format.ext, dest, marked: true });
  if (result) {
    void reportExport(result, `${(result.packets ?? 0).toLocaleString()} marked packet${result.packets === 1 ? "" : "s"}`, true);
  }
  return result;
}

/** "PCAP: Export Selected Packets…": the packets selected in the list (Shift/Ctrl+click) to pcapng or pcap. */
export async function exportSelected(provider: PcapEditorProvider): Promise<ExportResult | undefined> {
  const session = requireSession(provider);
  if (!session || !backendOf(session)) {
    return undefined;
  }
  const frames = session.selectedFrames.length ? session.selectedFrames : session.selectedFrame !== null ? [session.selectedFrame] : [];
  if (!frames.length) {
    void vscode.window.showInformationMessage("Select packets first (Shift+click or Ctrl+click selects several).");
    return undefined;
  }
  const format = await pickCaptureFormat(`Export ${plural(frames.length, "Selected Packet")}`);
  if (!format) {
    return undefined;
  }
  const dest = await chooseDestination(session, frames.length === 1 ? `frame${frames[0]}` : "selected", format.ext, { [format.label]: [format.ext] });
  if (!dest) {
    return undefined;
  }
  const result = await runExport(session, `Exporting selected packets to ${path.basename(dest)}`, { kind: format.ext, dest, frames });
  if (result) {
    void reportExport(result, `${plural(result.packets ?? 0, "selected packet")}`, true);
  }
  return result;
}

/** "PCAP: Export Packet List as CSV/JSON…": the displayed (or selected) rows, in the current sort order, with their columns. */
export async function exportPacketList(provider: PcapEditorProvider): Promise<ExportResult | undefined> {
  const session = requireSession(provider);
  if (!session || !backendOf(session)) {
    return undefined;
  }
  const selected = session.selectedFrames;
  let frames: number[] | undefined;
  if (selected.length > 1) {
    const scope = await vscode.window.showQuickPick(
      [
        { label: "Displayed rows", description: session.currentFilter ? `filter: ${session.currentFilter}` : "all packets" },
        { label: "Selected rows", description: plural(selected.length, "row"), frames: selected },
      ],
      { title: "Export Packet List", placeHolder: "Which rows?" },
    );
    if (!scope) {
      return undefined;
    }
    frames = "frames" in scope ? scope.frames : undefined;
  }
  const format = await vscode.window.showQuickPick(
    [
      { label: "CSV", description: "one quoted row per packet, like Wireshark", ext: "csv" },
      { label: "JSON", description: "an array of objects keyed by column", ext: "json" },
    ],
    { title: "Export Packet List", placeHolder: session.currentFilter ? `Displayed packets (filter: ${session.currentFilter})` : "All packets" },
  );
  if (!format) {
    return undefined;
  }
  const dest = await chooseDestination(session, frames ? "selected-packets" : "packets", format.ext, { [format.label]: [format.ext] });
  if (!dest) {
    return undefined;
  }
  const columns = readSettings(session.uri).columns;
  const result = await runExport(session, `Exporting packet list to ${path.basename(dest)}`, {
    kind: format.ext,
    dest,
    columns: columns.map((c) => c.field),
    titles: columns.map((c) => c.title),
    ...(frames ? { frames } : {}),
  });
  if (result) {
    void reportExport(result, `${(result.packets ?? 0).toLocaleString()} rows`, false);
  }
  return result;
}

/** "PCAP: Export Packet Bytes…": raw bytes of the selected packet (or one of its reassembled sources). */
export async function exportPacketBytes(provider: PcapEditorProvider, frame?: number): Promise<ExportResult | undefined> {
  const session = requireSession(provider);
  const backend = session && backendOf(session);
  if (!session || !backend) {
    return undefined;
  }
  const number = typeof frame === "number" ? frame : session.selectedFrame;
  if (number === null) {
    void vscode.window.showInformationMessage("Select a packet to export its bytes.");
    return undefined;
  }
  let source = 0;
  try {
    const detail = await backend.request<{ sources: { name: string; hex: string }[] }>("packet_detail", { number }, { timeoutMs: 0 });
    if (detail.sources.length > 1) {
      const pick = await vscode.window.showQuickPick(
        detail.sources.map((s, i) => ({ label: s.name, description: `${s.hex.length / 2} bytes`, index: i })),
        { title: `Export Bytes of Packet ${number}`, placeHolder: "Which data?" },
      );
      if (!pick) {
        return undefined;
      }
      source = pick.index;
    }
  } catch (err) {
    void vscode.window.showErrorMessage(`PCAP Viewer: ${describeError(err)}`);
    return undefined;
  }
  const dest = await chooseDestination(session, `frame${number}`, "bin", { "Raw bytes": ["bin"], "All files": ["*"] });
  if (!dest) {
    return undefined;
  }
  const result = await runExport(session, `Exporting bytes of packet ${number}`, { kind: "bytes", dest, number, source });
  if (result) {
    void reportExport(result, `${(result.bytes ?? 0).toLocaleString()} bytes of packet ${number}`, false);
  }
  return result;
}

export function registerExportCommands(context: vscode.ExtensionContext, provider: PcapEditorProvider): void {
  context.subscriptions.push(
    vscode.commands.registerCommand("pcapViewer.exportFiltered", () => exportFiltered(provider)),
    vscode.commands.registerCommand("pcapViewer.exportPacketList", () => exportPacketList(provider)),
    vscode.commands.registerCommand("pcapViewer.exportMarked", () => exportMarked(provider)),
    vscode.commands.registerCommand("pcapViewer.exportSelected", () => exportSelected(provider)),
    vscode.commands.registerCommand("pcapViewer.exportPacketBytes", (frame?: number) => exportPacketBytes(provider, frame)),
  );
}
