import * as path from "node:path";
import * as vscode from "vscode";
import { PcapEditorProvider, describeError } from "../pcapEditor";
import { withBackend } from "./withBackend";

/** What the backend's probe_file answers. */
export interface ProbeResult {
  readable: boolean;
  format?: string | null;
  message?: string;
  berRecords?: number;
}

/** Files listed from the workspace folders at most. */
const MAX_FILES = 20_000;

type FileItem = vscode.QuickPickItem & { uri?: vscode.Uri };

/** A file from the workspace folders (files.exclude applies), or any file via Browse…. */
async function pickFile(): Promise<vscode.Uri | undefined> {
  const browse = async () =>
    (
      await vscode.window.showOpenDialog({
        title: "Open File in PCAP Viewer",
        canSelectMany: false,
        openLabel: "Open",
        defaultUri: vscode.workspace.workspaceFolders?.[0]?.uri,
      })
    )?.[0];
  if (!vscode.workspace.workspaceFolders?.length) {
    return browse();
  }
  const pick = vscode.window.createQuickPick<FileItem>();
  pick.title = "Open File in PCAP Viewer";
  pick.placeholder = "Type to find a file in the workspace (any name, with or without extension)";
  pick.matchOnDescription = true;
  pick.busy = true;
  const browseItem: FileItem = {
    label: "$(folder-opened) Browse…",
    description: "a file outside the workspace",
    alwaysShow: true,
  };
  pick.items = [browseItem];
  pick.show();
  void vscode.workspace.findFiles("**/*", undefined, MAX_FILES).then((uris) => {
    const files = uris
      .map((uri) => ({ uri, rel: vscode.workspace.asRelativePath(uri) }))
      .sort((a, b) => a.rel.localeCompare(b.rel))
      .map(({ uri, rel }) => ({
        label: path.basename(uri.fsPath),
        description: path.dirname(rel) === "." ? "" : path.dirname(rel),
        uri,
      }));
    pick.items = [browseItem, ...files];
    pick.busy = false;
  });
  const chosen = await new Promise<FileItem | undefined>((resolve) => {
    pick.onDidAccept(() => resolve(pick.selectedItems[0]));
    pick.onDidHide(() => resolve(undefined));
  });
  pick.dispose();
  if (!chosen) {
    return undefined;
  }
  return chosen.uri ?? browse();
}

/**
 * PCAP: Open File in PCAP Viewer…: open any file (a workspace file, one
 * browsed to, or the Explorer's selection) in the viewer if tshark can read
 * it, whatever it is called: VS Code picks editors by file name only, so a
 * capture or a BER file without a known extension otherwise never gets the
 * viewer. Files tshark can't read get a warning saying why. Returns whether
 * the file opened.
 */
export async function openFileInViewer(
  provider: PcapEditorProvider,
  context: vscode.ExtensionContext,
  log: vscode.LogOutputChannel,
  target?: vscode.Uri,
): Promise<boolean> {
  const uri = target instanceof vscode.Uri ? target : await pickFile();
  if (!uri) {
    return false;
  }
  if (uri.scheme !== "file") {
    void vscode.window.showWarningMessage(
      `PCAP Viewer: ${path.basename(uri.path)} isn't a file on disk; open a copy of it instead.`,
    );
    return false;
  }
  let probe: ProbeResult;
  try {
    probe = await vscode.window.withProgress(
      { location: vscode.ProgressLocation.Window, title: `Checking ${path.basename(uri.fsPath)}` },
      () =>
        withBackend(provider, context, log, (client) =>
          client.request<ProbeResult>("probe_file", { path: uri.fsPath }, { timeoutMs: 60_000 }),
        ),
    );
  } catch (err) {
    log.error(`open file ${uri.fsPath}: ${describeError(err)}`);
    void vscode.window.showErrorMessage(`PCAP Viewer: ${describeError(err)}`);
    return false;
  }
  if (!probe.readable) {
    const why = probe.message ?? `${path.basename(uri.fsPath)} can't be read by tshark`;
    const more = probe.berRecords
      ? " Splitting such a file into one packet per record isn't supported yet."
      : "";
    log.warn(`open file ${uri.fsPath}: ${why}`);
    void vscode.window.showWarningMessage(`PCAP Viewer: ${why}.${more}`);
    return false;
  }
  await vscode.commands.executeCommand("vscode.openWith", uri, PcapEditorProvider.viewType);
  return true;
}

export function registerOpenFileCommand(
  context: vscode.ExtensionContext,
  provider: PcapEditorProvider,
  log: vscode.LogOutputChannel,
): void {
  context.subscriptions.push(
    vscode.commands.registerCommand("pcapViewer.openFile", (uri?: vscode.Uri) =>
      openFileInViewer(provider, context, log, uri),
    ),
  );
}
