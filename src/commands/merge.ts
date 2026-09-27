import * as path from "node:path";
import * as vscode from "vscode";
import { RpcError } from "../backendClient";
import { PcapEditorProvider, describeError } from "../pcapEditor";
import { withBackend } from "./withBackend";
import { mergedFileName, rotatedSiblings } from "../rotation";

/**
 * "PCAP: Merge Captures…": merge capture files into one (mergecap) and open it.
 * `files` (full paths) skips the choice: the pieces of a rotated capture, in order.
 */
export async function mergeCaptures(
  provider: PcapEditorProvider,
  context: vscode.ExtensionContext,
  log: vscode.LogOutputChannel,
  files?: unknown,
): Promise<string | undefined> {
  let inputs = Array.isArray(files) ? files.filter((f): f is string => typeof f === "string") : [];
  // A rotated capture's pieces go one after another; other files are merged by timestamp.
  let append = inputs.length > 1;
  if (inputs.length < 2) {
    const active = provider.activeSession?.uri.fsPath;
    const pieces = active ? await rotatedSiblings(active) : [];
    if (pieces.length > 1) {
      const pick = await vscode.window.showQuickPick(
        [
          {
            label: `Merge the ${pieces.length} Files of This Rotated Capture`,
            description: pieces.map((p) => path.basename(p)).join(", "),
            rotated: true,
          },
          { label: "Choose Files…", description: "merged by timestamp", rotated: false },
        ],
        { title: "Merge Captures" },
      );
      if (!pick) {
        return undefined;
      }
      inputs = pick.rotated ? pieces : [];
      append = pick.rotated;
    }
    if (!inputs.length) {
      const chosen = await vscode.window.showOpenDialog({
        title: "Merge Captures: choose the files to merge",
        openLabel: "Merge",
        canSelectMany: true,
        defaultUri: active ? vscode.Uri.file(path.dirname(active)) : undefined,
        filters: {
          "Capture files": ["pcap", "pcapng", "cap", "ntar", "gz", "zst", "lz4"],
          "All files": ["*"],
        },
      });
      inputs = (chosen ?? []).filter((u) => u.scheme === "file").map((u) => u.fsPath);
      append = false;
    }
  }
  if (inputs.length < 2) {
    if (inputs.length === 1) {
      void vscode.window.showInformationMessage("Choose at least two capture files to merge.");
    }
    return undefined;
  }
  const target = await vscode.window.showSaveDialog({
    defaultUri: vscode.Uri.file(
      path.join(path.dirname(inputs[0]), mergedFileName(path.basename(inputs[0]))),
    ),
    filters: { pcapng: ["pcapng"], pcap: ["pcap"] },
    saveLabel: "Merge",
  });
  if (!target || target.scheme !== "file") {
    return undefined;
  }
  const dest = target.fsPath;
  const format = dest.toLowerCase().endsWith(".pcap") ? "pcap" : "pcapng";
  try {
    await vscode.window.withProgress(
      {
        location: vscode.ProgressLocation.Notification,
        title: `Merging ${inputs.length} captures into ${path.basename(dest)}`,
        cancellable: true,
      },
      (_progress, token) =>
        withBackend(provider, context, log, (backend) => {
          const pending = backend.send("merge", { inputs, dest, format, append }, { timeoutMs: 0 });
          token.onCancellationRequested(() => backend.cancel(pending.id));
          return pending.promise;
        }),
    );
  } catch (err) {
    if (!(err instanceof RpcError && err.cancelled)) {
      void vscode.window.showErrorMessage(`PCAP Viewer: merging failed: ${describeError(err)}`);
    }
    return undefined;
  }
  await vscode.commands.executeCommand(
    "vscode.openWith",
    vscode.Uri.file(dest),
    PcapEditorProvider.viewType,
  );
  return dest;
}

export function registerMergeCommands(
  context: vscode.ExtensionContext,
  provider: PcapEditorProvider,
  log: vscode.LogOutputChannel,
): void {
  context.subscriptions.push(
    vscode.commands.registerCommand("pcapViewer.mergeCaptures", (files?: unknown) =>
      mergeCaptures(provider, context, log, files),
    ),
  );
}
