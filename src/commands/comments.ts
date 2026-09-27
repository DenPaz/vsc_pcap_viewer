import * as vscode from "vscode";
import type { PcapEditorProvider } from "../pcapEditor";
import { requireSession } from "./filter";

/**
 * "PCAP: Delete All Packet Comments": one undoable edit that deletes every
 * comment of the capture (the others, add/edit/delete one, are viewer actions).
 */
export async function deleteAllPacketComments(provider: PcapEditorProvider): Promise<void> {
  const session = requireSession(provider);
  const client = session?.backend;
  if (!session || !client?.running) {
    return;
  }
  const res = await client.request<{ comments: Record<string, string> }>("packet_comments", {
    all: true,
  });
  const frames = Object.keys(res.comments).map(Number);
  if (!frames.length) {
    void vscode.window.showInformationMessage("This capture has no packet comments.");
    return;
  }
  session.editComments(
    new Map(frames.map((n) => [n, ""])),
    `Delete ${frames.length} Packet Comment${frames.length === 1 ? "" : "s"}`,
  );
}

export function registerCommentCommands(
  context: vscode.ExtensionContext,
  provider: PcapEditorProvider,
): void {
  context.subscriptions.push(
    vscode.commands.registerCommand("pcapViewer.deleteAllPacketComments", () =>
      deleteAllPacketComments(provider),
    ),
  );
}
