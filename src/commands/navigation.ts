import * as vscode from "vscode";
import { getSetting, updateSetting } from "../config";
import { VIEWER_COMMANDS, ViewerCommand } from "../messages";
import type { PcapEditorProvider } from "../pcapEditor";
import { TIME_FORMATS } from "../settingsModel";
import { requireSession } from "./filter";

/** Command id for each viewer action, e.g. "pcapViewer.toggleMark". */
export function viewerCommandId(command: ViewerCommand): string {
  return `pcapViewer.${command}`;
}

/** "PCAP: Time Display Format": pick how the Time column is shown (pcapViewer.timeFormat). */
export async function pickTimeFormat(provider: PcapEditorProvider): Promise<void> {
  const scope = provider.activeSession?.uri;
  const current = getSetting<string>("timeFormat", "relative", scope);
  const pick = await vscode.window.showQuickPick(
    TIME_FORMATS.map((f) => ({ label: f.label, description: f.id === current ? "current" : undefined, id: f.id })),
    { title: "Time Display Format", placeHolder: "How the packet list shows the Time column" },
  );
  if (pick) {
    await updateSetting("timeFormat", pick.id, scope);
  }
}

/**
 * Viewer actions (Find, navigation, marks, time reference) for the command
 * palette and keybindings: each asks the active capture's webview to act.
 */
export function registerNavigationCommands(context: vscode.ExtensionContext, provider: PcapEditorProvider): void {
  context.subscriptions.push(
    ...VIEWER_COMMANDS.map((command) =>
      vscode.commands.registerCommand(viewerCommandId(command), () => {
        const session = requireSession(provider);
        if (session) {
          session.reveal();
          session.runCommand(command);
        }
      }),
    ),
    vscode.commands.registerCommand("pcapViewer.timeFormat", () => pickTimeFormat(provider)),
  );
}
