import * as path from "node:path";
import * as vscode from "vscode";
import { revealHow, whereLabel } from "../remote";

/** The label of a "show the saved file" button. */
export function revealLabel(): string {
  return whereLabel(vscode.env.remoteName) ? "Show" : "Reveal in File Explorer";
}

/**
 * Show a file or folder: in the OS file manager locally; in a remote window
 * (the OS file manager can't open a remote folder) in the Explorer view when
 * it is inside the workspace, else by offering to copy its path.
 * `preferExplorer`: the Explorer view locally too, for files in the workspace.
 */
export async function revealFile(file: string, preferExplorer = false): Promise<void> {
  const uri = vscode.Uri.file(file);
  const inWorkspace = vscode.workspace.getWorkspaceFolder(uri) !== undefined;
  switch (revealHow(vscode.env.remoteName, inWorkspace, preferExplorer)) {
    case "os":
      await vscode.commands.executeCommand("revealFileInOS", uri);
      return;
    case "explorer":
      await vscode.commands.executeCommand("revealInExplorer", uri);
      return;
    case "copyPath": {
      const where = whereLabel(vscode.env.remoteName);
      const choice = await vscode.window.showInformationMessage(
        `${path.basename(file)} is in ${path.dirname(file)} on ${where}.`,
        "Copy Path",
      );
      if (choice) {
        await vscode.env.clipboard.writeText(file);
      }
    }
  }
}
