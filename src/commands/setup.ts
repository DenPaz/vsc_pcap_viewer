import * as vscode from "vscode";
import { BackendClient, findPython } from "../backendClient";
import { readSettings } from "../config";
import {
  EnvironmentStatus,
  checkEnvironment,
  environmentSummary,
  settingToFix,
} from "../environment";

/** The Get Started walkthrough's id in package.json. */
export const WALKTHROUGH = "gettingStarted";
/** Context keys the walkthrough's Python and TShark steps complete on. */
export const PYTHON_FOUND = "pcapViewer.pythonFound";
export const TSHARK_FOUND = "pcapViewer.tsharkFound";
/** …the Open step, once a capture loaded, and the Filter step, once a filter was applied. */
export const CAPTURE_OPENED = "pcapViewer.captureOpened";
export const FILTER_APPLIED = "pcapViewer.filterApplied";

const DOWNLOADS = {
  pythonPath: "https://www.python.org/downloads/",
  tsharkPath: "https://www.wireshark.org/download.html",
} as const;

/** Mark the walkthrough's setup steps done (a capture that loads proves both). */
export function setEnvironmentContext(python: boolean, tshark: boolean): void {
  void vscode.commands.executeCommand("setContext", PYTHON_FOUND, python);
  void vscode.commands.executeCommand("setContext", TSHARK_FOUND, tshark);
}

export function openWalkthrough(context: vscode.ExtensionContext): Thenable<unknown> {
  return vscode.commands.executeCommand(
    "workbench.action.openWalkthrough",
    `${context.extension.id}#${WALKTHROUGH}`,
    false,
  );
}

/** Offer the fixes for a missing Python or tshark (also used when a capture can't load). */
export async function offerSetupHelp(
  context: vscode.ExtensionContext,
  message: string,
  setting: "pythonPath" | "tsharkPath",
): Promise<void> {
  const download = setting === "pythonPath" ? "Download Python" : "Download Wireshark";
  const choice = await vscode.window.showErrorMessage(
    `PCAP Viewer: ${message}`,
    "Setup Guide",
    download,
    "Open Settings",
  );
  if (choice === "Setup Guide") {
    await openWalkthrough(context);
  } else if (choice === download) {
    await vscode.env.openExternal(vscode.Uri.parse(DOWNLOADS[setting]));
  } else if (choice === "Open Settings") {
    await vscode.commands.executeCommand("workbench.action.openSettings", `pcapViewer.${setting}`);
  }
}

export function registerSetupCommands(
  context: vscode.ExtensionContext,
  log: vscode.LogOutputChannel,
): void {
  const backendDir = vscode.Uri.joinPath(context.extensionUri, "backend").fsPath;

  async function initialize(python: string[], tsharkPath: string | undefined) {
    const client = new BackendClient({
      python,
      backendDir,
      logger: { info: (m) => log.info(m), warn: (m) => log.warn(m), error: (m) => log.error(m) },
    });
    try {
      client.start();
      return await client.request<{ version: string; tsharkPath: string }>(
        "initialize",
        { tsharkPath },
        { timeoutMs: 30_000 },
      );
    } finally {
      await client.dispose();
    }
  }

  context.subscriptions.push(
    /** Returns the status (the smoke test reads it); `{quiet: true}` shows no message. */
    vscode.commands.registerCommand(
      "pcapViewer.checkEnvironment",
      async (options?: { quiet?: boolean }): Promise<EnvironmentStatus> => {
        const status = await vscode.window.withProgress(
          { location: vscode.ProgressLocation.Window, title: "PCAP: Checking Python and TShark…" },
          () => checkEnvironment(readSettings(), { findPython, initialize }),
        );
        setEnvironmentContext(status.python.ok, status.tshark.ok);
        const summary = environmentSummary(status);
        const fix = settingToFix(status);
        (fix ? log.warn : log.info).call(log, `environment check: ${summary}`);
        if (!options?.quiet) {
          if (fix) {
            void offerSetupHelp(context, summary, fix);
          } else {
            void vscode.window.showInformationMessage(`PCAP Viewer: ${summary}`);
          }
        }
        return status;
      },
    ),
    vscode.commands.registerCommand("pcapViewer.openSample", async () => {
      // A copy in the extension's storage: comments saved into it must not
      // touch the installed extension (which updates replace anyway).
      const dir = vscode.Uri.joinPath(context.globalStorageUri, "samples");
      const sample = vscode.Uri.joinPath(dir, "sample.pcapng");
      await vscode.workspace.fs.createDirectory(dir);
      try {
        await vscode.workspace.fs.stat(sample);
      } catch {
        await vscode.workspace.fs.copy(
          vscode.Uri.joinPath(context.extensionUri, "media", "sample.pcapng"),
          sample,
        );
      }
      await vscode.commands.executeCommand("vscode.openWith", sample, "pcapViewer.editor");
      return sample;
    }),
    vscode.commands.registerCommand("pcapViewer.openWalkthrough", () => openWalkthrough(context)),
  );
}
