import * as vscode from "vscode";
import { registerAnalysisCommands } from "./commands/analysis";
import { registerColumnCommands } from "./commands/columns";
import { registerDissectorCommands } from "./commands/dissectors";
import { registerFilterCommands } from "./commands/filter";
import { registerSavedFilterCommands } from "./commands/savedFilters";
import { RELOAD_KEYS, SECTION, readSettings } from "./config";
import { PcapEditorProvider } from "./pcapEditor";

let provider: PcapEditorProvider | undefined;

export interface PcapViewerApi {
  /** Exposed for integration tests. */
  readonly provider: PcapEditorProvider;
}

export function activate(context: vscode.ExtensionContext): PcapViewerApi {
  const log = vscode.window.createOutputChannel("PCAP Viewer", { log: true });
  context.subscriptions.push(log);
  provider = PcapEditorProvider.register(context, log);
  const p = provider;

  registerFilterCommands(context, p);
  registerColumnCommands(context, p);
  registerSavedFilterCommands(context, p);
  registerAnalysisCommands(context, p);
  registerDissectorCommands(context, p, log);
  context.subscriptions.push(
    vscode.commands.registerCommand("pcapViewer.showLog", () => log.show()),
    vscode.workspace.onDidChangeConfiguration(async (e) => {
      if (!e.affectsConfiguration(SECTION)) {
        return;
      }
      if (e.affectsConfiguration(`${SECTION}.columns`)) {
        const columns = readSettings().columns;
        for (const s of p.allSessions) {
          s.setColumns(columns);
        }
      }
      if (e.affectsConfiguration(`${SECTION}.savedFilters`)) {
        const saved = readSettings().savedFilters;
        for (const s of p.allSessions) {
          s.setSavedFilters(saved);
        }
      }
      if (RELOAD_KEYS.some((k) => e.affectsConfiguration(k)) && p.allSessions.length) {
        const choice = await vscode.window.showInformationMessage(
          "PCAP Viewer settings changed. Reload open captures to apply them?",
          "Reload",
        );
        if (choice === "Reload") {
          await Promise.all(p.allSessions.map((s) => s.load()));
        }
      }
    }),
  );
  return { provider: p };
}

export async function deactivate(): Promise<void> {
  // Make sure no python/tshark process outlives the extension host.
  await provider?.disposeAll();
  provider = undefined;
}
