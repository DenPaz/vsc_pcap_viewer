import * as vscode from "vscode";
import { registerAnalysisCommands } from "./commands/analysis";
import { registerColoringCommands } from "./commands/coloring";
import { registerColumnCommands } from "./commands/columns";
import { registerDissectorCommands } from "./commands/dissectors";
import { registerExportCommands } from "./commands/export";
import { registerNavigationCommands } from "./commands/navigation";
import { registerFilterCommands } from "./commands/filter";
import { registerSavedFilterCommands } from "./commands/savedFilters";
import { registerFilterButtonCommands } from "./commands/filterButtons";
import { COLORING_KEYS, RELOAD_KEYS, SECTION, readQuickDetail, readSettings } from "./config";
import { FilterAssistant } from "./ai";
import { registerAiCommands } from "./commands/ai";
import { registerIndexCacheCommands } from "./commands/indexCache";
import { registerTlsCommands } from "./commands/tls";
import { registerMergeCommands } from "./commands/merge";
import { registerCommentCommands } from "./commands/comments";
import { registerCaptureCommands } from "./commands/capture";
import { registerEditCaptureCommands } from "./commands/editCapture";
import { registerSetupCommands } from "./commands/setup";
import { pruneTemporaryCaptures } from "./tempCaptures";
import { PcapEditorProvider } from "./pcapEditor";
import { sameNameResolution } from "./settingsModel";

let provider: PcapEditorProvider | undefined;
let namesTimer: ReturnType<typeof setTimeout> | undefined;

export interface PcapViewerApi {
  /** Exposed for integration tests. */
  readonly provider: PcapEditorProvider;
}

export function activate(context: vscode.ExtensionContext): PcapViewerApi {
  const log = vscode.window.createOutputChannel("PCAP Viewer", { log: true });
  context.subscriptions.push(log);
  const assistant = new FilterAssistant(log);
  context.subscriptions.push(assistant);
  provider = PcapEditorProvider.register(context, log, assistant);
  const p = provider;

  registerFilterCommands(context, p);
  registerColumnCommands(context, p);
  registerSavedFilterCommands(context, p);
  registerFilterButtonCommands(context, p);
  registerAnalysisCommands(context, p);
  registerDissectorCommands(context, p, log);
  registerExportCommands(context, p);
  registerNavigationCommands(context, p);
  registerColoringCommands(context, p);
  registerAiCommands(context, p, log);
  registerIndexCacheCommands(context);
  registerTlsCommands(context, p);
  registerMergeCommands(context, p, log);
  registerCommentCommands(context, p);
  registerCaptureCommands(context, p, log);
  registerEditCaptureCommands(context, p, log);
  registerSetupCommands(context, log);
  // Unsaved captures left behind (a crash, or a restored editor long closed).
  void pruneTemporaryCaptures(context, new Set(p.allSessions.map((s) => s.uri.fsPath)));
  context.subscriptions.push(
    vscode.commands.registerCommand("pcapViewer.showLog", () => log.show()),
    vscode.workspace.onDidChangeConfiguration(async (e) => {
      if (!e.affectsConfiguration(SECTION)) {
        return;
      }
      if (
        e.affectsConfiguration(`${SECTION}.columns`) ||
        e.affectsConfiguration(`${SECTION}.columnLayout`)
      ) {
        for (const s of p.allSessions) {
          const settings = readSettings(s.uri); // folder-scoped: each capture its own
          s.setColumns(settings.columns, settings.columnLayout);
        }
      }
      if (e.affectsConfiguration(`${SECTION}.timeFormat`)) {
        for (const s of p.allSessions) {
          s.setTimeFormat(readSettings(s.uri).timeFormat);
        }
      }
      if (e.affectsConfiguration(`${SECTION}.quickDetail`)) {
        for (const s of p.allSessions) {
          s.setQuickDetail(readQuickDetail(s.uri));
        }
      }
      if (e.affectsConfiguration(`${SECTION}.filterButtons`)) {
        const buttons = readSettings().filterButtons;
        for (const s of p.allSessions) {
          s.setFilterButtons(buttons);
        }
      }
      if (e.affectsConfiguration(`${SECTION}.savedFilters`)) {
        const saved = readSettings().savedFilters;
        for (const s of p.allSessions) {
          s.setSavedFilters(saved);
        }
      }
      if (COLORING_KEYS.some((k) => e.affectsConfiguration(k))) {
        // Colors are re-evaluated in the background; no re-indexing needed.
        for (const s of p.allSessions) {
          void s.applyColoring();
        }
      }
      if (e.affectsConfiguration(`${SECTION}.nameResolution`)) {
        // Usually PCAP: Name Resolution…, which can change several keys: reload
        // once they are all written (saved indexes make switching back instant).
        clearTimeout(namesTimer);
        namesTimer = setTimeout(() => {
          for (const s of p.allSessions.filter(
            (s) => !sameNameResolution(readSettings(s.uri).nameResolution, s.names),
          )) {
            void s.load();
          }
        }, 300);
      }
      if (e.affectsConfiguration(`${SECTION}.tlsKeyLogFile`)) {
        // Usually PCAP: Set TLS Key Log File…: reload the captures whose key log changed.
        await Promise.all(
          p.allSessions
            .filter((s) => readSettings(s.uri).tlsKeyLogFile !== s.keyLogFile)
            .map((s) => s.load()),
        );
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
