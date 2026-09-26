import * as vscode from "vscode";
import { readSettings, updateSetting } from "../config";
import type { PcapEditorProvider, PcapEditorSession } from "../pcapEditor";
import { SavedFilter, upsertSavedFilter } from "../settingsModel";

/**
 * Ask for a name and store `expr` in `pcapViewer.savedFilters` (asks before
 * overwriting an existing name). Returns the saved entry, or undefined if cancelled.
 */
export async function saveFilterInteractive(expr: string, session?: PcapEditorSession): Promise<SavedFilter | undefined> {
  let filter = expr.trim();
  if (!filter) {
    const typed = await vscode.window.showInputBox({
      title: "Save Display Filter",
      prompt: "Display filter to save",
      validateInput: async (text) => (text.trim() && session ? await session.validateFilter(text) : undefined),
    });
    filter = typed?.trim() ?? "";
    if (!filter) {
      return undefined;
    }
  } else if (session) {
    const error = await session.validateFilter(filter);
    if (error) {
      void vscode.window.showErrorMessage(`Not saving an invalid filter: ${error}`);
      return undefined;
    }
  }
  const existing = readSettings().savedFilters;
  const name = await vscode.window.showInputBox({
    title: "Save Display Filter",
    prompt: `Name for: ${filter}`,
    value: existing.find((f) => f.filter === filter)?.name ?? (filter.length <= 40 ? filter : `${filter.slice(0, 37)}…`),
    validateInput: (text) => (text.trim() ? undefined : "Enter a name"),
  });
  if (name === undefined) {
    return undefined;
  }
  const entry = { name: name.trim(), filter };
  const clash = existing.find((f) => f.name === entry.name);
  if (clash && clash.filter !== filter) {
    const choice = await vscode.window.showWarningMessage(
      `A saved filter named "${entry.name}" already exists (${clash.filter}). Replace it?`,
      { modal: true },
      "Replace",
    );
    if (choice !== "Replace") {
      return undefined;
    }
  }
  await updateSetting("savedFilters", upsertSavedFilter(existing, entry));
  vscode.window.setStatusBarMessage(`Saved display filter "${entry.name}"`, 3000);
  return entry;
}

type FilterItem = vscode.QuickPickItem & { entry?: SavedFilter; action?: "save" | "settings" };

const DELETE_BUTTON: vscode.QuickInputButton = { iconPath: new vscode.ThemeIcon("trash"), tooltip: "Delete" };

/** Quick pick over saved filters: select to apply, trash button to delete. */
export async function showSavedFilters(session: PcapEditorSession | undefined): Promise<void> {
  const qp = vscode.window.createQuickPick<FilterItem>();
  qp.title = "Saved Display Filters";
  qp.placeholder = session ? "Select a filter to apply it" : "Open a capture to apply a filter";
  qp.matchOnDescription = true;
  const build = () => {
    const saved = readSettings().savedFilters;
    const current = session?.currentFilter.trim();
    qp.items = [
      ...saved.map<FilterItem>((entry) => ({ label: entry.name, description: entry.filter, entry, buttons: [DELETE_BUTTON] })),
      { label: "", kind: vscode.QuickPickItemKind.Separator },
      ...(current ? [{ label: "$(save) Save current filter…", description: current, action: "save" as const }] : []),
      { label: "$(settings-gear) Edit in settings", action: "settings" },
    ];
  };
  build();
  qp.onDidTriggerItemButton(async ({ item }) => {
    if (item.entry) {
      const remaining = readSettings().savedFilters.filter((f) => f.name !== item.entry?.name);
      await updateSetting("savedFilters", remaining);
      build();
    }
  });
  qp.onDidAccept(async () => {
    const item = qp.selectedItems[0];
    qp.hide();
    if (item?.entry) {
      session?.applyFilter(item.entry.filter);
    } else if (item?.action === "save" && session) {
      await saveFilterInteractive(session.currentFilter, session);
    } else if (item?.action === "settings") {
      await vscode.commands.executeCommand("workbench.action.openSettings", "pcapViewer.savedFilters");
    }
  });
  qp.onDidHide(() => qp.dispose());
  qp.show();
}

export function registerSavedFilterCommands(context: vscode.ExtensionContext, provider: PcapEditorProvider): void {
  context.subscriptions.push(
    vscode.commands.registerCommand("pcapViewer.saveFilter", async (expr?: unknown) => {
      const session = provider.activeSession;
      await saveFilterInteractive(typeof expr === "string" ? expr : (session?.currentFilter ?? ""), session);
    }),
    vscode.commands.registerCommand("pcapViewer.savedFilters", () => showSavedFilters(provider.activeSession)),
  );
}
