import * as vscode from "vscode";
import { readSettings, updateSetting } from "../config";
import type { PcapEditorProvider, PcapEditorSession } from "../pcapEditor";
import { FilterButton, MAX_FILTER_BUTTONS, moveFilterButton } from "../settingsModel";

/** The stored buttons (normalized: what the bar shows). */
function buttons(): FilterButton[] {
  return readSettings().filterButtons;
}

async function store(list: FilterButton[]): Promise<void> {
  await updateSetting("filterButtons", list);
}

/** A default label for a filter: the filter itself, shortened. */
function labelFor(filter: string): string {
  return filter.length <= 24 ? filter : `${filter.slice(0, 23)}…`;
}

/** Ask for a display filter (validated against the capture when there is one). */
async function askFilter(
  title: string,
  value: string,
  session?: PcapEditorSession,
): Promise<string | undefined> {
  const typed = await vscode.window.showInputBox({
    title,
    prompt: "Display filter the button applies",
    value,
    validateInput: async (text) => {
      if (!text.trim()) {
        return "Enter a display filter";
      }
      return session ? await session.validateFilter(text) : undefined;
    },
  });
  return typed?.trim() || undefined;
}

/**
 * Add a button for `expr` (else ask for a filter): asks for its label and an
 * optional comment. Returns the new button, or undefined if cancelled.
 */
export async function addFilterButtonInteractive(
  expr: string,
  session?: PcapEditorSession,
): Promise<FilterButton | undefined> {
  const title = "Add Filter Button";
  if (buttons().length >= MAX_FILTER_BUTTONS) {
    void vscode.window.showWarningMessage(
      `The filter bar shows at most ${MAX_FILTER_BUTTONS} buttons. Remove one first.`,
    );
    return undefined;
  }
  let filter = expr.trim();
  if (filter && session) {
    const error = await session.validateFilter(filter);
    if (error) {
      void vscode.window.showErrorMessage(`Not adding a button for an invalid filter: ${error}`);
      return undefined;
    }
  }
  if (!filter) {
    filter = (await askFilter(title, "", session)) ?? "";
    if (!filter) {
      return undefined;
    }
  }
  const label = await vscode.window.showInputBox({
    title,
    prompt: `Button label for: ${filter}`,
    value: labelFor(filter),
    validateInput: (text) => (text.trim() ? undefined : "Enter a label"),
  });
  if (label === undefined) {
    return undefined;
  }
  const comment = await vscode.window.showInputBox({
    title,
    prompt: "Comment shown as the button's tooltip (optional)",
  });
  if (comment === undefined) {
    return undefined;
  }
  const button: FilterButton = { label: label.trim(), filter };
  if (comment.trim()) {
    button.comment = comment.trim();
  }
  await store([...buttons(), button]);
  vscode.window.setStatusBarMessage(`Added filter button "${button.label}"`, 3000);
  return button;
}

/**
 * The button the webview meant: `index` in the current list if it still holds
 * `filter`, else the first button with that filter (the setting may have
 * changed since the bar was drawn).
 */
function locate(list: readonly FilterButton[], index: number, filter?: string): number {
  if (
    index >= 0 &&
    index < list.length &&
    (filter === undefined || list[index].filter === filter)
  ) {
    return index;
  }
  return filter === undefined ? -1 : list.findIndex((b) => b.filter === filter);
}

type Action = "label" | "filter" | "comment" | "left" | "right" | "remove";

/** Right-click on a button: edit its label, filter or comment, move it, or remove it. */
export async function editFilterButton(
  index: number,
  filter: string | undefined,
  session?: PcapEditorSession,
): Promise<void> {
  const list = buttons();
  const i = locate(list, index, filter);
  if (i < 0) {
    return;
  }
  const button = list[i];
  const items: (vscode.QuickPickItem & { action: Action })[] = [
    { label: "$(edit) Edit Label…", description: button.label, action: "label" },
    { label: "$(filter) Edit Filter…", description: button.filter, action: "filter" },
    { label: "$(comment) Edit Comment…", description: button.comment ?? "", action: "comment" },
    ...(i > 0 ? [{ label: "$(arrow-left) Move Left", action: "left" as const }] : []),
    ...(i < list.length - 1
      ? [{ label: "$(arrow-right) Move Right", action: "right" as const }]
      : []),
    { label: "$(trash) Remove", action: "remove" },
  ];
  const pick = await vscode.window.showQuickPick(items, {
    title: `Filter Button "${button.label}"`,
    placeHolder: button.filter,
  });
  if (!pick) {
    return;
  }
  const title = `Filter Button "${button.label}"`;
  let next: FilterButton[] | undefined;
  switch (pick.action) {
    case "label": {
      const label = await vscode.window.showInputBox({
        title,
        prompt: "Button label",
        value: button.label,
        validateInput: (text) => (text.trim() ? undefined : "Enter a label"),
      });
      if (label !== undefined) {
        next = list.map((b, j) => (j === i ? { ...b, label: label.trim() } : b));
      }
      break;
    }
    case "filter": {
      const expr = await askFilter(title, button.filter, session);
      if (expr) {
        next = list.map((b, j) => (j === i ? { ...b, filter: expr } : b));
      }
      break;
    }
    case "comment": {
      const comment = await vscode.window.showInputBox({
        title,
        prompt: "Comment shown as the button's tooltip (empty: none)",
        value: button.comment ?? "",
      });
      if (comment !== undefined) {
        const text = comment.trim();
        next = list.map((b, j) =>
          j !== i ? b : text ? { ...b, comment: text } : { label: b.label, filter: b.filter },
        );
      }
      break;
    }
    case "left":
    case "right":
      next = moveFilterButton(list, i, pick.action === "left" ? -1 : 1);
      break;
    case "remove":
      next = list.filter((_, j) => j !== i);
      break;
  }
  if (next) {
    await store(next);
  }
}

type ManageItem = vscode.QuickPickItem & { index?: number; action?: "add" | "settings" };

const REMOVE_BUTTON: vscode.QuickInputButton = {
  iconPath: new vscode.ThemeIcon("trash"),
  tooltip: "Remove",
};

/** Quick pick over the buttons: select one to edit it, trash to remove, or add one. */
export async function manageFilterButtons(session: PcapEditorSession | undefined): Promise<void> {
  const qp = vscode.window.createQuickPick<ManageItem>();
  qp.title = "Filter Buttons";
  qp.placeholder = "Select a button to edit, move or remove it";
  qp.matchOnDescription = true;
  const build = () => {
    const current = session?.currentFilter.trim();
    qp.items = [
      ...buttons().map<ManageItem>((b, index) => ({
        label: b.label,
        description: b.filter,
        detail: b.comment,
        index,
        buttons: [REMOVE_BUTTON],
      })),
      { label: "", kind: vscode.QuickPickItemKind.Separator },
      {
        label: "$(add) Add Filter Button…",
        description: current ? `for ${current}` : undefined,
        action: "add",
      },
      { label: "$(settings-gear) Edit in settings", action: "settings" },
    ];
  };
  build();
  qp.onDidTriggerItemButton(async ({ item }) => {
    if (item.index !== undefined) {
      const list = buttons();
      await store(list.filter((_, j) => j !== item.index));
      build();
    }
  });
  qp.onDidAccept(async () => {
    const item = qp.selectedItems[0];
    qp.hide();
    if (item?.index !== undefined) {
      await editFilterButton(item.index, item.description, session);
    } else if (item?.action === "add") {
      await addFilterButtonInteractive(session?.currentFilter ?? "", session);
    } else if (item?.action === "settings") {
      await vscode.commands.executeCommand(
        "workbench.action.openSettings",
        "pcapViewer.filterButtons",
      );
    }
  });
  qp.onDidHide(() => qp.dispose());
  qp.show();
}

export function registerFilterButtonCommands(
  context: vscode.ExtensionContext,
  provider: PcapEditorProvider,
): void {
  context.subscriptions.push(
    vscode.commands.registerCommand("pcapViewer.addFilterButton", async (expr?: unknown) => {
      const session = provider.activeSession;
      await addFilterButtonInteractive(
        typeof expr === "string" ? expr : (session?.currentFilter ?? ""),
        session,
      );
    }),
    vscode.commands.registerCommand("pcapViewer.manageFilterButtons", () =>
      manageFilterButtons(provider.activeSession),
    ),
  );
}
