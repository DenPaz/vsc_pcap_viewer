import * as vscode from "vscode";
import { readSettings, updateSetting } from "../config";
import type { PcapEditorProvider } from "../pcapEditor";
import { ColumnSetting, isValidFieldName } from "../settingsModel";

interface FieldInfo {
  name: string;
  desc: string;
  type: string;
}

type Item = vscode.QuickPickItem & { action: "add" | "remove"; column?: ColumnSetting };

/** "PCAP: Manage Custom Columns": add/remove extra packet-list columns (persisted in settings). */
export function registerColumnCommands(context: vscode.ExtensionContext, provider: PcapEditorProvider): void {
  context.subscriptions.push(
    vscode.commands.registerCommand("pcapViewer.manageColumns", async (field?: unknown) => {
      const scope = provider.activeSession?.uri;
      const columns = readSettings(scope).columns;
      if (typeof field === "string" && isValidFieldName(field)) {
        if (!columns.some((c) => c.field === field)) {
          await updateSetting("columns", [...columns, { field, title: field }], scope);
        }
        return;
      }
      const items: Item[] = [
        { label: "$(add) Add column…", action: "add", alwaysShow: true },
        ...columns.map<Item>((c) => ({
          label: `$(trash) ${c.title}`,
          description: c.field === c.title ? undefined : c.field,
          detail: "Remove this column",
          action: "remove",
          column: c,
        })),
      ];
      const pick = await vscode.window.showQuickPick(items, { title: "Custom Columns", placeHolder: "Add or remove packet list columns" });
      if (!pick) {
        return;
      }
      if (pick.action === "remove" && pick.column) {
        await updateSetting(
          "columns",
          columns.filter((c) => c.field !== pick.column?.field),
          scope,
        );
        return;
      }
      const newField = await pickField(provider);
      if (!newField || columns.some((c) => c.field === newField)) {
        return;
      }
      const title = await vscode.window.showInputBox({ title: "Column title", value: newField });
      if (title === undefined) {
        return;
      }
      await updateSetting("columns", [...columns, { field: newField, title: title.trim() || newField }], scope);
    }),
  );
}

/** Quick pick over tshark's field list (queried by prefix from the active backend). */
async function pickField(provider: PcapEditorProvider): Promise<string | undefined> {
  const backend = provider.activeSession?.backend;
  const qp = vscode.window.createQuickPick<vscode.QuickPickItem>();
  qp.title = "Add Column";
  qp.placeholder = "Type a field name, e.g. tcp.stream or http.host";
  qp.matchOnDescription = true;
  let seq = 0;
  const refresh = async (prefix: string) => {
    const mine = ++seq;
    const typed: vscode.QuickPickItem[] = isValidFieldName(prefix) ? [{ label: prefix, description: "use as typed" }] : [];
    if (!backend?.running || prefix.length < 2) {
      qp.items = typed;
      return;
    }
    qp.busy = true;
    try {
      const res = await backend.request<{ fields: FieldInfo[] }>("field_index", { prefix, limit: 100 });
      if (mine === seq) {
        const found = res.fields.map((f) => ({ label: f.name, description: f.desc, detail: f.type }));
        qp.items = found.some((f) => f.label === prefix) ? found : [...typed, ...found];
      }
    } catch {
      if (mine === seq) {
        qp.items = typed;
      }
    } finally {
      if (mine === seq) {
        qp.busy = false;
      }
    }
  };
  qp.onDidChangeValue((v) => void refresh(v.trim()));
  return new Promise((resolve) => {
    qp.onDidAccept(() => {
      const value = qp.selectedItems[0]?.label ?? qp.value.trim();
      resolve(isValidFieldName(value) ? value : undefined);
      qp.hide();
    });
    qp.onDidHide(() => {
      resolve(undefined);
      qp.dispose();
    });
    qp.show();
  });
}
