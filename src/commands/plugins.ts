import * as fs from "node:fs";
import * as vscode from "vscode";
import { PcapEditorProvider, describeError } from "../pcapEditor";
import { type PluginRow, type PluginsResult, pluginRows, pluginsTitle } from "../plugins";
import { revealFile } from "./reveal";
import { withBackend } from "./withBackend";

type RowItem = vscode.QuickPickItem & { row: PluginRow };

/**
 * _PCAP: Show TShark Plugins_: the plugins tshark loads (personal ones first)
 * and the personal folder a new dissector plugin goes into. Choosing a plugin
 * shows its file; the folder can be opened (created if missing) or its path
 * copied. Returns the backend's answer (the smoke test reads it); `{quiet:
 * true}` shows nothing.
 */
export async function showPlugins(
  provider: PcapEditorProvider,
  context: vscode.ExtensionContext,
  log: vscode.LogOutputChannel,
  options?: { quiet?: boolean },
): Promise<PluginsResult | undefined> {
  let result: PluginsResult;
  try {
    result = await vscode.window.withProgress(
      { location: vscode.ProgressLocation.Window, title: "PCAP: Listing TShark plugins…" },
      () =>
        withBackend(provider, context, log, (client) =>
          client.request<PluginsResult>("tshark_plugins", {}, { timeoutMs: 60_000 }),
        ),
    );
  } catch (err) {
    log.error(`tshark plugins: ${describeError(err)}`);
    if (!options?.quiet) {
      void vscode.window.showErrorMessage(`PCAP Viewer: ${describeError(err)}`);
    }
    return undefined;
  }
  const mine = result.plugins.filter((p) => p.personal).map((p) => p.name);
  log.info(
    `tshark plugins: ${result.plugins.length} (yours: ${mine.join(", ") || "none"}); ` +
      `dissector plugins go into ${result.install ?? "(no personal folder)"}`,
  );
  for (const warning of result.warnings) {
    log.warn(`tshark plugins: ${warning}`);
  }
  if (options?.quiet) {
    return result;
  }
  for (const warning of result.warnings) {
    void vscode.window.showWarningMessage(`PCAP Viewer: ${warning}.`);
  }
  const install = result.install;
  const items: RowItem[] = pluginRows(result, install !== null && fs.existsSync(install)).map(
    (row) =>
      row.kind === "separator"
        ? { label: row.label, kind: vscode.QuickPickItemKind.Separator, row }
        : { label: row.label, description: row.description, detail: row.detail, row },
  );
  const chosen = await vscode.window.showQuickPick(items, {
    title: pluginsTitle(result),
    placeHolder: "Choose a plugin to show its file, or open the folder new plugins go into",
    matchOnDescription: true,
    matchOnDetail: true,
  });
  if (!chosen) {
    return result;
  }
  const row = chosen.row;
  if (row.kind === "plugin") {
    await revealFile(row.path);
  } else if (install && row.kind === "openFolder") {
    try {
      fs.mkdirSync(install, { recursive: true });
    } catch (err) {
      void vscode.window.showErrorMessage(
        `PCAP Viewer: can't create ${install}: ${describeError(err)}`,
      );
      return result;
    }
    await revealFile(install);
  } else if (install && row.kind === "copyFolder") {
    await vscode.env.clipboard.writeText(install);
    void vscode.window.showInformationMessage(`PCAP Viewer: copied ${install}`);
  }
  return result;
}

export function registerPluginCommands(
  context: vscode.ExtensionContext,
  provider: PcapEditorProvider,
  log: vscode.LogOutputChannel,
): void {
  context.subscriptions.push(
    vscode.commands.registerCommand("pcapViewer.showPlugins", (options?: { quiet?: boolean }) =>
      showPlugins(provider, context, log, options),
    ),
  );
}
