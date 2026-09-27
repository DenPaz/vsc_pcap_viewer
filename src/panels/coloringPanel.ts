import * as vscode from "vscode";
import { SECTION, getSetting, updateSetting } from "../config";
import type { PcapEditorProvider } from "../pcapEditor";
import { EditableColoringRule, coloringRulesSetting, editableColoringRules } from "../settingsModel";
import { panelHtml, webviewRoot } from "./panelHtml";

type FromPanel =
  | { type: "ready" }
  | { type: "validate"; id: number; filter: string }
  | { type: "save"; rules: EditableColoringRule[] }
  | { type: "openSettings" };

/**
 * "PCAP: Edit Coloring Rules": the rules in a table (order = priority), with
 * filters checked by tshark as you type (through an open capture's backend).
 * Saving writes `pcapViewer.coloringRules` for the capture that was active,
 * like the other commands; open captures recolor without re-indexing.
 */
export class ColoringPanel {
  private static current?: ColoringPanel;

  static show(context: vscode.ExtensionContext, provider: PcapEditorProvider): ColoringPanel {
    if (ColoringPanel.current) {
      ColoringPanel.current.panel.reveal(undefined, false);
      return ColoringPanel.current;
    }
    ColoringPanel.current = new ColoringPanel(context, provider);
    return ColoringPanel.current;
  }

  /** For tests. */
  static get open(): ColoringPanel | undefined {
    return ColoringPanel.current;
  }

  readonly panel: vscode.WebviewPanel;
  /** The capture the rules are read and saved for (folder settings apply). */
  private readonly scope?: vscode.Uri;
  private readonly disposables: vscode.Disposable[] = [];

  private constructor(
    context: vscode.ExtensionContext,
    private readonly provider: PcapEditorProvider,
  ) {
    this.scope = provider.activeSession?.uri;
    const root = webviewRoot(context);
    this.panel = vscode.window.createWebviewPanel("pcapViewer.coloring", "Coloring Rules", vscode.ViewColumn.Active, {
      enableScripts: true,
      localResourceRoots: [root],
      retainContextWhenHidden: true,
    });
    this.panel.webview.html = panelHtml(this.panel.webview, root, "coloring.js", "Coloring Rules");
    this.disposables.push(
      this.panel.webview.onDidReceiveMessage((msg: FromPanel) => void this.onMessage(msg)),
      this.panel.onDidDispose(() => this.dispose()),
      vscode.workspace.onDidChangeConfiguration((e) => {
        if (e.affectsConfiguration(`${SECTION}.coloringRules`)) {
          this.post({ type: "rules", rules: this.rules() });
        }
      }),
    );
  }

  private rules(): EditableColoringRule[] {
    return editableColoringRules(getSetting<unknown>("coloringRules", [], this.scope));
  }

  private post(msg: unknown): void {
    void this.panel.webview.postMessage(msg);
  }

  private async onMessage(msg: FromPanel): Promise<void> {
    switch (msg.type) {
      case "ready": {
        const defaults = vscode.workspace.getConfiguration(SECTION, this.scope).inspect<unknown>("coloringRules")?.defaultValue;
        this.post({ type: "init", rules: this.rules(), defaults: editableColoringRules(defaults), canValidate: this.validator() !== undefined });
        break;
      }
      case "validate": {
        const session = this.validator();
        // null: valid; undefined: can't tell (no capture open to ask tshark).
        const error = session ? ((await session.validateFilter(msg.filter)) ?? null) : undefined;
        this.post({ type: "validation", id: msg.id, filter: msg.filter, error });
        break;
      }
      case "save":
        await updateSetting("coloringRules", coloringRulesSetting(editableColoringRules(msg.rules)), this.scope);
        this.post({ type: "saved", rules: this.rules() });
        break;
      case "openSettings":
        await vscode.commands.executeCommand("workbench.action.openSettings", `${SECTION}.coloringRules`);
        break;
    }
  }

  /** A capture whose backend can check filters: the active one, else any open one. */
  private validator() {
    return this.provider.activeSession ?? this.provider.allSessions[0];
  }

  private dispose(): void {
    ColoringPanel.current = undefined;
    for (const d of this.disposables) {
      d.dispose();
    }
  }
}
