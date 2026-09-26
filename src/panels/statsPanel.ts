import * as path from "node:path";
import * as vscode from "vscode";
import { ErrorCodes, RpcError } from "../backendClient";
import type { PcapEditorSession } from "../pcapEditor";
import { panelHtml, webviewRoot } from "./panelHtml";

export type StatsKind = "conversations" | "endpoints" | "phs" | "io" | "expert" | "properties";

export const STATS_TITLES: Record<StatsKind, string> = {
  conversations: "Conversations",
  endpoints: "Endpoints",
  phs: "Protocol Hierarchy",
  io: "I/O Graph",
  expert: "Expert Information",
  properties: "Capture File Properties",
};

type FromPanel =
  | { type: "ready" }
  | { type: "query"; id: number; params: { type?: string; interval?: number; limit?: boolean } }
  | { type: "cancel"; id: number }
  | { type: "filter"; expr: string; apply: boolean }
  | { type: "goto"; frame: number }
  | { type: "copy"; text: string };

/**
 * A statistics report for one capture, in a webview panel beside the editor.
 * One panel per (capture editor, kind); showing it again reveals the existing one.
 */
export class StatsPanel {
  private static readonly open = new Map<string, StatsPanel>();

  private readonly inflight = new Map<number, number>();
  private readonly disposables: vscode.Disposable[] = [];

  static show(context: vscode.ExtensionContext, session: PcapEditorSession, kind: StatsKind): StatsPanel {
    const key = `${session.id}:${kind}`;
    const existing = StatsPanel.open.get(key);
    if (existing) {
      existing.panel.reveal(undefined, false);
      return existing;
    }
    const panel = new StatsPanel(context, session, kind, key);
    StatsPanel.open.set(key, panel);
    return panel;
  }

  /** For tests: the open panels. */
  static get all(): readonly StatsPanel[] {
    return [...StatsPanel.open.values()];
  }

  readonly panel: vscode.WebviewPanel;

  private constructor(
    context: vscode.ExtensionContext,
    readonly session: PcapEditorSession,
    readonly kind: StatsKind,
    private readonly key: string,
  ) {
    const title = `${STATS_TITLES[kind]} · ${path.basename(session.uri.fsPath)}`;
    const root = webviewRoot(context);
    this.panel = vscode.window.createWebviewPanel("pcapViewer.stats", title, vscode.ViewColumn.Beside, {
      enableScripts: true,
      localResourceRoots: [root],
      retainContextWhenHidden: true,
    });
    this.panel.webview.html = panelHtml(this.panel.webview, root, "stats.js", title);
    this.disposables.push(
      this.panel.webview.onDidReceiveMessage((msg: FromPanel) => void this.onMessage(msg)),
      this.panel.onDidDispose(() => this.dispose()),
      this.panel.onDidChangeViewState((e) => e.webviewPanel.active && session.activate()),
      session.onDidDispose(() => this.panel.dispose()),
    );
  }

  private post(msg: unknown): void {
    void this.panel.webview.postMessage(msg);
  }

  private async onMessage(msg: FromPanel): Promise<void> {
    switch (msg.type) {
      case "ready":
        this.post({ type: "init", kind: this.kind, title: STATS_TITLES[this.kind], filter: this.session.currentFilter });
        return;
      case "query":
        return this.query(msg.id, msg.params);
      case "cancel": {
        const backendId = this.inflight.get(msg.id);
        if (backendId !== undefined) {
          this.session.backend?.cancel(backendId);
        }
        return;
      }
      case "filter":
        if (msg.apply) {
          this.session.applyFilter(msg.expr);
        } else {
          this.session.prepareFilter(msg.expr);
        }
        this.session.reveal();
        return;
      case "goto":
        this.session.goTo(msg.frame);
        this.session.reveal();
        return;
      case "copy":
        await vscode.env.clipboard.writeText(msg.text);
        vscode.window.setStatusBarMessage("Copied to clipboard", 2000);
        return;
    }
  }

  private async query(id: number, params: { type?: string; interval?: number; limit?: boolean }): Promise<void> {
    const client = this.session.backend;
    if (!client?.running) {
      this.post({ type: "error", id, message: "The capture is not loaded (the PCAP backend is not running)." });
      return;
    }
    const filter = params.limit ? this.session.currentFilter : "";
    const pending = client.send(
      "stats",
      { kind: this.kind, type: params.type, interval: params.interval, filter },
      { timeoutMs: 0 },
    );
    this.inflight.set(id, pending.id);
    try {
      const table = await pending.promise;
      this.post({ type: "result", id, table });
    } catch (err) {
      const e = err instanceof RpcError ? err : new RpcError(String(err), ErrorCodes.InternalError);
      this.post({ type: "error", id, message: e.message, cancelled: e.cancelled });
    } finally {
      this.inflight.delete(id);
    }
  }

  private dispose(): void {
    StatsPanel.open.delete(this.key);
    for (const backendId of this.inflight.values()) {
      this.session.backend?.cancel(backendId);
    }
    for (const d of this.disposables) {
      d.dispose();
    }
  }
}
