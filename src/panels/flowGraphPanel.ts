import * as path from "node:path";
import * as vscode from "vscode";
import { ErrorCodes, RpcError } from "../backendClient";
import type { PcapEditorSession } from "../pcapEditor";
import { panelHtml, webviewRoot } from "./panelHtml";

type FromPanel =
  | { type: "ready" }
  | { type: "query"; id: number; offset: number; limit: number }
  | { type: "cancel"; id: number }
  | { type: "goto"; frame: number };

/**
 * Flow graph of one capture: a sequence diagram of the displayed packets
 * between their endpoints, following the capture's display filter. One panel
 * per editor; the backend's flow_graph pages the arrows.
 */
export class FlowGraphPanel {
  private static readonly open = new Map<number, FlowGraphPanel>();

  static show(context: vscode.ExtensionContext, session: PcapEditorSession): FlowGraphPanel {
    const existing = FlowGraphPanel.open.get(session.id);
    if (existing) {
      existing.panel.reveal(undefined, false);
      return existing;
    }
    const panel = new FlowGraphPanel(context, session);
    FlowGraphPanel.open.set(session.id, panel);
    return panel;
  }

  /** For tests: the open panels. */
  static get all(): readonly FlowGraphPanel[] {
    return [...FlowGraphPanel.open.values()];
  }

  readonly panel: vscode.WebviewPanel;
  /** The first page received since the last reset (for tests). */
  firstPage: { total: number; nodes: string[] } | undefined;
  private readonly inflight = new Map<number, number>();
  private readonly disposables: vscode.Disposable[] = [];

  private constructor(
    context: vscode.ExtensionContext,
    readonly session: PcapEditorSession,
  ) {
    const title = `Flow Graph · ${path.basename(session.uri.fsPath)}`;
    const root = webviewRoot(context);
    this.panel = vscode.window.createWebviewPanel(
      "pcapViewer.flowGraph",
      title,
      vscode.ViewColumn.Beside,
      { enableScripts: true, localResourceRoots: [root], retainContextWhenHidden: true },
    );
    this.panel.webview.html = panelHtml(this.panel.webview, root, "flowgraph.js", title);
    this.disposables.push(
      this.panel.webview.onDidReceiveMessage((msg: FromPanel) => void this.onMessage(msg)),
      this.panel.onDidDispose(() => this.dispose()),
      this.panel.onDidChangeViewState((e) => e.webviewPanel.active && session.activate()),
      session.onDidDispose(() => this.panel.dispose()),
      session.onDidChangeFilter((filter) => {
        this.firstPage = undefined;
        this.post({ type: "reset", filter });
      }),
    );
  }

  private post(msg: unknown): void {
    void this.panel.webview.postMessage(msg);
  }

  private async onMessage(msg: FromPanel): Promise<void> {
    switch (msg.type) {
      case "ready":
        this.post({
          type: "init",
          title: `Flow Graph · ${path.basename(this.session.uri.fsPath)}`,
          filter: this.session.currentFilter,
        });
        return;
      case "query":
        return this.query(msg.id, msg.offset, msg.limit);
      case "cancel": {
        const backendId = this.inflight.get(msg.id);
        if (backendId !== undefined) {
          this.session.backend?.cancel(backendId);
        }
        return;
      }
      case "goto":
        this.session.goTo(msg.frame);
        return;
    }
  }

  private async query(id: number, offset: number, limit: number): Promise<void> {
    const client = this.session.backend;
    if (!client?.running) {
      this.post({
        type: "error",
        id,
        message: "The capture is not loaded (the PCAP backend is not running).",
      });
      return;
    }
    const pending = client.send<{ total: number; nodes: string[] }>(
      "flow_graph",
      { offset, limit },
      { timeoutMs: 0, onProgress: () => this.post({ type: "busy", id }) },
    );
    this.inflight.set(id, pending.id);
    try {
      const page = await pending.promise;
      if (offset === 0) {
        this.firstPage = page;
      }
      this.post({ type: "page", id, offset, page });
    } catch (err) {
      const e = err instanceof RpcError ? err : new RpcError(String(err), ErrorCodes.InternalError);
      const busy = e.code === ErrorCodes.Indexing;
      this.post({ type: "error", id, message: e.message, cancelled: e.cancelled, busy });
    } finally {
      this.inflight.delete(id);
    }
  }

  private dispose(): void {
    FlowGraphPanel.open.delete(this.session.id);
    for (const backendId of this.inflight.values()) {
      this.session.backend?.cancel(backendId);
    }
    for (const d of this.disposables) {
      d.dispose();
    }
  }
}
