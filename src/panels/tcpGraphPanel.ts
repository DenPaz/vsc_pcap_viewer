import * as path from "node:path";
import * as vscode from "vscode";
import { ErrorCodes, RpcError } from "../backendClient";
import type { PcapEditorSession } from "../pcapEditor";
import { panelHtml, webviewRoot } from "./panelHtml";

type FromPanel =
  | { type: "ready" }
  | { type: "query"; id: number; stream?: number; frame?: number }
  | { type: "goto"; frame: number };

/**
 * TCP stream graphs of one capture (Stevens, throughput, round-trip time,
 * window). One panel per editor; showing it again switches to the stream of
 * the packet asked for. The backend's tcp_graph reads one stream per pass.
 */
export class TcpGraphPanel {
  private static readonly open = new Map<number, TcpGraphPanel>();

  static show(
    context: vscode.ExtensionContext,
    session: PcapEditorSession,
    frame: number,
  ): TcpGraphPanel {
    const existing = TcpGraphPanel.open.get(session.id);
    if (existing) {
      existing.panel.reveal(undefined, false);
      existing.post({ type: "show", frame });
      return existing;
    }
    const panel = new TcpGraphPanel(context, session, frame);
    TcpGraphPanel.open.set(session.id, panel);
    return panel;
  }

  /** For tests: the open panels. */
  static get all(): readonly TcpGraphPanel[] {
    return [...TcpGraphPanel.open.values()];
  }

  readonly panel: vscode.WebviewPanel;
  /** The last stream shown (for tests). */
  current: { stream: number; endpoints: string[]; points: unknown[][] } | undefined;
  private readonly disposables: vscode.Disposable[] = [];

  private constructor(
    context: vscode.ExtensionContext,
    readonly session: PcapEditorSession,
    private readonly frame: number,
  ) {
    const title = `TCP Stream Graph · ${path.basename(session.uri.fsPath)}`;
    const root = webviewRoot(context);
    this.panel = vscode.window.createWebviewPanel(
      "pcapViewer.tcpGraph",
      title,
      vscode.ViewColumn.Beside,
      { enableScripts: true, localResourceRoots: [root], retainContextWhenHidden: true },
    );
    this.panel.webview.html = panelHtml(this.panel.webview, root, "tcpgraph.js", title);
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
        this.post({ type: "init", frame: this.frame });
        return;
      case "query":
        return this.query(msg.id, msg.stream, msg.frame);
      case "goto":
        this.session.goTo(msg.frame);
        return;
    }
  }

  private async query(id: number, stream?: number, frame?: number): Promise<void> {
    const client = this.session.backend;
    if (!client?.running) {
      this.post({
        type: "error",
        id,
        message: "The capture is not loaded (the PCAP backend is not running).",
      });
      return;
    }
    try {
      const result = await client.request<{
        stream: number;
        endpoints: string[];
        points: unknown[][];
      }>("tcp_graph", stream !== undefined ? { stream } : { frame }, { timeoutMs: 0 });
      this.current = result;
      this.post({ type: "stream", id, result });
    } catch (err) {
      const e = err instanceof RpcError ? err : new RpcError(String(err), ErrorCodes.InternalError);
      this.post({ type: "error", id, message: e.message, cancelled: e.cancelled });
    }
  }

  private dispose(): void {
    TcpGraphPanel.open.delete(this.session.id);
    for (const d of this.disposables) {
      d.dispose();
    }
  }
}
