import * as path from "node:path";
import * as vscode from "vscode";
import { ErrorCodes, RpcError } from "../backendClient";
import type { PcapEditorSession } from "../pcapEditor";
import { safeFileName } from "../settingsModel";
import { panelHtml, webviewRoot } from "./panelHtml";

/** An object as the backend's export_objects lists it. */
export interface ExportedObject {
  id: number;
  protocol: string;
  name: string;
  size: number;
  frame: number | null;
  host: string;
  contentType: string;
}

type FromPanel =
  | { type: "ready" }
  | { type: "list" }
  | { type: "cancel" }
  | { type: "save"; id: number }
  | { type: "saveAll"; ids: number[] }
  | { type: "goto"; frame: number };

/**
 * Export Objects for one capture: the files carried by HTTP, SMB, TFTP, IMF,
 * DICOM and FTP-DATA, listed by the backend (one tshark pass, then cached) and
 * saved by it (file contents never pass through the webview).
 */
export class ObjectsPanel {
  private static readonly open = new Map<number, ObjectsPanel>();

  static show(context: vscode.ExtensionContext, session: PcapEditorSession): ObjectsPanel {
    const existing = ObjectsPanel.open.get(session.id);
    if (existing) {
      existing.panel.reveal(undefined, false);
      return existing;
    }
    const panel = new ObjectsPanel(context, session);
    ObjectsPanel.open.set(session.id, panel);
    return panel;
  }

  /** For tests: the open panels. */
  static get all(): readonly ObjectsPanel[] {
    return [...ObjectsPanel.open.values()];
  }

  readonly panel: vscode.WebviewPanel;
  /** The last list received (for tests). */
  objects: ExportedObject[] | undefined;
  private listing: number | undefined;
  private readonly disposables: vscode.Disposable[] = [];

  private constructor(
    context: vscode.ExtensionContext,
    readonly session: PcapEditorSession,
  ) {
    const title = `Export Objects · ${path.basename(session.uri.fsPath)}`;
    const root = webviewRoot(context);
    this.panel = vscode.window.createWebviewPanel(
      "pcapViewer.objects",
      title,
      vscode.ViewColumn.Beside,
      {
        enableScripts: true,
        localResourceRoots: [root],
        retainContextWhenHidden: true,
      },
    );
    this.panel.webview.html = panelHtml(this.panel.webview, root, "objects.js", title);
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
        this.post({
          type: "init",
          title: `Export Objects · ${path.basename(this.session.uri.fsPath)}`,
        });
        return this.list();
      case "list":
        return this.list();
      case "cancel":
        if (this.listing !== undefined) {
          this.session.backend?.cancel(this.listing);
        }
        return;
      case "save":
        return this.save([msg.id], false);
      case "saveAll":
        return this.save(msg.ids, true);
      case "goto":
        this.session.goTo(msg.frame);
        this.session.reveal();
        return;
    }
  }

  private async list(): Promise<void> {
    const client = this.session.backend;
    if (!client?.running) {
      this.post({
        type: "error",
        message: "The capture is not loaded (the PCAP backend is not running).",
      });
      return;
    }
    if (this.listing !== undefined) {
      client.cancel(this.listing);
    }
    const pending = client.send<{ objects: ExportedObject[] }>(
      "export_objects",
      {},
      {
        timeoutMs: 0,
        onProgress: (p) => this.post({ type: "progress", fraction: p.fraction ?? null }),
      },
    );
    this.listing = pending.id;
    try {
      const { objects } = await pending.promise;
      this.objects = objects;
      this.post({ type: "objects", objects });
    } catch (err) {
      const e = err instanceof RpcError ? err : new RpcError(String(err), ErrorCodes.InternalError);
      this.post({ type: "error", message: e.message, cancelled: e.cancelled });
    } finally {
      if (this.listing === pending.id) {
        this.listing = undefined;
      }
    }
  }

  private async save(ids: number[], many: boolean): Promise<void> {
    const client = this.session.backend;
    const chosen = ids
      .map((id) => this.objects?.find((o) => o.id === id))
      .filter((o): o is ExportedObject => !!o);
    if (!client?.running || !chosen.length) {
      return;
    }
    const folder = vscode.Uri.file(path.dirname(this.session.uri.fsPath));
    let params: { ids: number[]; dest?: string; dir?: string };
    if (many) {
      const picked = await vscode.window.showOpenDialog({
        canSelectFolders: true,
        canSelectFiles: false,
        defaultUri: folder,
        openLabel: `Save ${chosen.length} ${chosen.length === 1 ? "Object" : "Objects"} Here`,
        title: "Save Objects",
      });
      if (!picked?.[0]) {
        return;
      }
      params = { ids: chosen.map((o) => o.id), dir: picked[0].fsPath };
    } else {
      const dest = await vscode.window.showSaveDialog({
        defaultUri: vscode.Uri.joinPath(folder, safeFileName(chosen[0].name)),
        title: "Save Object",
      });
      if (!dest) {
        return;
      }
      params = { ids: [chosen[0].id], dest: dest.fsPath };
    }
    try {
      const { saved } = await vscode.window.withProgress(
        {
          location: vscode.ProgressLocation.Notification,
          title: "Saving objects",
          cancellable: true,
        },
        (_progress, token) =>
          client.request<{ saved: string[] }>("save_objects", params, {
            timeoutMs: 0,
            cancellation: token,
          }),
      );
      const where = many ? (params.dir ?? "") : saved[0];
      const reveal = "Reveal in File Explorer";
      const choice = await vscode.window.showInformationMessage(
        many
          ? `Saved ${saved.length} ${saved.length === 1 ? "object" : "objects"} to ${where}`
          : `Saved ${where}`,
        reveal,
      );
      if (choice === reveal) {
        await vscode.commands.executeCommand("revealFileInOS", vscode.Uri.file(saved[0]));
      }
    } catch (err) {
      if (!(err instanceof RpcError && err.cancelled)) {
        void vscode.window.showErrorMessage(
          `Saving objects failed: ${err instanceof Error ? err.message : String(err)}`,
        );
      }
    }
  }

  private dispose(): void {
    ObjectsPanel.open.delete(this.session.id);
    if (this.listing !== undefined) {
      this.session.backend?.cancel(this.listing);
    }
    for (const d of this.disposables) {
      d.dispose();
    }
  }
}
