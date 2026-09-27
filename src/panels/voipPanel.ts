import * as crypto from "node:crypto";
import * as fs from "node:fs/promises";
import * as path from "node:path";
import * as vscode from "vscode";
import { revealFile, revealLabel } from "../commands/reveal";
import { ErrorCodes, RpcError } from "../backendClient";
import type { PcapEditorSession } from "../pcapEditor";
import { audioFileName } from "../settingsModel";
import { panelHtml, webviewRoot } from "./panelHtml";

/** An RTP stream as the backend's voip_calls lists it. */
export interface RtpStream {
  src: string;
  srcPort: number;
  dst: string;
  dstPort: number;
  ssrc: string;
  payload: string;
  packets: number;
  lost: number;
  filter: string;
  heuristic?: boolean;
}

/** A SIP call as the backend's voip_calls lists it. */
export interface VoipCall {
  id: number;
  callId: string;
  from: string;
  to: string;
  state: string;
  streams: number[];
  filter: string;
}

type FromPanel =
  | { type: "ready" }
  | { type: "list"; heuristic: boolean }
  | { type: "analyse"; id: number; stream: RtpStream }
  | { type: "play"; id: number; stream: RtpStream }
  | { type: "save"; stream: RtpStream; format: "wav" | "raw" }
  | { type: "filter"; expr: string }
  | { type: "goto"; frame: number };

/**
 * VoIP calls of one capture: the SIP calls (with their message flow and
 * media), the RTP streams (packets, loss, jitter), a stream's packet-by-packet
 * analysis, and its audio, played in the panel or saved as WAV. The backend
 * does the passes and the decoding; audio reaches the webview as a file in
 * this panel's own folder (never through postMessage).
 */
export class VoipPanel {
  private static readonly open = new Map<number, VoipPanel>();

  static show(context: vscode.ExtensionContext, session: PcapEditorSession): VoipPanel {
    const existing = VoipPanel.open.get(session.id);
    if (existing) {
      existing.panel.reveal(undefined, false);
      return existing;
    }
    const panel = new VoipPanel(context, session);
    VoipPanel.open.set(session.id, panel);
    return panel;
  }

  /** For tests: the open panels. */
  static get all(): readonly VoipPanel[] {
    return [...VoipPanel.open.values()];
  }

  readonly panel: vscode.WebviewPanel;
  /** The last list received (for tests). */
  calls: { calls: VoipCall[]; streams: RtpStream[] } | undefined;
  private listing: number | undefined;
  /** Where played audio is written (removed with the panel). */
  private readonly audioDir: string;
  private audioSeq = 0;
  private readonly disposables: vscode.Disposable[] = [];

  private constructor(
    context: vscode.ExtensionContext,
    readonly session: PcapEditorSession,
  ) {
    const title = `VoIP Calls · ${path.basename(session.uri.fsPath)}`;
    const root = webviewRoot(context);
    // A file: path (the backend writes it; globalStorageUri may be vscode-userdata:).
    this.audioDir = path.join(
      context.globalStorageUri.fsPath,
      "audio",
      crypto.randomBytes(8).toString("hex"),
    );
    this.panel = vscode.window.createWebviewPanel(
      "pcapViewer.voip",
      title,
      vscode.ViewColumn.Beside,
      {
        enableScripts: true,
        localResourceRoots: [root, vscode.Uri.file(this.audioDir)],
        retainContextWhenHidden: true,
      },
    );
    this.panel.webview.html = panelHtml(this.panel.webview, root, "voip.js", title, {
      media: true,
    });
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
          title: `VoIP Calls · ${path.basename(this.session.uri.fsPath)}`,
        });
        return this.list(false);
      case "list":
        return this.list(msg.heuristic === true);
      case "analyse":
        return this.analyse(msg.id, msg.stream);
      case "play":
        return this.play(msg.id, msg.stream);
      case "save":
        return this.save(msg.stream, msg.format === "raw" ? "raw" : "wav");
      case "filter":
        if (typeof msg.expr === "string" && msg.expr) {
          this.session.applyFilter(msg.expr);
          this.session.reveal();
        }
        return;
      case "goto":
        this.session.goTo(msg.frame);
        this.session.reveal();
        return;
    }
  }

  private backend() {
    const client = this.session.backend;
    if (!client?.running) {
      this.post({
        type: "error",
        message: "The capture is not loaded (the PCAP backend is not running).",
      });
      return undefined;
    }
    return client;
  }

  private async list(heuristic: boolean): Promise<void> {
    const client = this.backend();
    if (!client) {
      return;
    }
    if (this.listing !== undefined) {
      client.cancel(this.listing);
    }
    const pending = client.send<{ calls: VoipCall[]; streams: RtpStream[] }>(
      "voip_calls",
      { heuristic },
      { timeoutMs: 0 },
    );
    this.listing = pending.id;
    try {
      const result = await pending.promise;
      this.calls = result;
      this.post({ type: "calls", ...result, heuristic });
    } catch (err) {
      this.postError(err);
    } finally {
      if (this.listing === pending.id) {
        this.listing = undefined;
      }
    }
  }

  private async analyse(id: number, stream: RtpStream): Promise<void> {
    const client = this.backend();
    if (!client) {
      return;
    }
    try {
      const result = await client.request("rtp_stream", { stream }, { timeoutMs: 0 });
      this.post({ type: "analysis", id, result });
    } catch (err) {
      this.postError(err, id);
    }
  }

  private async play(id: number, stream: RtpStream): Promise<void> {
    const client = this.backend();
    if (!client) {
      return;
    }
    try {
      await fs.mkdir(this.audioDir, { recursive: true });
      // A new name each time: the webview would otherwise replay a cached file.
      const file = path.join(this.audioDir, `stream-${++this.audioSeq}.wav`);
      const result = await client.request<Record<string, unknown>>(
        "rtp_audio",
        { stream, dest: file },
        { timeoutMs: 0 },
      );
      const uri = this.panel.webview.asWebviewUri(vscode.Uri.file(file)).toString();
      this.post({ type: "audio", id, uri, ...result });
    } catch (err) {
      this.postError(err, id);
    }
  }

  private async save(stream: RtpStream, format: "wav" | "raw"): Promise<void> {
    const client = this.backend();
    if (!client) {
      return;
    }
    const dest = await vscode.window.showSaveDialog({
      defaultUri: vscode.Uri.file(audioFileName(this.session.uri.fsPath, stream, format)),
      filters: format === "wav" ? { "WAV audio": ["wav"] } : { "Raw payload": ["raw"] },
      title: format === "wav" ? "Save Audio" : "Save RTP Payload",
    });
    if (!dest) {
      return;
    }
    try {
      await vscode.window.withProgress(
        {
          location: vscode.ProgressLocation.Notification,
          title: "Saving audio",
          cancellable: true,
        },
        (_progress, token) =>
          client.request(
            "rtp_audio",
            { stream, dest: dest.fsPath, format },
            {
              timeoutMs: 0,
              cancellation: token,
            },
          ),
      );
      const reveal = revealLabel();
      if ((await vscode.window.showInformationMessage(`Saved ${dest.fsPath}`, reveal)) === reveal) {
        await revealFile(dest.fsPath);
      }
    } catch (err) {
      if (err instanceof RpcError && err.cancelled) {
        return;
      }
      const unsupported =
        err instanceof RpcError && (err.data as { unsupported?: boolean })?.unsupported === true;
      const raw = "Save Raw Payload…";
      const choice = await vscode.window.showErrorMessage(
        `Saving the audio failed: ${err instanceof Error ? err.message : String(err)}`,
        ...(unsupported ? [raw] : []),
      );
      if (choice === raw) {
        await this.save(stream, "raw");
      }
    }
  }

  private postError(err: unknown, id?: number): void {
    const e = err instanceof RpcError ? err : new RpcError(String(err), ErrorCodes.InternalError);
    this.post({
      type: "error",
      id,
      message: e.message,
      cancelled: e.cancelled,
      unsupported: (e.data as { unsupported?: boolean } | undefined)?.unsupported === true,
    });
  }

  private dispose(): void {
    VoipPanel.open.delete(this.session.id);
    if (this.listing !== undefined) {
      this.session.backend?.cancel(this.listing);
    }
    void fs.rm(this.audioDir, { recursive: true, force: true });
    for (const d of this.disposables) {
      d.dispose();
    }
  }
}
