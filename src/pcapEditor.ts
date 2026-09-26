import * as crypto from "node:crypto";
import * as fs from "node:fs";
import * as vscode from "vscode";
import { BackendClient, ErrorCodes, RpcError, findPython } from "./backendClient";
import { Settings, readSettings } from "./config";
import { ColoringResult, HostToWebview, OpenResult, WEBVIEW_RPC_METHODS, WebviewToHost } from "./messages";
import { saveFilterInteractive, showSavedFilters } from "./commands/savedFilters";
import { FollowPanel } from "./panels/followPanel";
import { ColumnSetting, SavedFilter, pushHistory } from "./settingsModel";

const HISTORY_KEY = "pcapViewer.filterHistory";
/** Coloring problems already shown in a notification (each is reported once per window). */
const reportedColoringErrors = new Set<string>();

class PcapDocument implements vscode.CustomDocument {
  constructor(readonly uri: vscode.Uri) {}
  dispose(): void {}
}

/**
 * Read-only custom editor for capture files. Each editor panel owns one
 * backend process (the backend keeps per-view filter/sort state).
 */
export class PcapEditorProvider implements vscode.CustomReadonlyEditorProvider<PcapDocument> {
  static readonly viewType = "pcapViewer.editor";

  private readonly sessions = new Set<PcapEditorSession>();
  private active?: PcapEditorSession;

  constructor(
    private readonly context: vscode.ExtensionContext,
    private readonly log: vscode.LogOutputChannel,
  ) {}

  static register(context: vscode.ExtensionContext, log: vscode.LogOutputChannel): PcapEditorProvider {
    const provider = new PcapEditorProvider(context, log);
    context.subscriptions.push(
      vscode.window.registerCustomEditorProvider(PcapEditorProvider.viewType, provider, {
        webviewOptions: { retainContextWhenHidden: true },
        supportsMultipleEditorsPerDocument: true,
      }),
    );
    return provider;
  }

  openCustomDocument(uri: vscode.Uri): PcapDocument {
    return new PcapDocument(uri);
  }

  resolveCustomEditor(document: PcapDocument, panel: vscode.WebviewPanel): void {
    const session = new PcapEditorSession(this.context, document.uri, panel, this.log);
    this.sessions.add(session);
    this.active = session;
    panel.onDidChangeViewState(() => {
      if (panel.active) {
        this.active = session;
      }
    });
    // Focusing one of this capture's statistics/follow panels makes it the
    // target of capture commands too (not whichever editor was focused last).
    session.onDidActivate(() => (this.active = session));
    panel.onDidDispose(() => {
      this.sessions.delete(session);
      if (this.active === session) {
        this.active = undefined;
      }
      void session.dispose();
    });
  }

  get activeSession(): PcapEditorSession | undefined {
    return this.active;
  }

  get allSessions(): readonly PcapEditorSession[] {
    return [...this.sessions];
  }

  async disposeAll(): Promise<void> {
    await Promise.all([...this.sessions].map((s) => s.dispose()));
    this.sessions.clear();
  }
}

let nextSessionId = 1;

export class PcapEditorSession {
  /** Unique per editor panel (keys the statistics panels). */
  readonly id = nextSessionId++;
  /** Frame currently selected in the packet list, if any. */
  selectedFrame: number | null = null;
  private readonly disposeEmitter = new vscode.EventEmitter<void>();
  /** Fires when the editor closes (auxiliary panels close with it). */
  readonly onDidDispose = this.disposeEmitter.event;
  private readonly activateEmitter = new vscode.EventEmitter<void>();
  /** Fires when one of this capture's auxiliary panels gains focus. */
  readonly onDidActivate = this.activateEmitter.event;
  private client?: BackendClient;
  private info?: OpenResult;
  private filter = "";
  private loading?: { id: number; client: BackendClient };
  /** webview request id -> backend request id (for cancellation). */
  private readonly inflight = new Map<number, number>();
  private readonly disposables: vscode.Disposable[] = [];
  private disposed = false;
  private loadSeq = 0;
  private coloring?: { id: number; client: BackendClient };
  private readonly ready: Promise<void>;

  constructor(
    private readonly context: vscode.ExtensionContext,
    readonly uri: vscode.Uri,
    readonly panel: vscode.WebviewPanel,
    private readonly log: vscode.LogOutputChannel,
  ) {
    const webviewRoot = vscode.Uri.joinPath(context.extensionUri, "src", "webview");
    panel.webview.options = { enableScripts: true, localResourceRoots: [webviewRoot] };
    panel.webview.html = this.renderHtml(webviewRoot);
    let markReady: () => void = () => undefined;
    this.ready = new Promise((resolve) => (markReady = resolve));
    this.disposables.push(
      panel.webview.onDidReceiveMessage((msg: WebviewToHost) => {
        if (msg.type === "ready") {
          markReady();
        }
        void this.onMessage(msg);
      }),
    );
    void this.ready.then(() => this.load());
  }

  get openInfo(): OpenResult | undefined {
    return this.info;
  }

  get backend(): BackendClient | undefined {
    return this.client;
  }

  get currentFilter(): string {
    return this.filter;
  }

  /** (Re)start the backend and index the file. */
  async load(): Promise<void> {
    const seq = ++this.loadSeq;
    const settings = readSettings(this.uri);
    await this.stopBackend();
    if (this.disposed || seq !== this.loadSeq) {
      return;
    }
    this.post({ type: "loading", message: "Starting backend…" });

    const py = findPython(settings.pythonPath || undefined);
    if ("error" in py) {
      this.fail(py.error, "pythonPath");
      return;
    }
    const client = new BackendClient({
      python: py.python,
      backendDir: vscode.Uri.joinPath(this.context.extensionUri, "backend").fsPath,
      logger: {
        info: (m) => this.log.info(m),
        warn: (m) => this.log.warn(m),
        error: (m) => this.log.error(m),
      },
      maxCachedFrames: settings.maxCachedFrames,
      defaultTimeoutMs: settings.requestTimeoutMs,
    });
    this.client = client;
    client.onExit(({ expected }) => {
      if (!expected && this.client === client && !this.disposed) {
        this.client = undefined;
        this.post({ type: "error", message: "The PCAP backend stopped unexpectedly. See the PCAP Viewer log for details.", canReload: true });
      }
    });

    const started = Date.now();
    try {
      client.start();
      const init = await client.request<{ version: string; tsharkPath: string }>("initialize", { tsharkPath: settings.tsharkPath || undefined }, { timeoutMs: 30_000 });
      this.log.info(`using ${init.version} at ${init.tsharkPath} (python ${py.version})`);
      this.post({ type: "loading", message: "Indexing packets…" });
      const info = await this.openFile(client, settings);
      if (seq !== this.loadSeq || this.disposed) {
        return;
      }
      this.info = info;
      const warnings = [...settings.luaWarnings, ...info.warnings];
      for (const w of warnings) {
        this.log.warn(`${this.uri.fsPath}: ${w}`);
      }
      // Lua load errors are errors, not warnings: say so and point at the log.
      const luaErrors = warnings.filter((w) => w.startsWith("Lua:"));
      const others = warnings.filter((w) => !w.startsWith("Lua:"));
      if (luaErrors.length) {
        const first = luaErrors[0].split("\n")[0].replace(/^Lua: /, "");
        void vscode.window
          .showErrorMessage(`PCAP Viewer: Lua dissector error: ${first}${luaErrors.length > 1 ? ` (+${luaErrors.length - 1} more)` : ""}`, "Show Log")
          .then((choice) => choice && this.log.show());
      }
      if (others.length) {
        void vscode.window.showWarningMessage(`PCAP Viewer: ${others[0]}${others.length > 1 ? ` (+${others.length - 1} more)` : ""}`, "Show Log").then((choice) => {
          if (choice) {
            this.log.show();
          }
        });
      }
      this.post({
        type: "init",
        info,
        columns: settings.columns,
        filter: this.filter,
        history: this.history(),
        savedFilters: settings.savedFilters,
        elapsedMs: Date.now() - started,
      });
      void this.applyColoring();
    } catch (err) {
      if (seq !== this.loadSeq || this.disposed) {
        return;
      }
      if (err instanceof RpcError && err.cancelled) {
        this.post({ type: "error", message: "Loading was cancelled.", canReload: true });
        await this.stopBackend();
        return;
      }
      const setting = err instanceof RpcError && err.code === ErrorCodes.TsharkNotFound ? "tsharkPath" : undefined;
      this.fail(describeError(err), setting);
    }
  }

  private async openFile(client: BackendClient, settings: Settings): Promise<OpenResult> {
    return vscode.window.withProgress(
      { location: vscode.ProgressLocation.Window, title: `Indexing ${vscode.workspace.asRelativePath(this.uri)}` },
      async (progress) => {
        const pending = client.send<OpenResult>(
          "open",
          {
            path: this.uri.fsPath,
            lua: settings.luaScripts,
            decodeAs: settings.decodeAs,
            prefs: settings.prefs,
            columns: settings.columns.map((c) => c.field),
          },
          {
            timeoutMs: 0,
            onProgress: (p) => {
              this.post({ type: "progress", phase: p.phase, fraction: p.fraction, frames: p.frames });
              if (typeof p.frames === "number") {
                progress.report({ message: `${p.frames.toLocaleString()} packets` });
              }
            },
          },
        );
        this.loading = { id: pending.id, client };
        try {
          return await pending.promise;
        } finally {
          this.loading = undefined;
        }
      },
    );
  }

  private fail(message: string, setting?: "tsharkPath" | "pythonPath"): void {
    this.log.error(`${this.uri.fsPath}: ${message}`);
    this.post({ type: "error", message, canReload: true });
    const actions = setting ? ["Open Settings", ...(setting === "tsharkPath" ? ["Download Wireshark"] : [])] : ["Show Log"];
    void vscode.window.showErrorMessage(`PCAP Viewer: ${message}`, ...actions).then((choice) => {
      if (choice === "Open Settings") {
        void vscode.commands.executeCommand("workbench.action.openSettings", `pcapViewer.${setting}`);
      } else if (choice === "Download Wireshark") {
        void vscode.env.openExternal(vscode.Uri.parse("https://www.wireshark.org/download.html"));
      } else if (choice === "Show Log") {
        this.log.show();
      }
    });
  }

  private async onMessage(msg: WebviewToHost): Promise<void> {
    switch (msg.type) {
      case "ready":
        return;
      case "rpc":
        return this.forwardRpc(msg.id, msg.method, msg.params);
      case "cancel": {
        const backendId = this.inflight.get(msg.id);
        if (backendId !== undefined) {
          this.client?.cancel(backendId);
        }
        return;
      }
      case "cancelLoad":
        if (this.loading) {
          this.loading.client.cancel(this.loading.id);
        }
        return;
      case "reload":
        return this.load();
      case "filterApplied":
        this.filter = msg.expr;
        if (msg.expr.trim()) {
          const history = pushHistory(this.history(), msg.expr);
          await this.context.globalState.update(HISTORY_KEY, history);
          this.post({ type: "history", history });
        }
        return;
      case "saveFilter":
        await saveFilterInteractive(msg.expr, this);
        return;
      case "manageSavedFilters":
        await showSavedFilters(this);
        return;
      case "selection":
        this.selectedFrame = typeof msg.frame === "number" ? msg.frame : null;
        return;
      case "follow":
        FollowPanel.show(this.context, this, msg.proto, msg.frame);
        return;
      case "decodeAs":
        await vscode.commands.executeCommand("pcapViewer.decodeAs", msg.frame);
        return;
      case "colorize":
        await vscode.commands.executeCommand("pcapViewer.colorizeWithFilter", msg.filter);
        return;
      case "exportBytes":
        await vscode.commands.executeCommand("pcapViewer.exportPacketBytes", msg.frame);
        return;
      case "copy":
        await vscode.env.clipboard.writeText(String(msg.text));
        vscode.window.setStatusBarMessage("Copied to clipboard", 2000);
        return;
      case "showLog":
        this.log.show();
        return;
    }
  }

  private async forwardRpc(id: number, method: string, params: Record<string, unknown>): Promise<void> {
    if (!WEBVIEW_RPC_METHODS.has(method)) {
      this.post({ type: "rpcError", id, error: { code: ErrorCodes.MethodNotFound, message: `method not allowed: ${method}` } });
      return;
    }
    const client = this.client;
    if (!client?.running) {
      this.post({ type: "rpcError", id, error: { code: ErrorCodes.BackendExited, message: "The PCAP backend is not running" } });
      return;
    }
    // Long-running methods are cancellable instead of timed out.
    const longRunning = method === "set_filter" || method === "list_packets" || method === "packet_detail";
    const pending = client.send(method, params ?? {}, {
      timeoutMs: longRunning ? 0 : undefined,
      onProgress: (p) => this.post({ type: "progress", phase: p.phase, fraction: p.fraction, frames: p.frames, matched: p.matched }),
    });
    this.inflight.set(id, pending.id);
    try {
      const result = await pending.promise;
      this.post({ type: "rpcResult", id, result });
    } catch (err) {
      const e = err instanceof RpcError ? err : new RpcError(String(err), ErrorCodes.InternalError);
      if (!e.cancelled && e.code !== ErrorCodes.InvalidFilter) {
        this.log.warn(`${method} failed: ${e.message}`);
      }
      this.post({ type: "rpcError", id, error: { code: e.code, message: e.message, data: e.data } });
    } finally {
      this.inflight.delete(id);
    }
  }

  // ------------------------------------------------------------------ coloring

  /**
   * Evaluate the coloring rules in the backend (one tshark pass, in the
   * background) and send the palette to the webview once rows carry colors.
   * A newer call cancels a running one.
   */
  async applyColoring(): Promise<void> {
    const client = this.client;
    if (!client?.running || !this.info) {
      return;
    }
    if (this.coloring?.client === client) {
      client.cancel(this.coloring.id);
    }
    const settings = readSettings(this.uri);
    const rules = settings.colorize ? settings.coloringRules : [];
    const pending = client.send<ColoringResult>(
      "set_coloring",
      { rules: rules.map((r) => ({ filter: r.filter, foreground: r.foreground, background: r.background })) },
      { timeoutMs: 0 },
    );
    const coloring = { id: pending.id, client };
    this.coloring = coloring;
    let result: ColoringResult;
    try {
      result = await (rules.length
        ? vscode.window.withProgress({ location: vscode.ProgressLocation.Window, title: "Colorizing packets" }, () => pending.promise)
        : pending.promise);
    } catch (err) {
      if (!(err instanceof RpcError && err.cancelled) && this.client === client) {
        this.log.warn(`${this.uri.fsPath}: coloring failed: ${describeError(err)}`);
      }
      return;
    } finally {
      if (this.coloring === coloring) {
        this.coloring = undefined;
      }
    }
    if (this.client !== client || this.disposed) {
      return;
    }
    const problems = Object.entries(result.errors).map(([i, message]) => `Coloring rule "${rules[Number(i)]?.name ?? i}" skipped: ${message}`);
    for (const p of problems) {
      this.log.warn(p);
    }
    const fresh = problems.filter((p) => !reportedColoringErrors.has(p));
    if (fresh.length) {
      fresh.forEach((p) => reportedColoringErrors.add(p));
      void vscode.window.showWarningMessage(`PCAP Viewer: ${fresh[0]}${fresh.length > 1 ? ` (+${fresh.length - 1} more)` : ""}`, "Edit Rules", "Show Log").then((choice) => {
        if (choice === "Edit Rules") {
          void vscode.commands.executeCommand("pcapViewer.manageColoringRules");
        } else if (choice === "Show Log") {
          this.log.show();
        }
      });
    }
    this.post({
      type: "coloring",
      coloringId: result.coloringId,
      rules: rules.map((r) => ({ name: r.name, foreground: r.foreground, background: r.background })),
    });
  }

  // ------------------------------------------------------------------ commands

  applyFilter(expr: string): void {
    this.post({ type: "applyFilter", expr });
  }

  /** Put a filter in the filter bar without applying it ("Prepare as Filter"). */
  prepareFilter(expr: string): void {
    this.post({ type: "prepareFilter", expr });
  }

  /** Called by this capture's panels when they gain focus. */
  activate(): void {
    this.activateEmitter.fire();
  }

  /** Bring the capture editor to the front (e.g. after a panel applied a filter). */
  reveal(): void {
    this.panel.reveal(undefined, false);
  }

  focusFilter(): void {
    this.post({ type: "focusFilter" });
  }

  goTo(frame: number): void {
    this.post({ type: "goto", number: frame });
  }

  setColumns(columns: ColumnSetting[]): void {
    this.post({ type: "columns", columns });
  }

  setSavedFilters(savedFilters: SavedFilter[]): void {
    this.post({ type: "savedFilters", savedFilters });
  }

  async validateFilter(expr: string): Promise<string | undefined> {
    if (!this.client?.running) {
      return undefined;
    }
    try {
      const res = await this.client.request<{ valid: boolean; error?: string }>("validate_filter", { expr });
      return res.valid ? undefined : res.error;
    } catch {
      return undefined;
    }
  }

  // ------------------------------------------------------------------ plumbing

  private history(): string[] {
    return this.context.globalState.get<string[]>(HISTORY_KEY, []);
  }

  private post(msg: HostToWebview): void {
    if (!this.disposed) {
      void this.panel.webview.postMessage(msg);
    }
  }

  private async stopBackend(): Promise<void> {
    const client = this.client;
    this.client = undefined;
    this.info = undefined;
    this.coloring = undefined;
    this.inflight.clear();
    if (client) {
      await client.dispose();
    }
  }

  async dispose(): Promise<void> {
    if (this.disposed) {
      return;
    }
    this.disposed = true;
    this.loadSeq++;
    this.disposeEmitter.fire();
    this.disposeEmitter.dispose();
    this.activateEmitter.dispose();
    for (const d of this.disposables) {
      d.dispose();
    }
    await this.stopBackend();
  }

  private renderHtml(root: vscode.Uri): string {
    const webview = this.panel.webview;
    const nonce = crypto.randomBytes(16).toString("base64");
    const template = fs.readFileSync(vscode.Uri.joinPath(root, "index.html").fsPath, "utf8");
    const values: Record<string, string> = {
      cspSource: webview.cspSource,
      nonce,
      stylesUri: webview.asWebviewUri(vscode.Uri.joinPath(root, "styles.css")).toString(),
      libUri: webview.asWebviewUri(vscode.Uri.joinPath(root, "lib.js")).toString(),
      mainUri: webview.asWebviewUri(vscode.Uri.joinPath(root, "main.js")).toString(),
    };
    return template.replace(/\{\{(\w+)\}\}/g, (_m, key: string) => values[key] ?? "");
  }
}

export function describeError(err: unknown): string {
  if (err instanceof RpcError) {
    const stderr = (err.data as { stderr?: string } | undefined)?.stderr;
    return stderr && !err.message.includes(stderr) ? `${err.message}\n${stderr}` : err.message;
  }
  return err instanceof Error ? err.message : String(err);
}
