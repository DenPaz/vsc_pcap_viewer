/**
 * JSON-RPC client for the Python backend (newline-delimited JSON over stdio).
 *
 * Deliberately free of `vscode` imports so it can be unit-tested with plain
 * Node. The process is spawned with an argument array (never a shell).
 */
import { ChildProcess, spawn, spawnSync } from "node:child_process";
import { EventEmitter } from "node:events";

export interface Logger {
  info(message: string): void;
  warn(message: string): void;
  error(message: string): void;
}

export interface BackendOptions {
  /** Python executable plus leading args, e.g. ["py", "-3"]. */
  python: string[];
  /** Directory containing the `pcap_backend` package. */
  backendDir: string;
  logger: Logger;
  maxCachedFrames?: number;
  /** Default timeout for requests that don't specify one (ms). 0 = none. */
  defaultTimeoutMs?: number;
}

export interface Progress {
  requestId: number;
  method: string;
  phase?: string;
  fraction?: number | null;
  frames?: number;
  matched?: number;
}

export interface RequestOptions {
  /** 0 disables the timeout (use for cancellable long operations). */
  timeoutMs?: number;
  onProgress?: (p: Progress) => void;
  /** Anything with VS Code's CancellationToken shape. */
  cancellation?: { isCancellationRequested: boolean; onCancellationRequested(cb: () => void): { dispose(): void } };
}

/** Error codes shared with backend/pcap_backend/protocol.py. */
export const ErrorCodes = {
  ParseError: -32700,
  InvalidRequest: -32600,
  MethodNotFound: -32601,
  InvalidParams: -32602,
  InternalError: -32603,
  RequestCancelled: -32800,
  TsharkNotFound: -32001,
  TsharkFailed: -32002,
  NotOpen: -32003,
  InvalidFilter: -32010,
  UnsupportedFormat: -32011,
  /** The streaming index pass is still running (filters, sorting… wait for it). */
  Indexing: -32012,
  // Client-side codes.
  Timeout: -33001,
  BackendExited: -33002,
} as const;

export class RpcError extends Error {
  constructor(
    message: string,
    readonly code: number,
    readonly data?: unknown,
  ) {
    super(message);
    this.name = "RpcError";
  }

  get cancelled(): boolean {
    return this.code === ErrorCodes.RequestCancelled;
  }
}

interface Pending {
  method: string;
  resolve(value: unknown): void;
  reject(err: RpcError): void;
  timer?: NodeJS.Timeout;
  onProgress?: (p: Progress) => void;
  disposeCancel?: () => void;
}

export interface PendingRequest<T> {
  id: number;
  promise: Promise<T>;
}

export class BackendClient {
  private proc?: ChildProcess;
  private nextId = 1;
  private readonly pending = new Map<number, Pending>();
  private buffer = "";
  private stderrBuffer = "";
  private readonly events = new EventEmitter();
  private disposed = false;
  private exitPromise?: Promise<void>;

  constructor(private readonly opts: BackendOptions) {}

  get running(): boolean {
    return !!this.proc && this.proc.exitCode === null && this.proc.signalCode === null;
  }

  get pid(): number | undefined {
    return this.proc?.pid;
  }

  /** Fires when the backend process exits (expectedly or not). */
  onExit(listener: (info: { code: number | null; signal: NodeJS.Signals | null; expected: boolean }) => void): () => void {
    this.events.on("exit", listener);
    return () => this.events.off("exit", listener);
  }

  /** Backend notifications other than request progress (e.g. "index" of a streaming open). */
  onNotification(method: string, listener: (params: Record<string, unknown>) => void): () => void {
    const handler = (m: string, params: Record<string, unknown>) => {
      if (m === method) {
        listener(params);
      }
    };
    this.events.on("notification", handler);
    return () => this.events.off("notification", handler);
  }

  start(): void {
    if (this.running) {
      return;
    }
    if (this.disposed) {
      throw new Error("backend client disposed");
    }
    const [cmd, ...pre] = this.opts.python;
    const args = [...pre, "-u", "-m", "pcap_backend"];
    if (this.opts.maxCachedFrames) {
      args.push("--max-cached-frames", String(this.opts.maxCachedFrames));
    }
    const env = { ...process.env, PYTHONPATH: joinPath(this.opts.backendDir, process.env.PYTHONPATH), PYTHONIOENCODING: "utf-8" };
    this.opts.logger.info(`starting backend: ${[cmd, ...args].join(" ")}`);
    const proc = spawn(cmd, args, {
      cwd: this.opts.backendDir,
      env,
      stdio: ["pipe", "pipe", "pipe"],
      windowsHide: true,
      shell: false,
    });
    this.proc = proc;
    this.buffer = "";
    proc.stdout.setEncoding("utf8");
    proc.stderr.setEncoding("utf8");
    proc.stdout.on("data", (chunk: string) => this.onStdout(chunk));
    proc.stderr.on("data", (chunk: string) => this.onStderr(chunk));
    proc.stdin.on("error", (err) => this.opts.logger.warn(`backend stdin: ${err.message}`));
    this.exitPromise = new Promise((resolve) => {
      let settled = false;
      const finish = (code: number | null, signal: NodeJS.Signals | null) => {
        if (settled) {
          return;
        }
        settled = true;
        if (this.stderrBuffer) {
          this.opts.logger.info(`[backend] ${this.stderrBuffer}`);
          this.stderrBuffer = "";
        }
        const expected = this.disposed || this.proc !== proc;
        (expected ? this.opts.logger.info : this.opts.logger.error).call(
          this.opts.logger,
          `backend exited (code=${code}, signal=${signal})`,
        );
        if (this.proc === proc) {
          this.proc = undefined;
          this.rejectAll(new RpcError("The PCAP backend process exited", ErrorCodes.BackendExited, { code, signal }));
        }
        this.events.emit("exit", { code, signal, expected });
        resolve();
      };
      proc.on("exit", finish);
      proc.on("error", (err) => {
        this.opts.logger.error(`failed to start backend (${cmd}): ${err.message}`);
        finish(null, null);
      });
    });
  }

  request<T>(method: string, params: object = {}, options: RequestOptions = {}): Promise<T> {
    return this.send<T>(method, params, options).promise;
  }

  /** Like {@link request} but also exposes the request id (for {@link cancel}). */
  send<T>(method: string, params: object = {}, options: RequestOptions = {}): PendingRequest<T> {
    const id = this.nextId++;
    const promise = new Promise<T>((resolve, reject) => {
      if (!this.running || !this.proc?.stdin?.writable) {
        reject(new RpcError("The PCAP backend is not running", ErrorCodes.BackendExited));
        return;
      }
      const pending: Pending = { method, resolve: resolve as (v: unknown) => void, reject, onProgress: options.onProgress };
      const timeoutMs = options.timeoutMs ?? this.opts.defaultTimeoutMs ?? 0;
      if (timeoutMs > 0) {
        pending.timer = setTimeout(() => {
          this.cancel(id);
          this.settle(id, undefined, new RpcError(`${method} timed out after ${Math.round(timeoutMs / 1000)}s`, ErrorCodes.Timeout));
        }, timeoutMs);
      }
      if (options.cancellation) {
        if (options.cancellation.isCancellationRequested) {
          reject(new RpcError("request cancelled", ErrorCodes.RequestCancelled));
          return;
        }
        const sub = options.cancellation.onCancellationRequested(() => this.cancel(id));
        pending.disposeCancel = () => sub.dispose();
      }
      this.pending.set(id, pending);
      this.write({ jsonrpc: "2.0", id, method, params });
    });
    return { id, promise };
  }

  /** Ask the backend to cancel request `id`; the request then rejects with RequestCancelled. */
  cancel(id: number): void {
    if (this.pending.has(id) && this.running) {
      this.write({ jsonrpc: "2.0", method: "cancel", params: { requestId: id } });
    }
  }

  /**
   * Stop the backend. Closing stdin lets it cancel work and kill its tshark
   * children itself; SIGTERM/SIGKILL (or a tree kill on Windows) follow if it
   * does not exit in time, so no process is left orphaned.
   */
  async stop(graceMs = 2000): Promise<void> {
    const proc = this.proc;
    if (!proc) {
      return;
    }
    this.proc = undefined;
    this.rejectAll(new RpcError("The PCAP backend was stopped", ErrorCodes.BackendExited));
    const exited = this.exitPromise ?? Promise.resolve();
    proc.stdin?.end();
    if (await waitFor(exited, graceMs)) {
      return;
    }
    if (process.platform === "win32" && proc.pid) {
      // Kill the whole tree (python + tshark children).
      spawnSync("taskkill", ["/PID", String(proc.pid), "/T", "/F"], { windowsHide: true, shell: false });
    } else {
      proc.kill("SIGTERM");
    }
    if (await waitFor(exited, 1000)) {
      return;
    }
    proc.kill("SIGKILL");
    await waitFor(exited, 1000);
  }

  async dispose(): Promise<void> {
    this.disposed = true;
    await this.stop();
    this.events.removeAllListeners();
  }

  private write(msg: object): void {
    try {
      this.proc?.stdin?.write(JSON.stringify(msg) + "\n");
    } catch (err) {
      this.opts.logger.error(`failed to write to backend: ${String(err)}`);
    }
  }

  private onStdout(chunk: string): void {
    this.buffer += chunk;
    let nl: number;
    while ((nl = this.buffer.indexOf("\n")) >= 0) {
      const line = this.buffer.slice(0, nl).trim();
      this.buffer = this.buffer.slice(nl + 1);
      if (line) {
        this.onLine(line);
      }
    }
  }

  private onStderr(chunk: string): void {
    this.stderrBuffer += chunk;
    let nl: number;
    while ((nl = this.stderrBuffer.indexOf("\n")) >= 0) {
      const line = this.stderrBuffer.slice(0, nl).trimEnd();
      this.stderrBuffer = this.stderrBuffer.slice(nl + 1);
      if (line) {
        this.opts.logger.info(`[backend] ${line}`);
      }
    }
  }

  private onLine(line: string): void {
    let msg: { id?: number | string | null; method?: string; params?: unknown; result?: unknown; error?: { code: number; message: string; data?: unknown } };
    try {
      msg = JSON.parse(line);
    } catch {
      this.opts.logger.warn(`[backend] non-JSON output: ${line.slice(0, 200)}`);
      return;
    }
    if (msg.method && (msg.id === undefined || msg.id === null)) {
      if (msg.method === "progress") {
        const p = msg.params as Progress;
        this.pending.get(p.requestId)?.onProgress?.(p);
      } else {
        this.events.emit("notification", msg.method, (msg.params ?? {}) as Record<string, unknown>);
      }
      return;
    }
    if (typeof msg.id !== "number") {
      if (msg.error) {
        this.opts.logger.error(`[backend] ${msg.error.message}`);
      }
      return;
    }
    if (msg.error) {
      this.settle(msg.id, undefined, new RpcError(msg.error.message, msg.error.code, msg.error.data));
    } else {
      this.settle(msg.id, msg.result);
    }
  }

  private settle(id: number, result: unknown, error?: RpcError): void {
    const pending = this.pending.get(id);
    if (!pending) {
      return;
    }
    this.pending.delete(id);
    if (pending.timer) {
      clearTimeout(pending.timer);
    }
    pending.disposeCancel?.();
    if (error) {
      pending.reject(error);
    } else {
      pending.resolve(result);
    }
  }

  private rejectAll(error: RpcError): void {
    for (const id of [...this.pending.keys()]) {
      this.settle(id, undefined, error);
    }
  }
}

function joinPath(first: string, rest: string | undefined): string {
  const sep = process.platform === "win32" ? ";" : ":";
  return rest ? `${first}${sep}${rest}` : first;
}

function waitFor(promise: Promise<void>, ms: number): Promise<boolean> {
  return new Promise((resolve) => {
    const timer = setTimeout(() => resolve(false), ms);
    promise.then(() => {
      clearTimeout(timer);
      resolve(true);
    });
  });
}

/**
/** Minimum Python for the backend (keep in sync with `requires-python` in pyproject.toml). */
export const MIN_PYTHON: readonly [number, number] = [3, 14];

/**
 * Find a Python >= {@link MIN_PYTHON} interpreter. `configured` wins when set;
 * otherwise try the versioned launcher first (distros often ship an older
 * `python3` next to `python3.14`), then the generic names. Returns the argv
 * prefix to use.
 */
export function findPython(configured: string | undefined): { python: string[]; version: string } | { error: string } {
  const [minMajor, minMinor] = MIN_PYTHON;
  const want = `${minMajor}.${minMinor}`;
  const candidates: string[][] = configured
    ? [[configured]]
    : process.platform === "win32"
      ? [["py", `-${want}`], ["py", "-3"], ["python"], ["python3"]]
      : [[`python${want}`], ["python3"], ["python"]];
  const tried: string[] = [];
  for (const [cmd, ...pre] of candidates) {
    tried.push([cmd, ...pre].join(" "));
    const res = spawnSync(cmd, [...pre, "-c", "import sys; print('%d.%d' % sys.version_info[:2])"], {
      encoding: "utf8",
      timeout: 10000,
      windowsHide: true,
      shell: false,
    });
    if (res.status !== 0 || !res.stdout) {
      continue;
    }
    const version = res.stdout.trim();
    const [major, minor] = version.split(".").map(Number);
    if (major > minMajor || (major === minMajor && minor >= minMinor)) {
      return { python: [cmd, ...pre], version };
    }
    tried[tried.length - 1] += ` (found ${version}, need >= ${want})`;
  }
  return { error: `No Python ${want}+ interpreter found. Tried: ${tried.join(", ")}. Install Python ${want} or set 'pcapViewer.pythonPath'.` };
}
