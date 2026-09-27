/**
 * Optional AI help through VS Code's Language Model API (`vscode.lm`, stable
 * since 1.90). Copilot's inline completions can't reach the webview filter
 * bar, so the extension host asks a chat model directly.
 *
 * - Display filters (aiFilter.ts): only the request, the current filter,
 *   protocol names and field names/descriptions are sent, never packet data.
 * - Explaining packets (aiExplain.ts, `@pcap /explain`): sends the packets'
 *   rows and dissection trees, so callers first get the user's consent
 *   (`pcapViewer.ai.allowPacketData`, see commands/ai.ts). Raw bytes only
 *   with `pcapViewer.ai.allowPacketBytes`.
 */
import * as vscode from "vscode";
import type { BackendClient } from "./backendClient";
import { SECTION } from "./config";
import {
  EXPLAIN_LIMITS,
  ExplainPacket,
  TreeNode,
  buildExplainPrompt,
  extractFilters,
} from "./aiExplain";
import type { QuickDetail } from "./settingsModel";
import {
  ChatTurn,
  FieldInfo,
  FilterSuggestion,
  Rejected,
  extractKeywords,
  suggestFilters,
} from "./aiFilter";

export interface SuggestOutcome {
  suggestions: FilterSuggestion[];
  rejected: Rejected[];
  /** Short user-facing note when there are no suggestions (or they were cut short). */
  message?: string;
  /** AI help can't be used right now (off, no model, no permission): hide the action. */
  unavailable?: boolean;
}

const MODEL_SELECTOR: vscode.LanguageModelChatSelector = { vendor: "copilot" };
const JUSTIFICATION =
  "PCAP Viewer turns your description into a Wireshark display filter. Only your request, the current filter and protocol/field names are sent.";
const EXPLAIN_JUSTIFICATION =
  "PCAP Viewer explains the packets you picked. Their packet-list rows and dissection trees are sent.";

/** What to explain (the caller has the user's consent to send packet data). */
export interface ExplainRequest {
  frames: number[];
  question: string;
  currentFilter: string;
  /** Column title by field, for the packet-list row. */
  titleOf: Record<string, string>;
  customFields: string[];
  includeBytes: boolean;
  /** Late packets use the quick (approximate) detail, like the viewer (pcapViewer.quickDetail). */
  quickDetail: QuickDetail;
}

/** Where the answer goes while it streams (chat response, or an editor). */
export interface ExplainSink {
  progress(message: string): void;
  markdown(text: string): void;
}

export interface ExplainOutcome {
  /** The packets that were explained. */
  frames: number[];
  /** Display filters from the answer that tshark accepts. */
  filters: string[];
  /** Short user-facing note when nothing (or not everything) was explained. */
  message?: string;
  /** AI help can't be used right now (off, no model, no permission). */
  unavailable?: boolean;
}
const FIELDS_PER_KEYWORD = 12;

function lmApi(): typeof vscode.lm | undefined {
  // Guard against hosts that ship without the API (it is stable in 1.90, our minimum).
  return typeof vscode.lm?.selectChatModels === "function" ? vscode.lm : undefined;
}

/** `promise`, or a CancellationError as soon as `token` is cancelled. */
function untilCancelled<T>(promise: Promise<T>, token: vscode.CancellationToken): Promise<T> {
  if (token.isCancellationRequested) {
    return Promise.reject(new vscode.CancellationError());
  }
  return new Promise<T>((resolve, reject) => {
    const sub = token.onCancellationRequested(() => {
      sub.dispose();
      reject(new vscode.CancellationError());
    });
    promise.then(
      (v) => {
        sub.dispose();
        resolve(v);
      },
      (e: unknown) => {
        sub.dispose();
        reject(e instanceof Error ? e : new Error(String(e)));
      },
    );
  });
}

export function aiEnabled(): boolean {
  return vscode.workspace.getConfiguration(SECTION).get<boolean>("ai.enabled", true);
}

export class FilterAssistant implements vscode.Disposable {
  /** Set when the user denied (or policy blocked) access; cleared when models or settings change. */
  private blocked = false;
  private readonly availability = new vscode.EventEmitter<void>();
  /** Fires when AI help may have become (un)available; re-check with isAvailable(). */
  readonly onDidChangeAvailability = this.availability.event;
  private readonly disposables: vscode.Disposable[] = [this.availability];
  /** Protocol names per backend (one protocol-hierarchy pass per capture). */
  private readonly protocols = new WeakMap<BackendClient, Promise<string[]>>();

  constructor(private readonly log: vscode.LogOutputChannel) {
    const lm = lmApi();
    if (lm?.onDidChangeChatModels) {
      this.disposables.push(lm.onDidChangeChatModels(() => this.changed()));
    }
    this.disposables.push(
      vscode.workspace.onDidChangeConfiguration((e) => {
        if (e.affectsConfiguration(`${SECTION}.ai.enabled`)) {
          this.changed();
        }
      }),
    );
  }

  private changed(): void {
    this.blocked = false;
    this.availability.fire();
  }

  async isAvailable(): Promise<boolean> {
    return !!(await this.model());
  }

  private async model(): Promise<vscode.LanguageModelChat | undefined> {
    const lm = lmApi();
    if (!aiEnabled() || this.blocked || !lm) {
      return undefined;
    }
    try {
      return (await lm.selectChatModels(MODEL_SELECTOR))[0];
    } catch {
      return undefined;
    }
  }

  /** Suggest validated display filters for `request` on the capture served by `backend`. */
  async suggest(
    backend: BackendClient,
    request: string,
    currentFilter: string,
    token: vscode.CancellationToken,
  ): Promise<SuggestOutcome> {
    if (!aiEnabled()) {
      return {
        suggestions: [],
        rejected: [],
        unavailable: true,
        message: "AI help is turned off (pcapViewer.ai.enabled).",
      };
    }
    const model = await this.model();
    if (!model) {
      return {
        suggestions: [],
        rejected: [],
        unavailable: true,
        message: this.blocked
          ? "AI help was not allowed to use the language model."
          : "No language model is available. Install and sign in to GitHub Copilot to use AI help.",
      };
    }
    try {
      // The first protocol-hierarchy pass can take a while on a big capture: don't make a cancel wait for it.
      const [protocols, fields] = await untilCancelled(
        Promise.all([this.protocolNames(backend), this.candidateFields(backend, request)]),
        token,
      );
      const ask = async (turns: ChatTurn[]): Promise<string> => {
        const messages = turns.map((t) =>
          t.role === "user"
            ? vscode.LanguageModelChatMessage.User(t.content)
            : vscode.LanguageModelChatMessage.Assistant(t.content),
        );
        const response = await model.sendRequest(messages, { justification: JUSTIFICATION }, token);
        let text = "";
        for await (const part of response.text) {
          text += part;
        }
        return text;
      };
      const validate = async (filter: string): Promise<string | undefined> => {
        try {
          const res = await backend.request<{ valid: boolean; error?: string }>("validate_filter", {
            expr: filter,
          });
          return res.valid ? undefined : (res.error ?? "invalid filter");
        } catch (err) {
          return `could not validate: ${(err as Error).message}`;
        }
      };
      const result = await suggestFilters(
        { ask, validate },
        { request, currentFilter, protocols, fields },
      );
      for (const r of result.rejected) {
        this.log.info(`AI filter suggestion rejected by tshark: ${r.filter} (${r.error})`);
      }
      return result.suggestions.length
        ? result
        : {
            ...result,
            message:
              "The language model didn't come up with a valid display filter. Try describing it differently.",
          };
    } catch (err) {
      return this.failure(err, token);
    }
  }

  private failure(err: unknown, token: vscode.CancellationToken): SuggestOutcome {
    if (token.isCancellationRequested || err instanceof vscode.CancellationError) {
      return { suggestions: [], rejected: [], message: "Cancelled." };
    }
    if (err instanceof vscode.LanguageModelError) {
      this.log.warn(`AI filter help: ${err.code}: ${err.message}`);
      if (
        err.code === vscode.LanguageModelError.NoPermissions.name ||
        err.code === vscode.LanguageModelError.Blocked.name
      ) {
        this.blocked = true;
        this.availability.fire();
        return {
          suggestions: [],
          rejected: [],
          unavailable: true,
          message: "AI help was not allowed to use the language model.",
        };
      }
      if (err.code === vscode.LanguageModelError.NotFound.name) {
        this.availability.fire();
        return {
          suggestions: [],
          rejected: [],
          unavailable: true,
          message: "The language model is no longer available.",
        };
      }
    } else {
      this.log.warn(`AI filter help failed: ${(err as Error)?.message ?? err}`);
    }
    return {
      suggestions: [],
      rejected: [],
      message: `AI request failed: ${(err as Error)?.message ?? err}`,
    };
  }

  /**
   * Explain packets: their rows (list_packets) and dissection trees
   * (packet_detail) go into the prompt (aiExplain.ts caps them and leaves
   * raw bytes out unless `includeBytes`), the answer streams into `sink`, and
   * the ```filter blocks it contains are checked with tshark.
   */
  async explain(
    backend: BackendClient,
    req: ExplainRequest,
    sink: ExplainSink,
    token: vscode.CancellationToken,
  ): Promise<ExplainOutcome> {
    const none = { frames: [], filters: [] };
    if (!aiEnabled()) {
      return {
        ...none,
        unavailable: true,
        message: "AI help is turned off (pcapViewer.ai.enabled).",
      };
    }
    const model = await this.model();
    if (!model) {
      return {
        ...none,
        unavailable: true,
        message: this.blocked
          ? "AI help was not allowed to use the language model."
          : "No language model is available. Install and sign in to GitHub Copilot to use AI help.",
      };
    }
    const included = req.frames.slice(0, EXPLAIN_LIMITS.maxPackets);
    try {
      sink.progress(`Reading packet${included.length === 1 ? "" : "s"} ${included.join(", ")}…`);
      type Rows = { rows: { number: number; cells: string[] }[]; columns: string[] };
      type Detail = {
        tree: TreeNode[];
        sources: { name: string; hex: string }[];
        approximate?: boolean;
        window?: [number, number];
      };
      const q = req.quickDetail;
      const detailParams = (number: number) =>
        q.after > 0 && number > q.after && number > q.window
          ? { number, mode: "quick", window: q.window }
          : { number };
      const [rows, details] = await untilCancelled(
        Promise.all([
          backend.request<Rows>(
            "list_packets",
            { frames: included, inView: false, columns: req.customFields, timeFormat: "relative" },
            { timeoutMs: 0 },
          ),
          Promise.all(
            included.map((number) =>
              backend
                .request<Detail>("packet_detail", detailParams(number), { timeoutMs: 0 })
                // No editcap: a quick request answers {unavailable}; use the exact detail then.
                .then((d) =>
                  d.tree
                    ? d
                    : backend.request<Detail>("packet_detail", { number }, { timeoutMs: 0 }),
                )
                .catch(() => undefined),
            ),
          ),
        ]),
        token,
      );
      const packets: ExplainPacket[] = [];
      included.forEach((number, i) => {
        const detail = details[i];
        const row = rows.rows.find((r) => r.number === number);
        if (detail?.tree && row) {
          packets.push({
            number,
            cells: row.cells,
            tree: detail.tree,
            hex: req.includeBytes ? detail.sources[0]?.hex : undefined,
            approximateFrom: detail.approximate && detail.window ? detail.window[0] : undefined,
          });
        }
      });
      if (!packets.length) {
        return { ...none, message: `The capture has no packet ${req.frames.join(", ")}.` };
      }
      const prompt = buildExplainPrompt({
        question: req.question,
        currentFilter: req.currentFilter,
        titles: rows.columns.map((f) => req.titleOf[f] ?? f),
        packets,
        omitted: req.frames.length - packets.length,
        includeBytes: req.includeBytes,
      });
      sink.progress("Asking the language model…");
      const response = await model.sendRequest(
        [vscode.LanguageModelChatMessage.User(prompt)],
        { justification: EXPLAIN_JUSTIFICATION },
        token,
      );
      let answer = "";
      for await (const part of response.text) {
        answer += part;
        sink.markdown(part);
      }
      const filters: string[] = [];
      for (const filter of extractFilters(answer)) {
        const res = await backend
          .request<{ valid: boolean }>("validate_filter", { expr: filter })
          .catch(() => ({ valid: false }));
        if (res.valid) {
          filters.push(filter);
        } else {
          this.log.info(`AI explain: filter rejected by tshark: ${filter}`);
        }
      }
      const skipped = req.frames.length - packets.length;
      return {
        frames: packets.map((p) => p.number),
        filters,
        message: skipped
          ? `${skipped} of the ${req.frames.length} packets were not included (at most ${EXPLAIN_LIMITS.maxPackets} at a time).`
          : undefined,
      };
    } catch (err) {
      const failed = this.failure(err, token);
      return { ...none, message: failed.message, unavailable: failed.unavailable };
    }
  }

  /** Protocol names from the capture's protocol hierarchy (names only, no counts or data). */
  private protocolNames(backend: BackendClient): Promise<string[]> {
    let names = this.protocols.get(backend);
    if (!names) {
      names = backend
        .request<{ rows: { cells: unknown[] }[] }>("stats", { kind: "phs" }, { timeoutMs: 0 })
        .then((t) => [...new Set(t.rows.map((r) => String(r.cells[0] ?? "")).filter(Boolean))])
        .catch(() => {
          this.protocols.delete(backend);
          return [];
        });
      this.protocols.set(backend, names);
    }
    return names;
  }

  /** Field names/descriptions from tshark's field list, by prefix search on the request's words. */
  private async candidateFields(backend: BackendClient, request: string): Promise<FieldInfo[]> {
    type Found = {
      protocols: { name: string; desc?: string }[];
      fields: { name: string; desc?: string; blurb?: string; type?: string }[];
    };
    const lists = await Promise.all(
      extractKeywords(request).map((prefix) =>
        backend
          .request<Found>("field_index", { prefix, limit: FIELDS_PER_KEYWORD })
          .catch(() => undefined),
      ),
    );
    const out = new Map<string, FieldInfo>();
    for (const found of lists) {
      for (const p of found?.protocols ?? []) {
        out.set(p.name, { name: p.name, desc: p.desc, type: "protocol" });
      }
      for (const f of found?.fields ?? []) {
        out.set(f.name, {
          name: f.name,
          desc: f.blurb && f.blurb !== f.desc ? `${f.desc} — ${f.blurb}` : f.desc,
          type: f.type,
        });
      }
    }
    return [...out.values()];
  }

  dispose(): void {
    for (const d of this.disposables) {
      d.dispose();
    }
  }
}
