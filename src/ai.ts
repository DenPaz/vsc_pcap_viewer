/**
 * Optional AI help for display filters through VS Code's Language Model API
 * (`vscode.lm`, stable since 1.90). Copilot's inline completions can't reach
 * the webview filter bar, so the extension host asks a chat model directly.
 * The prompt logic is in aiFilter.ts; only the request, the current filter,
 * protocol names and field names/descriptions are sent (never packet data).
 */
import * as vscode from "vscode";
import type { BackendClient } from "./backendClient";
import { SECTION } from "./config";
import { ChatTurn, FieldInfo, FilterSuggestion, Rejected, extractKeywords, suggestFilters } from "./aiFilter";

export interface SuggestOutcome {
  suggestions: FilterSuggestion[];
  rejected: Rejected[];
  /** Short user-facing note when there are no suggestions (or they were cut short). */
  message?: string;
  /** AI help can't be used right now (off, no model, no permission): hide the action. */
  unavailable?: boolean;
}

const MODEL_SELECTOR: vscode.LanguageModelChatSelector = { vendor: "copilot" };
const JUSTIFICATION = "PCAP Viewer turns your description into a Wireshark display filter. Only your request, the current filter and protocol/field names are sent.";
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
  async suggest(backend: BackendClient, request: string, currentFilter: string, token: vscode.CancellationToken): Promise<SuggestOutcome> {
    if (!aiEnabled()) {
      return { suggestions: [], rejected: [], unavailable: true, message: "AI help is turned off (pcapViewer.ai.enabled)." };
    }
    const model = await this.model();
    if (!model) {
      return {
        suggestions: [],
        rejected: [],
        unavailable: true,
        message: this.blocked ? "AI help was not allowed to use the language model." : "No language model is available. Install and sign in to GitHub Copilot to use AI help.",
      };
    }
    try {
      // The first protocol-hierarchy pass can take a while on a big capture: don't make a cancel wait for it.
      const [protocols, fields] = await untilCancelled(Promise.all([this.protocolNames(backend), this.candidateFields(backend, request)]), token);
      const ask = async (turns: ChatTurn[]): Promise<string> => {
        const messages = turns.map((t) => (t.role === "user" ? vscode.LanguageModelChatMessage.User(t.content) : vscode.LanguageModelChatMessage.Assistant(t.content)));
        const response = await model.sendRequest(messages, { justification: JUSTIFICATION }, token);
        let text = "";
        for await (const part of response.text) {
          text += part;
        }
        return text;
      };
      const validate = async (filter: string): Promise<string | undefined> => {
        try {
          const res = await backend.request<{ valid: boolean; error?: string }>("validate_filter", { expr: filter });
          return res.valid ? undefined : (res.error ?? "invalid filter");
        } catch (err) {
          return `could not validate: ${(err as Error).message}`;
        }
      };
      const result = await suggestFilters({ ask, validate }, { request, currentFilter, protocols, fields });
      for (const r of result.rejected) {
        this.log.info(`AI filter suggestion rejected by tshark: ${r.filter} (${r.error})`);
      }
      return result.suggestions.length ? result : { ...result, message: "The language model didn't come up with a valid display filter. Try describing it differently." };
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
      if (err.code === vscode.LanguageModelError.NoPermissions.name || err.code === vscode.LanguageModelError.Blocked.name) {
        this.blocked = true;
        this.availability.fire();
        return { suggestions: [], rejected: [], unavailable: true, message: "AI help was not allowed to use the language model." };
      }
      if (err.code === vscode.LanguageModelError.NotFound.name) {
        this.availability.fire();
        return { suggestions: [], rejected: [], unavailable: true, message: "The language model is no longer available." };
      }
    } else {
      this.log.warn(`AI filter help failed: ${(err as Error)?.message ?? err}`);
    }
    return { suggestions: [], rejected: [], message: `AI request failed: ${(err as Error)?.message ?? err}` };
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
    type Found = { protocols: { name: string; desc?: string }[]; fields: { name: string; desc?: string; blurb?: string; type?: string }[] };
    const lists = await Promise.all(
      extractKeywords(request).map((prefix) => backend.request<Found>("field_index", { prefix, limit: FIELDS_PER_KEYWORD }).catch(() => undefined)),
    );
    const out = new Map<string, FieldInfo>();
    for (const found of lists) {
      for (const p of found?.protocols ?? []) {
        out.set(p.name, { name: p.name, desc: p.desc, type: "protocol" });
      }
      for (const f of found?.fields ?? []) {
        out.set(f.name, { name: f.name, desc: f.blurb && f.blurb !== f.desc ? `${f.desc} — ${f.blurb}` : f.desc, type: f.type });
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
