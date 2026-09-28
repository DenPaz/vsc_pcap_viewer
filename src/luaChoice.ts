import * as path from "node:path";
import type * as vscode from "vscode";

/**
 * Which Lua dissectors each capture loads, when chosen with _PCAP: Lua
 * Dissectors…_: capture path → script paths ([] = none). Kept in the
 * workspace state (per user and workspace, not shared); a capture without an
 * entry loads every configured script.
 */
const KEY = "pcapViewer.luaChoices";
/** Entries kept (the most recently chosen). */
const MAX_ENTRIES = 500;

let store: vscode.Memento | undefined;

export function initLuaChoices(memento: vscode.Memento): void {
  store = memento;
}

function choices(): Record<string, string[]> {
  const raw = store?.get<unknown>(KEY);
  return raw && typeof raw === "object" && !Array.isArray(raw)
    ? (raw as Record<string, string[]>)
    : {};
}

function keyOf(uri: vscode.Uri): string {
  return path.normalize(uri.fsPath);
}

/** The scripts chosen for this capture, or undefined (every configured script). */
export function luaChoiceFor(uri: vscode.Uri | undefined): string[] | undefined {
  if (!uri) {
    return undefined;
  }
  const chosen = choices()[keyOf(uri)];
  return Array.isArray(chosen) ? chosen.filter((f) => typeof f === "string") : undefined;
}

/** Remember the scripts for this capture (undefined: back to every configured script). */
export async function setLuaChoice(uri: vscode.Uri, scripts: string[] | undefined): Promise<void> {
  if (!store) {
    return;
  }
  const next = { ...choices() };
  const key = keyOf(uri);
  delete next[key]; // (re-added last: the most recent entries are kept)
  if (scripts) {
    next[key] = scripts;
  }
  const keys = Object.keys(next);
  for (const old of keys.slice(0, Math.max(0, keys.length - MAX_ENTRIES))) {
    delete next[old];
  }
  await store.update(KEY, next);
}
