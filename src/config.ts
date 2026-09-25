import * as vscode from "vscode";
import { ColumnSetting, normalizeColumns, resolveLuaScripts } from "./settingsModel";

export const SECTION = "pcapViewer";

export interface Settings {
  pythonPath: string;
  tsharkPath: string;
  luaScripts: string[];
  luaWarnings: string[];
  decodeAs: string[];
  prefs: Record<string, string | number | boolean>;
  columns: ColumnSetting[];
  maxCachedFrames: number;
  requestTimeoutMs: number;
}

export function readSettings(scope?: vscode.Uri): Settings {
  const cfg = vscode.workspace.getConfiguration(SECTION, scope);
  const baseDir = vscode.workspace.workspaceFolders?.[0]?.uri.fsPath;
  const lua = resolveLuaScripts(cfg.get<string[]>("luaScripts", []), cfg.get<string>("dissectorsFolder", ""), baseDir);
  return {
    pythonPath: cfg.get<string>("pythonPath", "").trim(),
    tsharkPath: cfg.get<string>("tsharkPath", "").trim(),
    luaScripts: lua.scripts,
    luaWarnings: lua.warnings,
    decodeAs: cfg.get<string[]>("decodeAs", []).filter((r) => typeof r === "string" && r.trim()),
    prefs: cfg.get<Record<string, string | number | boolean>>("prefs", {}),
    columns: normalizeColumns(cfg.get<unknown>("columns", [])),
    maxCachedFrames: cfg.get<number>("maxCachedFrames", 5_000_000),
    requestTimeoutMs: cfg.get<number>("requestTimeoutSeconds", 60) * 1000,
  };
}

/** Settings whose change requires re-running tshark over the file. */
export const RELOAD_KEYS = [
  "pythonPath",
  "tsharkPath",
  "luaScripts",
  "dissectorsFolder",
  "decodeAs",
  "prefs",
  "maxCachedFrames",
].map((k) => `${SECTION}.${k}`);

/** Update a setting where it is currently defined (workspace if set there, else user). */
export async function updateSetting(key: string, value: unknown): Promise<void> {
  const cfg = vscode.workspace.getConfiguration(SECTION);
  const inspected = cfg.inspect(key);
  const target =
    inspected?.workspaceFolderValue !== undefined
      ? vscode.ConfigurationTarget.WorkspaceFolder
      : inspected?.workspaceValue !== undefined
        ? vscode.ConfigurationTarget.Workspace
        : vscode.ConfigurationTarget.Global;
  await cfg.update(key, value, target);
}
