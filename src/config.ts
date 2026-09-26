import * as vscode from "vscode";
import { ColoringRule, ColumnSetting, SavedFilter, configTargetFor, normalizeColoringRules, normalizeColumns, normalizeSavedFilters, resolveLuaScripts } from "./settingsModel";

export const SECTION = "pcapViewer";

export interface Settings {
  pythonPath: string;
  tsharkPath: string;
  luaScripts: string[];
  luaWarnings: string[];
  decodeAs: string[];
  prefs: Record<string, string | number | boolean>;
  columns: ColumnSetting[];
  savedFilters: SavedFilter[];
  colorize: boolean;
  coloringRules: ColoringRule[];
  maxCachedFrames: number;
  requestTimeoutMs: number;
}

export function readSettings(scope?: vscode.Uri): Settings {
  const cfg = vscode.workspace.getConfiguration(SECTION, scope);
  const baseDir = workspaceDirFor(scope);
  const lua = resolveLuaScripts(cfg.get<string[]>("luaScripts", []), cfg.get<string>("dissectorsFolder", ""), baseDir);
  return {
    pythonPath: cfg.get<string>("pythonPath", "").trim(),
    tsharkPath: cfg.get<string>("tsharkPath", "").trim(),
    luaScripts: lua.scripts,
    luaWarnings: lua.warnings,
    decodeAs: cfg.get<string[]>("decodeAs", []).filter((r) => typeof r === "string" && r.trim()),
    prefs: cfg.get<Record<string, string | number | boolean>>("prefs", {}),
    columns: normalizeColumns(cfg.get<unknown>("columns", [])),
    savedFilters: normalizeSavedFilters(cfg.get<unknown>("savedFilters", [])),
    colorize: cfg.get<boolean>("colorize", true),
    coloringRules: normalizeColoringRules(cfg.get<unknown>("coloringRules", [])),
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

/** Settings that only change packet colors (no re-indexing needed). */
export const COLORING_KEYS = ["colorize", "coloringRules"].map((k) => `${SECTION}.${k}`);

/**
 * Folder that relative setting paths resolve against: the workspace folder
 * containing `scope` (multi-root aware), else the first workspace folder.
 */
export function workspaceDirFor(scope?: vscode.Uri): string | undefined {
  const folder = scope ? vscode.workspace.getWorkspaceFolder(scope) : undefined;
  return (folder ?? vscode.workspace.workspaceFolders?.[0])?.uri.fsPath;
}

/** A setting's effective value for `scope` (a capture's URI respects folder overrides). */
export function getSetting<T>(key: string, fallback: T, scope?: vscode.Uri): T {
  return vscode.workspace.getConfiguration(SECTION, scope).get<T>(key, fallback);
}

/**
 * Update a setting where it is currently defined for `scope` (folder,
 * workspace, else user), so the new value is the one `scope` sees.
 */
export async function updateSetting(key: string, value: unknown, scope?: vscode.Uri): Promise<void> {
  const cfg = vscode.workspace.getConfiguration(SECTION, scope);
  const target = {
    workspaceFolder: vscode.ConfigurationTarget.WorkspaceFolder,
    workspace: vscode.ConfigurationTarget.Workspace,
    global: vscode.ConfigurationTarget.Global,
  }[configTargetFor(cfg.inspect(key), !!scope && !!vscode.workspace.getWorkspaceFolder(scope))];
  await cfg.update(key, value, target);
}
