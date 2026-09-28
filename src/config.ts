import * as vscode from "vscode";
import {
  ColoringRule,
  ColumnLayout,
  ColumnSetting,
  FilterButton,
  NameResolution,
  QuickDetail,
  SavedFilter,
  TimeFormat,
  configTargetFor,
  normalizeColoringRules,
  normalizeColumnLayout,
  normalizeColumns,
  normalizeFilterButtons,
  normalizeNameResolution,
  normalizeSavedFilters,
  normalizeTimeFormat,
  resolveLuaScripts,
  resolveSettingPath,
  withTlsKeyLog,
} from "./settingsModel";

export const SECTION = "pcapViewer";

export interface Settings {
  pythonPath: string;
  tsharkPath: string;
  luaScripts: string[];
  luaWarnings: string[];
  decodeAs: string[];
  /** Includes tls.keylog_file when `tlsKeyLogFile` is set. */
  prefs: Record<string, string | number | boolean>;
  /** `pcapViewer.tlsKeyLogFile`, resolved ("" = none). */
  tlsKeyLogFile: string;
  columns: ColumnSetting[];
  columnLayout: ColumnLayout;
  timeFormat: TimeFormat;
  savedFilters: SavedFilter[];
  filterButtons: FilterButton[];
  colorize: boolean;
  coloringRules: ColoringRule[];
  maxCachedFrames: number;
  requestTimeoutMs: number;
  quickDetail: QuickDetail;
  /** Saved packet-list indexes (reopening skips the index pass); 0 bytes = off. */
  indexCacheBytes: number;
  nameResolution: NameResolution;
}

export function readQuickDetail(scope?: vscode.Uri): QuickDetail {
  const cfg = vscode.workspace.getConfiguration(SECTION, scope);
  const num = (key: string, fallback: number, min: number, max: number) => {
    const v = cfg.get<number>(key, fallback);
    return Number.isFinite(v) ? Math.min(max, Math.max(min, Math.round(v))) : fallback;
  };
  return {
    after: num("quickDetail.after", 20_000, 0, Number.MAX_SAFE_INTEGER),
    window: num("quickDetail.window", 300, 2, 5000),
  };
}

export function readSettings(scope?: vscode.Uri): Settings {
  const cfg = vscode.workspace.getConfiguration(SECTION, scope);
  const baseDir = workspaceDirFor(scope);
  const lua = resolveLuaScripts(
    cfg.get<string[]>("luaScripts", []),
    cfg.get<string>("dissectorsFolder", ""),
    baseDir,
  );
  const keyLog = resolveSettingPath(cfg.get<string>("tlsKeyLogFile", ""), baseDir) ?? "";
  return {
    pythonPath: cfg.get<string>("pythonPath", "").trim(),
    tsharkPath: cfg.get<string>("tsharkPath", "").trim(),
    luaScripts: lua.scripts,
    luaWarnings: lua.warnings,
    decodeAs: cfg.get<string[]>("decodeAs", []).filter((r) => typeof r === "string" && r.trim()),
    prefs: withTlsKeyLog(cfg.get<Record<string, string | number | boolean>>("prefs", {}), keyLog),
    tlsKeyLogFile: keyLog,
    columns: normalizeColumns(cfg.get<unknown>("columns", [])),
    columnLayout: normalizeColumnLayout(cfg.get<unknown>("columnLayout", {})),
    timeFormat: normalizeTimeFormat(cfg.get<unknown>("timeFormat", "relative")),
    savedFilters: normalizeSavedFilters(cfg.get<unknown>("savedFilters", [])),
    filterButtons: normalizeFilterButtons(cfg.get<unknown>("filterButtons", [])),
    colorize: cfg.get<boolean>("colorize", true),
    coloringRules: normalizeColoringRules(cfg.get<unknown>("coloringRules", [])),
    maxCachedFrames: cfg.get<number>("maxCachedFrames", 5_000_000),
    requestTimeoutMs: cfg.get<number>("requestTimeoutSeconds", 60) * 1000,
    quickDetail: readQuickDetail(scope),
    indexCacheBytes: cfg.get<boolean>("indexCache.enabled", true)
      ? Math.max(0, cfg.get<number>("indexCache.maxSizeMB", 1024)) * 1024 * 1024
      : 0,
    nameResolution: normalizeNameResolution((key) => cfg.get<unknown>(`nameResolution.${key}`)),
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
export async function updateSetting(
  key: string,
  value: unknown,
  scope?: vscode.Uri,
): Promise<void> {
  const cfg = vscode.workspace.getConfiguration(SECTION, scope);
  const target = {
    workspaceFolder: vscode.ConfigurationTarget.WorkspaceFolder,
    workspace: vscode.ConfigurationTarget.Workspace,
    global: vscode.ConfigurationTarget.Global,
  }[configTargetFor(cfg.inspect(key), !!scope && !!vscode.workspace.getWorkspaceFolder(scope))];
  await cfg.update(key, value, target);
}
