/**
 * Pure helpers for interpreting `pcapViewer.*` settings. No `vscode` imports,
 * so they are unit-testable with plain Node.
 */
import * as fs from "node:fs";
import * as path from "node:path";

export interface ColumnSetting {
  field: string;
  title: string;
}

const FIELD_RE = /^[A-Za-z0-9_][A-Za-z0-9_.-]*$/;

/** Accept `"http.host"` or `{ field, title? }`; drop invalid entries and duplicates. */
export function normalizeColumns(raw: unknown): ColumnSetting[] {
  if (!Array.isArray(raw)) {
    return [];
  }
  const out: ColumnSetting[] = [];
  const seen = new Set<string>();
  for (const item of raw) {
    let field: unknown;
    let title: unknown;
    if (typeof item === "string") {
      field = item;
    } else if (item && typeof item === "object") {
      field = (item as { field?: unknown }).field;
      title = (item as { title?: unknown }).title;
    }
    if (typeof field !== "string") {
      continue;
    }
    field = field.trim();
    if (!FIELD_RE.test(field as string) || seen.has(field as string)) {
      continue;
    }
    seen.add(field as string);
    out.push({ field: field as string, title: typeof title === "string" && title.trim() ? title.trim() : (field as string) });
  }
  return out;
}

export function isValidFieldName(name: string): boolean {
  return FIELD_RE.test(name);
}

/**
 * Lua scripts to load: explicit `luaScripts` plus every `*.lua` directly in
 * `dissectorsFolder`. Relative paths resolve against `baseDir` (the first
 * workspace folder). Returns absolute paths, de-duplicated, explicit ones first.
 */
export function resolveLuaScripts(
  luaScripts: readonly string[],
  dissectorsFolder: string | undefined,
  baseDir: string | undefined,
  readdir: (dir: string) => string[] = (d) => fs.readdirSync(d),
): { scripts: string[]; warnings: string[] } {
  const scripts: string[] = [];
  const warnings: string[] = [];
  const abs = (p: string) => (path.isAbsolute(p) ? p : baseDir ? path.join(baseDir, p) : p);
  for (const s of luaScripts) {
    if (typeof s === "string" && s.trim()) {
      scripts.push(path.normalize(abs(expandHome(s.trim()))));
    }
  }
  if (dissectorsFolder && dissectorsFolder.trim()) {
    const dir = path.normalize(abs(expandHome(dissectorsFolder.trim())));
    try {
      for (const name of readdir(dir).sort()) {
        if (name.toLowerCase().endsWith(".lua")) {
          scripts.push(path.join(dir, name));
        }
      }
    } catch (err) {
      warnings.push(`Cannot read dissectors folder ${dir}: ${(err as Error).message}`);
    }
  }
  return { scripts: [...new Set(scripts)], warnings };
}

function expandHome(p: string): string {
  if (p === "~" || p.startsWith("~/") || p.startsWith("~\\")) {
    const home = process.env.HOME ?? process.env.USERPROFILE ?? "";
    return path.join(home, p.slice(1));
  }
  return p;
}

export interface SavedFilter {
  name: string;
  filter: string;
}

/** Accept `[{ name, filter }]`; drop entries without both, and duplicate names (first wins). */
export function normalizeSavedFilters(raw: unknown): SavedFilter[] {
  if (!Array.isArray(raw)) {
    return [];
  }
  const out: SavedFilter[] = [];
  const seen = new Set<string>();
  for (const item of raw) {
    if (!item || typeof item !== "object") {
      continue;
    }
    const name = (item as { name?: unknown }).name;
    const filter = (item as { filter?: unknown }).filter;
    if (typeof name !== "string" || typeof filter !== "string" || !name.trim() || !filter.trim() || seen.has(name.trim())) {
      continue;
    }
    seen.add(name.trim());
    out.push({ name: name.trim(), filter: filter.trim() });
  }
  return out;
}

/** Add or replace (by name) a saved filter, keeping the existing order. */
export function upsertSavedFilter(list: readonly SavedFilter[], entry: SavedFilter): SavedFilter[] {
  const i = list.findIndex((f) => f.name === entry.name);
  if (i < 0) {
    return [...list, entry];
  }
  const copy = [...list];
  copy[i] = entry;
  return copy;
}

/** A "Decode As" rule as stored in `pcapViewer.decodeAs`: `<layer>==<value>,<protocol>`. */
export interface DecodeAsRule {
  layer: string;
  value: string;
  protocol: string;
}

const DECODE_AS_RE = /^([A-Za-z0-9_][A-Za-z0-9_.-]*)(?:==|:)([^,\s]+),([A-Za-z0-9_.-]+)$/;

export function parseDecodeAsRule(rule: string): DecodeAsRule | undefined {
  const m = DECODE_AS_RE.exec(rule.trim());
  return m ? { layer: m[1], value: m[2], protocol: m[3] } : undefined;
}

export function formatDecodeAsRule(rule: DecodeAsRule): string {
  return `${rule.layer}==${rule.value},${rule.protocol}`;
}

/** Add a rule, replacing any existing rule for the same layer and value. */
export function upsertDecodeAsRule(rules: readonly string[], rule: DecodeAsRule): string[] {
  const kept = rules.filter((r) => {
    const parsed = parseDecodeAsRule(r);
    return !parsed || parsed.layer !== rule.layer || parsed.value !== rule.value;
  });
  return [...kept, formatDecodeAsRule(rule)];
}

/** Resolve `pcapViewer.dissectorsFolder` like the Lua scripts (relative to the workspace, ~ expanded). */
export function resolveDissectorsFolder(folder: string | undefined, baseDir: string | undefined): string | undefined {
  if (!folder || !folder.trim()) {
    return undefined;
  }
  const expanded = expandHome(folder.trim());
  return path.normalize(path.isAbsolute(expanded) ? expanded : baseDir ? path.join(baseDir, expanded) : expanded);
}

export type ConfigTarget = "workspaceFolder" | "workspace" | "global";

/**
 * Where to write a setting so the change is actually seen: the most specific
 * scope that currently defines it (a folder override would otherwise keep
 * shadowing a workspace or user value). Folder scope needs a resource scope.
 */
export function configTargetFor(inspected: { workspaceFolderValue?: unknown; workspaceValue?: unknown } | undefined, scoped: boolean): ConfigTarget {
  if (scoped && inspected?.workspaceFolderValue !== undefined) {
    return "workspaceFolder";
  }
  return inspected?.workspaceValue !== undefined ? "workspace" : "global";
}

/** Most-recent-first history without duplicates, capped at `max`. */
export function pushHistory(history: readonly string[], expr: string, max = 50): string[] {
  const trimmed = expr.trim();
  if (!trimmed) {
    return [...history];
  }
  return [trimmed, ...history.filter((h) => h !== trimmed)].slice(0, max);
}
