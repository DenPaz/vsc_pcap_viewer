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

/** A packet coloring rule as sent to the backend (`pcapViewer.coloringRules`). */
export interface ColoringRule {
  name: string;
  filter: string;
  foreground: string;
  background: string;
}

const COLOR_RE = /^#[0-9a-fA-F]{6}$/;
export const MAX_COLORING_RULES = 255;

export function isColor(value: unknown): value is string {
  return typeof value === "string" && COLOR_RE.test(value);
}

/**
 * Enabled rules with a filter, in priority order (at most 255). Colors are
 * passed through as given; the backend reports malformed ones per rule.
 */
export function normalizeColoringRules(raw: unknown): ColoringRule[] {
  if (!Array.isArray(raw)) {
    return [];
  }
  const out: ColoringRule[] = [];
  for (const item of raw) {
    if (!item || typeof item !== "object" || (item as { enabled?: unknown }).enabled === false) {
      continue;
    }
    const { name, filter, foreground, background } = item as Record<string, unknown>;
    if (typeof filter !== "string" || !filter.trim()) {
      continue;
    }
    out.push({
      name: typeof name === "string" && name.trim() ? name.trim() : filter.trim(),
      filter: filter.trim(),
      foreground: typeof foreground === "string" ? foreground : "#000000",
      background: typeof background === "string" ? background : "#ffffff",
    });
  }
  return out.slice(0, MAX_COLORING_RULES);
}

/** Colors offered by "Colorize with Filter" (Wireshark's conversation colors). */
export const COLORIZE_PALETTE: readonly { label: string; background: string }[] = [
  { label: "Red", background: "#ffc0c0" },
  { label: "Pink", background: "#ffc0ff" },
  { label: "Mauve", background: "#e0c0e0" },
  { label: "Blue", background: "#c0c0ff" },
  { label: "Teal", background: "#c0e0e0" },
  { label: "Cyan", background: "#c0ffff" },
  { label: "Green", background: "#c0ffc0" },
  { label: "Yellow", background: "#ffffc0" },
  { label: "Olive", background: "#e0e0c0" },
  { label: "Grey", background: "#e0e0e0" },
];
export const COLORIZE_FOREGROUND = "#12272e";

/** Put a new rule first (it wins over the existing ones), keeping the raw entries as they are. */
export function prependColoringRule(rules: unknown, rule: ColoringRule): unknown[] {
  return [rule, ...(Array.isArray(rules) ? rules : [])];
}

/** Suggested export file next to the capture: `dir/stem-suffix.ext`. */
export function exportFileName(capturePath: string, suffix: string, ext: string): string {
  const parsed = path.parse(capturePath);
  return path.join(parsed.dir, `${parsed.name}-${suffix}.${ext}`);
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
