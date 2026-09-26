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

/** Most-recent-first history without duplicates, capped at `max`. */
export function pushHistory(history: readonly string[], expr: string, max = 50): string[] {
  const trimmed = expr.trim();
  if (!trimmed) {
    return [...history];
  }
  return [trimmed, ...history.filter((h) => h !== trimmed)].slice(0, max);
}
