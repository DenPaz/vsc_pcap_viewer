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
    out.push({
      field: field as string,
      title: typeof title === "string" && title.trim() ? title.trim() : (field as string),
    });
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
    if (
      typeof name !== "string" ||
      typeof filter !== "string" ||
      !name.trim() ||
      !filter.trim() ||
      seen.has(name.trim())
    ) {
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

/** Resolve a path setting like the Lua scripts (relative to the workspace, ~ expanded). */
export function resolveSettingPath(
  setting: string | undefined,
  baseDir: string | undefined,
): string | undefined {
  if (!setting || !setting.trim()) {
    return undefined;
  }
  const expanded = expandHome(setting.trim());
  return path.normalize(
    path.isAbsolute(expanded) ? expanded : baseDir ? path.join(baseDir, expanded) : expanded,
  );
}

/** Resolve `pcapViewer.dissectorsFolder` (see resolveSettingPath). */
export const resolveDissectorsFolder = resolveSettingPath;

/** tshark's preference for the TLS (and QUIC) key log file. */
export const TLS_KEYLOG_PREF = "tls.keylog_file";

/** The preferences to pass: `prefs` with `pcapViewer.tlsKeyLogFile` (already resolved) as tls.keylog_file. */
export function withTlsKeyLog<T>(
  prefs: Record<string, T>,
  keyLogFile: string | undefined,
): Record<string, T | string> {
  return keyLogFile ? { ...prefs, [TLS_KEYLOG_PREF]: keyLogFile } : { ...prefs };
}

const KEYLOG_LINE =
  /^(CLIENT_RANDOM|RSA|(CLIENT|SERVER)_(HANDSHAKE_TRAFFIC_SECRET|TRAFFIC_SECRET_\d+)|CLIENT_EARLY_TRAFFIC_SECRET|(EARLY_)?EXPORTER_SECRET) [0-9A-Fa-f]+ [0-9A-Fa-f]+\s*$/;

/**
 * Whether the start of a file looks like an SSLKEYLOGFILE key log: an empty file
 * (a browser that has not written keys yet), or comment/blank lines and at least
 * one key line. `text` may end mid-line (only complete lines are checked).
 */
export function looksLikeKeyLog(text: string): boolean {
  const lines = text.split("\n");
  if (lines.length > 1) {
    lines.pop(); // possibly cut short
  }
  let keys = 0;
  for (const raw of lines) {
    const line = raw.replace(/\r$/, "");
    if (!line.trim() || line.startsWith("#")) {
      continue;
    }
    if (!KEYLOG_LINE.test(line)) {
      return false;
    }
    keys++;
  }
  return keys > 0 || !text.trim();
}

/** Packet-list time column formats (pcapViewer.timeFormat); computed by the backend. */
export const TIME_FORMATS = [
  { id: "relative", label: "Seconds since beginning of capture" },
  { id: "delta_displayed", label: "Seconds since previous displayed packet" },
  { id: "delta_captured", label: "Seconds since previous captured packet" },
  { id: "absolute", label: "Date and time of day (local)" },
  { id: "utc", label: "Date and time of day (UTC)" },
  { id: "epoch", label: "Seconds since 1970-01-01 (epoch)" },
] as const;
export type TimeFormat = (typeof TIME_FORMATS)[number]["id"];

export function normalizeTimeFormat(raw: unknown): TimeFormat {
  return TIME_FORMATS.find((f) => f.id === raw)?.id ?? "relative";
}

/** Packet-list column order and hidden columns (pcapViewer.columnLayout), by column id. */
export interface ColumnLayout {
  order: string[];
  hidden: string[];
}

const COLUMN_ID_RE =
  /^(number|time|source|destination|protocol|length|info|custom:[A-Za-z0-9_][A-Za-z0-9_.-]*)$/;

export function normalizeColumnLayout(raw: unknown): ColumnLayout {
  const ids = (v: unknown) =>
    Array.isArray(v)
      ? [...new Set(v.filter((x): x is string => typeof x === "string" && COLUMN_ID_RE.test(x)))]
      : [];
  const obj = raw && typeof raw === "object" ? (raw as { order?: unknown; hidden?: unknown }) : {};
  return { order: ids(obj.order), hidden: ids(obj.hidden) };
}

/** Add a column for `field` ("Apply as Column"); unchanged if it is already there. */
export function addColumn(
  columns: readonly ColumnSetting[],
  field: string,
  title: string,
): ColumnSetting[] {
  if (columns.some((c) => c.field === field)) {
    return [...columns];
  }
  return [...columns, { field, title: title.trim() || field }];
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

/** A coloring rule as the rules editor shows it: disabled ones and all. */
export interface EditableColoringRule extends ColoringRule {
  enabled: boolean;
}

/** `pcapViewer.coloringRules` for the editor: every rule, in order, with defaults filled in. */
export function editableColoringRules(raw: unknown): EditableColoringRule[] {
  if (!Array.isArray(raw)) {
    return [];
  }
  const text = (v: unknown) => (typeof v === "string" ? v.trim() : "");
  const color = (v: unknown, fallback: string) =>
    typeof v === "string" && COLOR_RE.test(v) ? v.toLowerCase() : fallback;
  return raw
    .filter((item): item is Record<string, unknown> => !!item && typeof item === "object")
    .map((item) => ({
      name: text(item.name),
      filter: text(item.filter),
      foreground: color(item.foreground, "#000000"),
      background: color(item.background, "#ffffff"),
      enabled: item.enabled !== false,
    }));
}

/** The editor's rules as the setting stores them (`enabled` only when false). */
export function coloringRulesSetting(
  rules: readonly EditableColoringRule[],
): Record<string, unknown>[] {
  return rules.map((r) => ({
    name: r.name.trim() || r.filter.trim(),
    filter: r.filter.trim(),
    foreground: r.foreground,
    background: r.background,
    ...(r.enabled ? {} : { enabled: false }),
  }));
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

const COMPRESSION_EXT = /\.(gz|zst|lz4)$/i;

/** A capture's name without compression and format extensions: `trace.pcap.gz` → `trace`. */
export function captureStem(capturePath: string): string {
  const base = path.basename(capturePath).replace(COMPRESSION_EXT, "");
  return base.replace(/\.[^.]+$/, "") || base;
}

/** Suggested export file next to the capture: `dir/stem-suffix.ext` (`trace.pcap.gz` → `trace-filtered.pcapng`). */
export function exportFileName(capturePath: string, suffix: string, ext: string): string {
  return path.join(path.dirname(capturePath), `${captureStem(capturePath)}-${suffix}.${ext}`);
}

// eslint-disable-next-line no-control-regex -- control characters are what it removes
const UNSAFE_FILE_NAME_CHARS = /[\x00-\x1f\x7f<>:"/\\|?*]/g;
const WINDOWS_RESERVED_NAME = /^(con|prn|aux|nul|com[1-9]|lpt[1-9])(\.|$)/i;

/** A file name taken from a capture (untrusted), made safe to suggest in a save dialog. */
export function safeFileName(name: string): string {
  const cleaned = name
    .replace(UNSAFE_FILE_NAME_CHARS, "_")
    .trim()
    .replace(/[. ]+$/, "");
  const safe = !cleaned || cleaned === "." || cleaned === ".." ? "object" : cleaned;
  return (WINDOWS_RESERVED_NAME.test(safe) ? `_${safe}` : safe).slice(0, 200);
}

export type ConfigTarget = "workspaceFolder" | "workspace" | "global";

/**
 * Where to write a setting so the change is actually seen: the most specific
 * scope that currently defines it (a folder override would otherwise keep
 * shadowing a workspace or user value). Folder scope needs a resource scope.
 */
export function configTargetFor(
  inspected: { workspaceFolderValue?: unknown; workspaceValue?: unknown } | undefined,
  scoped: boolean,
): ConfigTarget {
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

/** Quick (approximate) packet detail for late packets: from frame `after` on (0 = never), dissecting `window` packets. */
export interface QuickDetail {
  after: number;
  window: number;
}

/** Name resolution switches (pcapViewer.nameResolution.*), sent to the backend as `names`. */
export interface NameResolution {
  mac: boolean;
  network: boolean;
  capturedDns: boolean;
  transport: boolean;
  external: boolean;
}

export const DEFAULT_NAME_RESOLUTION: NameResolution = {
  mac: true,
  network: false,
  capturedDns: true,
  transport: false,
  external: false,
};

/** The switches in the order PCAP: Name Resolution… lists them. */
export const NAME_RESOLUTION_OPTIONS: readonly {
  key: keyof NameResolution;
  label: string;
  detail: string;
}[] = [
  {
    key: "mac",
    label: "MAC addresses",
    detail: "Vendor and well-known names, e.g. Broadcast or Dell_12:34:56",
  },
  {
    key: "network",
    label: "Network addresses",
    detail: "Host names for IP addresses, from hosts files and the capture's DNS answers",
  },
  {
    key: "capturedDns",
    label: "Use the capture's DNS answers",
    detail: "Names learned from DNS responses in the capture (with network addresses)",
  },
  { key: "transport", label: "Transport ports", detail: "Service names for ports, e.g. http(80)" },
  {
    key: "external",
    label: "Ask your DNS server",
    detail:
      "One query per address (with network addresses): slower, and the server sees the addresses",
  },
];

export function normalizeNameResolution(
  get: (key: keyof NameResolution) => unknown,
): NameResolution {
  const out = { ...DEFAULT_NAME_RESOLUTION };
  for (const key of Object.keys(out) as (keyof NameResolution)[]) {
    const v = get(key);
    if (typeof v === "boolean") {
      out[key] = v;
    }
  }
  return out;
}

export function sameNameResolution(a: NameResolution, b: NameResolution): boolean {
  return (Object.keys(a) as (keyof NameResolution)[]).every((k) => a[k] === b[k]);
}

/** Short status-bar text, e.g. "Names: MAC, network (DNS)". */
export function nameResolutionLabel(n: NameResolution): string {
  const parts: string[] = [];
  if (n.mac) {
    parts.push("MAC");
  }
  if (n.network) {
    const sources = [n.capturedDns ? "capture" : "", n.external ? "DNS server" : ""].filter(
      Boolean,
    );
    parts.push(sources.length ? `network (${sources.join(", ")})` : "network");
  }
  if (n.transport) {
    parts.push("ports");
  }
  return `Names: ${parts.length ? parts.join(", ") : "off"}`;
}

/** Unsaved comment edits from a hot-exit backup (see backupCustomDocument). */
export function parseCommentBackup(text: string): Map<number, string> {
  const raw = JSON.parse(text) as unknown;
  const edits = new Map<number, string>();
  if (raw && typeof raw === "object") {
    for (const [key, value] of Object.entries(raw)) {
      const n = Number(key);
      if (Number.isInteger(n) && n > 0 && (typeof value === "string" || value === null)) {
        edits.set(n, value ?? "");
      }
    }
  }
  return edits;
}
