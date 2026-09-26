/**
 * Message protocol between the extension host and the webview
 * (src/webview/main.js). Keep both sides in sync.
 */
import type { ColumnSetting, SavedFilter } from "./settingsModel";

export interface ColumnDescriptor {
  id: string;
  title: string;
  field: string;
  numeric: boolean;
}

export interface OpenResult {
  path: string;
  frames: number;
  startTime: number | null;
  endTime: number | null;
  linkType: string | null;
  fileType: string | null;
  size: number;
  warnings: string[];
  columns: ColumnDescriptor[];
  /** Id of the initial (unfiltered) view; list_packets results carry the current one. */
  filterId: number;
}

/** Backend methods the webview may call directly (anything else is refused). */
export const WEBVIEW_RPC_METHODS = new Set([
  "set_filter",
  "validate_filter",
  "list_packets",
  "packet_detail",
  "find_frame",
  "field_index",
  "capture_info",
]);

export type WebviewToHost =
  | { type: "ready" }
  | { type: "rpc"; id: number; method: string; params: Record<string, unknown> }
  | { type: "cancel"; id: number }
  | { type: "cancelLoad" }
  | { type: "reload" }
  | { type: "filterApplied"; expr: string }
  | { type: "saveFilter"; expr: string }
  | { type: "selection"; frame: number | null }
  | { type: "decodeAs"; frame: number }
  | { type: "follow"; proto: "tcp" | "udp" | "tls" | "http"; frame: number }
  | { type: "manageSavedFilters" }
  | { type: "colorize"; filter: string }
  | { type: "exportBytes"; frame: number }
  | { type: "copy"; text: string }
  | { type: "showLog" };

export type HostToWebview =
  | { type: "loading"; message: string }
  | { type: "progress"; phase?: string; fraction?: number | null; frames?: number; matched?: number }
  | {
      type: "init";
      info: OpenResult;
      columns: ColumnSetting[];
      filter: string;
      history: string[];
      savedFilters: SavedFilter[];
      elapsedMs: number;
    }
  | { type: "error"; message: string; canReload: boolean }
  | { type: "rpcResult"; id: number; result: unknown }
  | { type: "rpcError"; id: number; error: { code: number; message: string; data?: unknown } }
  | { type: "applyFilter"; expr: string }
  | { type: "prepareFilter"; expr: string }
  | { type: "focusFilter" }
  | { type: "goto"; number: number }
  | { type: "columns"; columns: ColumnSetting[] }
  | { type: "history"; history: string[] }
  | { type: "savedFilters"; savedFilters: SavedFilter[] }
  /** Row `color` values of list_packets results with this `coloringId` index `rules`. */
  | { type: "coloring"; coloringId: number; rules: { name: string; foreground: string; background: string }[] };

/** Result of the backend's set_coloring. */
export interface ColoringResult {
  coloringId: number;
  colored: number;
  /** Rule index → why the rule was skipped. */
  errors: Record<string, string>;
}
