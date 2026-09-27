/**
 * Message protocol between the extension host and the webview
 * (src/webview/main.js). Keep both sides in sync.
 */
import type {
  ColumnLayout,
  ColumnSetting,
  QuickDetail,
  SavedFilter,
  TimeFormat,
} from "./settingsModel";

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
  /** Streaming open: the index pass is still running ("index" notifications follow). */
  indexing?: boolean;
  /** Opened from a saved index (no index pass). */
  fromCache?: boolean;
  /**
   * The coloring rules sent with `open` were evaluated by the index pass (or
   * their colors were saved with the index): rows come with colors of this
   * `coloringId`. `colored`/`errors` once known (else in the "done" event).
   */
  coloring?: { coloringId: number; colored?: number; errors?: Record<string, string> };
}

/** Backend methods the webview may call directly (anything else is refused). */
export const WEBVIEW_RPC_METHODS = new Set([
  "set_filter",
  "stop_filter",
  "validate_filter",
  "list_packets",
  "packet_detail",
  "find_frame",
  "view_frames",
  "field_index",
  "capture_info",
  "find_packet",
  "neighbor_frame",
  "mark_packets",
  "unmark_all",
  "field_types",
]);

/** Actions the host asks the webview to perform (command palette and keybindings). */
export const VIEWER_COMMANDS = [
  "find",
  "findNext",
  "findPrevious",
  "goBack",
  "goForward",
  "nextInConversation",
  "previousInConversation",
  "firstPacket",
  "lastPacket",
  "selectAll",
  "toggleMark",
  "nextMark",
  "previousMark",
  "unmarkAll",
  "toggleTimeReference",
] as const;
export type ViewerCommand = (typeof VIEWER_COMMANDS)[number];

export type WebviewToHost =
  | { type: "ready" }
  | { type: "rpc"; id: number; method: string; params: Record<string, unknown> }
  | { type: "cancel"; id: number }
  | { type: "cancelLoad" }
  | { type: "reload" }
  | { type: "filterApplied"; expr: string }
  | { type: "saveFilter"; expr: string }
  /** The focused packet (detail pane) and, for a multi-selection, every selected frame. */
  | { type: "selection"; frame: number | null; frames?: number[] }
  | { type: "decodeAs"; frame: number }
  | { type: "follow"; proto: "tcp" | "udp" | "tls" | "http"; frame: number }
  | { type: "manageSavedFilters" }
  | { type: "colorize"; filter: string }
  /** "✨ Ask AI": natural-language description of the wanted packets. */
  | { type: "aiSuggest"; id: number; request: string }
  | { type: "aiCancel"; id: number }
  | { type: "exportBytes"; frame: number }
  | { type: "applyColumn"; field: string; title: string }
  | { type: "removeColumn"; field: string }
  | { type: "renameColumn"; field: string }
  | { type: "columnLayout"; layout: ColumnLayout }
  | { type: "pickTimeFormat" }
  | { type: "pickNameResolution" }
  | { type: "exportMarked" }
  | { type: "exportSelected" }
  /** "Ask Copilot About This Packet…" / "…About N Selected Packets". */
  | { type: "askAboutPackets"; frames: number[] }
  | { type: "marks"; count: number }
  | { type: "copy"; text: string }
  | { type: "showLog" };

export type HostToWebview =
  | { type: "loading"; message: string }
  /** Progress of the capture load, or (with `id`) of the webview's request `id`. */
  | {
      type: "progress";
      id?: number;
      phase?: string;
      fraction?: number | null;
      frames?: number;
      matched?: number;
    }
  | {
      type: "init";
      info: OpenResult;
      columns: ColumnSetting[];
      layout: ColumnLayout;
      timeFormat: TimeFormat;
      quickDetail: QuickDetail;
      filter: string;
      history: string[];
      savedFilters: SavedFilter[];
      elapsedMs: number;
      /** Status-bar text for the name resolution in effect, e.g. "Names: MAC". */
      names: string;
    }
  | { type: "error"; message: string; canReload: boolean }
  | { type: "rpcResult"; id: number; result: unknown }
  | { type: "rpcError"; id: number; error: { code: number; message: string; data?: unknown } }
  | { type: "applyFilter"; expr: string }
  | { type: "prepareFilter"; expr: string }
  | { type: "focusFilter" }
  | { type: "goto"; number: number }
  | { type: "columns"; columns: ColumnSetting[]; layout: ColumnLayout }
  | { type: "timeFormat"; format: TimeFormat }
  | { type: "quickDetail"; quickDetail: QuickDetail }
  /**
   * Streaming open: `frames` indexed so far (`fraction` when the format allows an
   * estimate); with a filter applied, `view` is how many of its matches are shown.
   */
  | { type: "indexProgress"; frames: number; fraction: number | null; view?: ViewCounts }
  /** The index pass ended: the final capture info (with `error` if it stopped early). */
  | { type: "indexDone"; info: OpenResult; error?: string; view?: ViewCounts }
  /** A streaming filter (set_filter with `stream`): more matches, or its end. */
  | ({ type: "filterEvent" } & FilterEvent)
  | { type: "command"; command: ViewerCommand }
  | { type: "history"; history: string[] }
  | { type: "savedFilters"; savedFilters: SavedFilter[] }
  /** Row `color` values of list_packets results with this `coloringId` index `rules`. */
  | {
      type: "coloring";
      coloringId: number;
      rules: { name: string; foreground: string; background: string }[];
    }
  /** A separate coloring pass is running (`fraction` when known), or it ended without new colors (`done`). */
  | { type: "coloringProgress"; fraction: number | null; done?: boolean }
  /** Whether to show the "✨ Ask AI" action (a language model is available and allowed). */
  | { type: "aiAvailable"; available: boolean }
  /** Validated suggestions for an aiSuggest request (empty with a `message` when there are none). */
  | {
      type: "aiSuggestions";
      id: number;
      suggestions: { filter: string; explanation: string }[];
      message?: string;
    };

/** How many matches the filtered view `filterId` shows. */
export interface ViewCounts {
  filterId: number;
  matchCount: number;
}

/** The backend's "filter" notification of a streaming filter. */
export interface FilterEvent extends ViewCounts {
  event: "progress" | "done" | "stopped" | "failed";
  fraction?: number | null;
  total?: number;
  message?: string;
}

/** Result of the backend's set_coloring. */
export interface ColoringResult {
  coloringId: number;
  colored: number;
  /** Rule index → why the rule was skipped. */
  errors: Record<string, string>;
}
