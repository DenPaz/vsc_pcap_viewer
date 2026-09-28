// @ts-check
/**
 * PCAP Viewer webview: filter bar, virtualized packet list, detail tree and
 * hex view. Talks to the extension host with postMessage; the host forwards
 * whitelisted calls to the Python backend.
 *
 * Security: packet data is untrusted. It is only ever inserted with
 * textContent / createElement — never innerHTML.
 */
(function () {
  "use strict";

  const vscode = acquireVsCodeApi();
  /** @type {any} */
  const lib = /** @type {any} */ (window).PcapLib;

  const PAGE_SIZE = 200;
  const MAX_CACHED_PAGES = 100;
  const MAX_INFLIGHT_PAGES = 6;
  // Multi-selection limits (the backend's MAX_SELECTION and MAX_PAGE).
  const MAX_SELECTION = 1_000_000;
  const MAX_COPY_ROWS = 100_000;
  const COPY_CHUNK = 5000;

  /** @type {Record<string, string>} */
  const TIME_LABELS = {
    relative: "Time: seconds since start",
    delta_displayed: "Time: since previous displayed",
    delta_captured: "Time: since previous captured",
    absolute: "Time: local date and time",
    utc: "Time: UTC date and time",
    epoch: "Time: epoch seconds",
  };
  const DEFAULT_WIDTHS = {
    number: 70,
    time: 100,
    source: 150,
    destination: 150,
    protocol: 80,
    length: 64,
  };
  const CUSTOM_WIDTH = 120;
  const NUMERIC_IDS = new Set(["number", "time", "length"]);

  /** @param {string} id */
  const $ = (id) => /** @type {HTMLElement} */ (document.getElementById(id));

  /**
   * The progress bar between the filter bar and the packet list, for the
   * long-running work (lib.progressView: indexing, a streaming filter, an
   * export, coloring, other requests). Built with createElement, styled in
   * styles.css; renderProgress() updates it.
   */
  function createProgressBar() {
    const bar = document.createElement("div");
    bar.id = "busy-bar";
    bar.className = "progress-bar hidden";
    bar.setAttribute("role", "progressbar");
    bar.setAttribute("aria-valuemin", "0");
    bar.setAttribute("aria-valuemax", "100");
    const fill = document.createElement("div");
    fill.className = "progress-fill";
    bar.append(fill);
    $("main").before(bar);
    return { bar, fill };
  }
  const progressBar = createProgressBar();

  const el = {
    filterInput: /** @type {HTMLInputElement} */ ($("filter-input")),
    filterApply: $("filter-apply"),
    filterClear: $("filter-clear"),
    filterCancel: $("filter-cancel"),
    filterError: $("filter-error"),
    filterSaved: $("filter-saved"),
    filterMenu: $("filter-menu"),
    filterButtons: $("filter-buttons"),
    filterAi: $("filter-ai"),
    filterField: $("filter-field"),
    suggest: $("suggest"),
    busyBar: progressBar.bar,
    busyFill: progressBar.fill,
    list: $("list"),
    header: $("list-header"),
    viewport: $("list-viewport"),
    spacer: $("list-spacer"),
    rows: $("list-rows"),
    empty: $("list-empty"),
    splitH: $("split-h"),
    splitV: $("split-v"),
    detail: $("detail"),
    tree: $("detail-tree"),
    treePlaceholder: $("detail-placeholder"),
    detailPane: $("detail"),
    detailNote: $("detail-note"),
    commentBar: $("comment-bar"),
    commentView: $("comment-view"),
    commentText: $("comment-text"),
    commentEdited: $("comment-edited"),
    commentEditor: $("comment-editor"),
    commentInput: /** @type {HTMLTextAreaElement} */ ($("comment-input")),
    bytesTabs: $("bytes-tabs"),
    bytesView: $("bytes-view"),
    statusLeft: $("status-left"),
    statusRight: $("status-right"),
    statusTime: $("status-time"),
    statusNames: $("status-names"),
    statusInfo: $("status-info"),
    statusCapture: $("status-capture"),
    captureText: $("capture-text"),
    captureStop: $("capture-stop"),
    findBar: $("find-bar"),
    findMode: /** @type {HTMLSelectElement} */ ($("find-mode")),
    findInput: /** @type {HTMLInputElement} */ ($("find-input")),
    findCase: /** @type {HTMLInputElement} */ ($("find-case")),
    findCaseLabel: $("find-case-label"),
    findPrev: $("find-prev"),
    findNext: $("find-next"),
    findStatus: $("find-status"),
    findClose: $("find-close"),
    overlay: $("overlay"),
    overlayBox: /** @type {HTMLElement} */ (document.querySelector(".overlay-box")),
    overlayMessage: $("overlay-message"),
    overlayProgress: $("overlay-progress"),
    overlayFill: $("overlay-progress-fill"),
    overlayDetail: $("overlay-detail"),
    overlayCancel: $("overlay-cancel"),
    overlayReload: $("overlay-reload"),
    overlayLog: $("overlay-log"),
    menu: $("context-menu"),
  };

  const saved = vscode.getState() || {};

  /**
   * @typedef {{id: string, title: string, field: string, numeric?: boolean, custom?: boolean}} Column
   * @typedef {{number: number, cells: string[], color?: number, cid?: number, marked?: boolean, addresses?: string[], comment?: string, commentEdited?: boolean}} Row
   * @typedef {{name: string, foreground: string, background: string}} ColorRule
   */
  const state = {
    ready: false,
    /** @type {any} */ info: null,
    /** @type {Column[]} */ baseColumns: [],
    /** @type {{field: string, title: string}[]} */ customColumns: [],
    /** @type {Record<string, number>} */ widths: saved.widths || {},
    appliedFilter: "",
    filterId: 0,
    total: 0,
    matchCount: 0,
    /** @type {{field: string, desc: boolean} | null} */ sort: null,
    viewKey: "",
    pages: new lib.LruMap(MAX_CACHED_PAGES),
    /** @type {Map<string, number>} page key -> rpc id */ inflightPages: new Map(),
    /** @type {number | null} */ selectedFrame: null,
    /** @type {number | null} */ selectedIndex: null,
    /** Every selected frame of a multi-selection (Shift/Ctrl+click, Ctrl+A); empty for one. */
    /** @type {Set<number>} */ selection: new Set(),
    /** Row a Shift+click range starts from; the filter the selection was made under. */
    /** @type {number | null} */ anchorIndex: null,
    selectionFilterId: 0,
    rangeSeq: 0,
    /** @type {any} */ detail: null,
    /** @type {number | null} */ detailRequest: null,
    /** @type {number | null} */ selectedNodeId: null,
    /** @type {Set<string>} */ expanded: new Set(saved.expanded || []),
    activeSource: 0,
    rowHeight: 22,
    /** @type {string[]} */ history: [],
    /** @type {{name: string, filter: string}[]} */ savedFilters: [],
    /** `pcapViewer.filterButtons`: the bar under the filter bar. */
    /** @type {{label: string, filter: string, comment?: string}[]} */ filterButtons: [],
    /** @type {number | null} */ filterRequest: null,
    validateSeq: 0,
    /** @type {number | null} */ elapsedMs: null,
    /** Palette for rows whose list_packets result had this coloringId. */
    /** @type {{id: number, rules: ColorRule[]} | null} */ coloring: null,
    /** A separate coloring pass is running (fraction, or null when unknown); undefined when not. */
    /** @type {number | null | undefined} */ coloringProgress: undefined,
    /** Column order / hidden columns (pcapViewer.columnLayout). */
    /** @type {{order: string[], hidden: string[]}} */ layout: { order: [], hidden: [] },
    /** Time column format (pcapViewer.timeFormat) and time reference frame (Ctrl+T). */
    timeFormat: "relative",
    /** Quick (approximate) detail from frame `after` on (0 = never), dissecting `window` packets (pcapViewer.quickDetail). */
    quickDetail: { after: 20000, window: 300 },
    /** @type {number | null} */ quickRequest: null,
    /** Streaming open: the index pass still runs (rows keep arriving; sorting waits). */
    indexing: false,
    /**
     * A live capture writing this file: its interfaces, whether it still runs,
     * and its latest statistics (``seconds`` since ``startedAt``, epoch seconds).
     * @type {{running: boolean, interfaces: string[], filter: string, startedAt: number, packets: number, bytes: number, seconds: number, dropped: number | null} | null}
     */
    capture: null,
    /** @type {number | null} */ indexFraction: null,
    /** "catching-up" while a resumed open re-reads the rows it already shows, else "indexing". */
    indexPhase: "indexing",
    /** Rows a resumed open started with (shown at once), else null. */
    /** @type {number | null} */ resumedAt: null,
    /** An export's progress (undefined: none running, null: amount unknown). */
    /** @type {number | null | undefined} */ exportProgress: undefined,
    /** Streaming filter: its matches are still arriving (a sort applies when it's done). */
    filtering: false,
    /** @type {number | null} */ filterFraction: null,
    /** The filter was stopped (or failed) early: the list holds the matches found by then. */
    filterPartial: false,
    /** "filter" events that came before the set_filter result naming their filterId. */
    /** @type {Map<number, any>} */ earlyFilterEvents: new Map(),
    /** @type {number | null} */ timeRef: null,
    markCount: 0,
    /** Back/forward history over jumps (links, go to, find, marks, conversation). */
    /** @type {{back: number[], forward: number[]}} */ nav: { back: [], forward: [] },
    /** Field name → {type, desc} from the backend's field catalogue (frame links, Apply as Column). */
    /** @type {Map<string, {type: string, desc: string}>} */ fieldTypes: new Map(),
    /** "✨ Ask AI": available (host says a model can be used), asking (the input holds a description). */
    /** The ☰ menu's commands (host "commands" message). @type {any[]} */
    commands: [],
    /** The ☰ menu's open headings (the rest start folded), kept in the webview state. */
    /** @type {Set<string>} */ menuGroups: new Set(
      Array.isArray(saved.menuGroups) ? saved.menuGroups : [],
    ),
    ai: {
      available: false,
      asking: false,
      /** @type {number | null} */ request: null,
      savedText: "",
      /** @type {string[]} */ savedClasses: [],
    },
  };

  // ------------------------------------------------------------------ rpc

  let rpcSeq = 0;
  /** @type {Map<number, {resolve: (v: any) => void, reject: (e: any) => void}>} */
  const rpcPending = new Map();

  /**
   * @param {string} method
   * @param {Record<string, unknown>} params
   * @returns {{id: number, promise: Promise<any>}}
   */
  function rpc(method, params) {
    const id = ++rpcSeq;
    const promise = new Promise((resolve, reject) => {
      rpcPending.set(id, { resolve, reject });
    });
    vscode.postMessage({ type: "rpc", id, method, params });
    return { id, promise };
  }

  /** @param {number} id */
  function cancelRpc(id) {
    if (rpcPending.has(id)) {
      vscode.postMessage({ type: "cancel", id });
    }
  }

  const CANCELLED = -32800;
  const INVALID_FILTER = -32010;

  // ------------------------------------------------------------------ host messages

  window.addEventListener("message", (event) => {
    const msg = event.data;
    switch (msg.type) {
      case "loading":
        showOverlay(msg.message, { progress: true });
        break;
      case "progress":
        onProgress(msg);
        break;
      case "init":
        onInit(msg);
        break;
      case "error":
        showOverlay(msg.message, { error: true, reload: msg.canReload });
        break;
      case "rpcResult": {
        const p = rpcPending.get(msg.id);
        rpcPending.delete(msg.id);
        setBusy(msg.id, false);
        p?.resolve(msg.result);
        break;
      }
      case "rpcError": {
        const p = rpcPending.get(msg.id);
        rpcPending.delete(msg.id);
        setBusy(msg.id, false);
        p?.reject(msg.error);
        break;
      }
      case "applyFilter":
        el.filterInput.value = msg.expr;
        void applyFilter(msg.expr);
        break;
      case "prepareFilter":
        el.filterInput.value = msg.expr;
        el.filterInput.focus();
        validateSoon();
        break;
      case "focusFilter":
        el.filterInput.focus();
        el.filterInput.select();
        break;
      case "goto":
        void gotoFrame(msg.number);
        break;
      case "columns":
        state.customColumns = msg.columns;
        state.layout = msg.layout || { order: [], hidden: [] };
        rebuildColumns();
        resetView({ keepSelection: true });
        break;
      case "timeFormat":
        state.timeFormat = msg.format;
        updateStatus();
        refreshRows();
        break;
      case "quickDetail":
        state.quickDetail = msg.quickDetail;
        break;
      case "indexProgress":
        onIndexProgress(msg);
        break;
      case "exportProgress":
        state.exportProgress = msg.done ? undefined : (msg.fraction ?? null);
        updateStatus();
        break;
      case "captureEvent":
        onCaptureEvent(msg);
        break;
      case "indexDone":
        onIndexDone(msg.info, msg.error, msg.view);
        break;
      case "filterEvent":
        onFilterEvent(msg);
        break;
      case "command":
        runCommand(msg.command);
        break;
      case "commentsChanged":
        refreshRows();
        void showComment(state.selectedFrame);
        break;
      case "history":
        setHistory(msg.history);
        break;
      case "savedFilters":
        state.savedFilters = msg.savedFilters || [];
        if (suggest.mode === "saved") {
          showSavedMenu();
        }
        break;
      case "coloring":
        state.coloring = msg.rules.length ? { id: msg.coloringId, rules: msg.rules } : null;
        state.coloringProgress = undefined;
        refreshRows();
        updateStatus();
        break;
      case "coloringProgress":
        state.coloringProgress = msg.done ? undefined : msg.fraction;
        updateStatus();
        break;
      case "aiAvailable":
        setAiAvailable(!!msg.available);
        break;
      case "commands":
        state.commands = Array.isArray(msg.commands) ? msg.commands : [];
        break;
      case "filterButtons":
        state.filterButtons = Array.isArray(msg.buttons) ? msg.buttons : [];
        renderFilterButtons();
        break;
      case "aiSuggestions":
        onAiSuggestions(msg);
        break;
    }
  });

  /** @param {any} msg */
  function onInit(msg) {
    leaveAskMode(true);
    state.info = msg.info;
    // The backend lists the seven base columns first, then any custom ones.
    state.baseColumns = msg.info.columns.slice(0, 7);
    // Only columns tshark accepted; unknown fields were dropped (with a warning) at open.
    state.customColumns = lib.acceptedColumns(msg.columns, msg.info.columns.slice(7));
    state.layout = msg.layout || { order: [], hidden: [] };
    state.timeFormat = msg.timeFormat || "relative";
    el.statusNames.textContent = msg.names || "";
    state.quickDetail = msg.quickDetail || state.quickDetail;
    state.timeRef = null;
    state.markCount = 0;
    state.nav = { back: [], forward: [] };
    state.total = msg.info.frames;
    state.matchCount = msg.info.frames;
    state.filterId = msg.info.filterId;
    state.indexing = !!msg.info.indexing;
    state.indexFraction = null;
    state.resumedAt = state.indexing && msg.info.resumedAt ? msg.info.resumedAt : null;
    state.indexPhase = state.resumedAt ? "catching-up" : "indexing";
    state.exportProgress = undefined;
    const capture = msg.info.capture;
    state.capture = capture
      ? {
          running: !!capture.running,
          interfaces: capture.interfaces || [],
          filter: capture.filter || "",
          startedAt: capture.startedAt || Date.now() / 1000,
          packets: capture.packets || 0,
          bytes: capture.bytes || 0,
          seconds: 0,
          dropped: capture.dropped ?? null,
        }
      : null;
    tickCapture();
    state.filtering = false;
    state.filterFraction = null;
    state.filterPartial = false;
    state.earlyFilterEvents.clear();
    state.coloringProgress = undefined;
    state.ready = true;
    setHistory(msg.history);
    state.savedFilters = msg.savedFilters || [];
    // Warm the backend's field catalogue so the first suggestion is instant.
    rpc("field_index", { limit: 0 }).promise.catch(() => undefined);
    hideOverlay();
    rebuildColumns();
    clearDetail();
    state.selectedFrame = null;
    state.selectedIndex = null;
    state.selection = new Set();
    state.anchorIndex = null;
    busyRequests.clear();
    renderProgress();
    state.elapsedMs = msg.elapsedMs;
    const filter = msg.filter || el.filterInput.value.trim();
    if (filter) {
      el.filterInput.value = filter;
      void applyFilter(filter);
    } else {
      resetView();
    }
    updateStatus();
    el.viewport.focus();
  }

  /** @param {any} p */
  function onProgress(p) {
    const fraction = typeof p.fraction === "number" ? p.fraction : null;
    if (!el.overlay.classList.contains("hidden")) {
      setProgress(el.overlayProgress, el.overlayFill, fraction);
      if (typeof p.frames === "number") {
        el.overlayDetail.textContent = `${p.frames.toLocaleString()} packets${fraction !== null ? ` · ${Math.round(fraction * 100)}%` : ""}`;
      }
    } else if (typeof p.id === "number" && rpcPending.has(p.id)) {
      setBusy(p.id, true, fraction);
    }
  }

  /**
   * The busy bar shows while a request that reported progress (a filter, a first
   * sort, a column extraction…) is running, and hides when the last one settles.
   */
  /** Requests running (id → fraction, null if unknown). */
  /** @type {Map<number, number | null>} */
  const busyRequests = new Map();
  /** Busy-bar id of a streaming filter after its set_filter request returned. */
  const FILTER_BUSY = -1;
  /** @param {number} id @param {boolean} on @param {number | null} [fraction] */
  function setBusy(id, on, fraction = null) {
    if (on) {
      busyRequests.set(id, fraction);
    } else {
      busyRequests.delete(id);
    }
    renderProgress();
  }

  /** Show the most important work running in the progress bar (or hide it). */
  function renderProgress() {
    const busy = [...busyRequests.values()];
    const view = lib.progressView({
      index:
        state.indexing && !state.capture && state.info
          ? {
              phase: state.indexPhase,
              frames: state.info.frames,
              fraction: state.indexFraction,
              resumedAt: state.resumedAt,
            }
          : null,
      filter: state.filtering ? state.filterFraction : undefined,
      exporting: state.exportProgress,
      coloring: state.coloringProgress,
      busy: busy.length ? (busy.find((f) => f !== null) ?? null) : undefined,
    });
    const bar = el.busyBar;
    bar.classList.toggle("hidden", !view.visible);
    bar.classList.toggle("indeterminate", view.visible && view.fraction === null);
    bar.classList.toggle("secondary", view.secondary);
    bar.setAttribute("aria-label", view.label || "Progress");
    if (view.visible && view.fraction !== null) {
      bar.setAttribute("aria-valuenow", String(Math.round(view.fraction * 100)));
      el.busyFill.style.width = `${(view.fraction * 100).toFixed(1)}%`;
    } else {
      bar.removeAttribute("aria-valuenow"); // (indeterminate, or hidden)
      el.busyFill.style.width = "";
    }
  }

  /**
   * @param {HTMLElement} bar @param {HTMLElement} fill @param {number | null} fraction
   */
  function setProgress(bar, fill, fraction) {
    bar.classList.toggle("indeterminate", fraction === null);
    fill.style.width = fraction === null ? "" : `${Math.round(fraction * 100)}%`;
  }

  // ------------------------------------------------------------------ overlay

  /**
   * @param {string} message
   * @param {{progress?: boolean, error?: boolean, reload?: boolean}} opts
   */
  function showOverlay(message, opts) {
    el.overlay.classList.remove("hidden");
    el.overlayBox.classList.toggle("error", !!opts.error);
    el.overlayMessage.textContent = message;
    el.overlayProgress.classList.toggle("hidden", !opts.progress);
    if (opts.progress) {
      setProgress(el.overlayProgress, el.overlayFill, null);
    }
    el.overlayDetail.textContent = "";
    el.overlayCancel.classList.toggle("hidden", !opts.progress);
    el.overlayReload.classList.toggle("hidden", !opts.reload);
    el.overlayLog.classList.toggle("hidden", !opts.error);
    if (opts.error) {
      state.ready = false;
    }
  }

  function hideOverlay() {
    el.overlay.classList.add("hidden");
  }

  el.overlayCancel.addEventListener("click", () => vscode.postMessage({ type: "cancelLoad" }));
  el.overlayReload.addEventListener("click", () => vscode.postMessage({ type: "reload" }));
  el.overlayLog.addEventListener("click", () => vscode.postMessage({ type: "showLog" }));

  // ------------------------------------------------------------------ columns

  /** @returns {Column[]} */
  function columns() {
    return [
      ...state.baseColumns,
      ...state.customColumns.map((c) => ({
        id: `custom:${c.field}`,
        title: c.title,
        field: c.field,
        custom: true,
      })),
    ];
  }

  /** Visible columns in display order, each with its cell index in a row. */
  function visibleColumns() {
    return lib.layoutColumns(columns(), state.layout);
  }

  /** @param {Column} c */
  function columnWidth(c) {
    return c.id === "info"
      ? "minmax(200px, 1fr)"
      : `${state.widths[c.id] ?? DEFAULT_WIDTHS[/** @type {keyof typeof DEFAULT_WIDTHS} */ (c.id)] ?? CUSTOM_WIDTH}px`;
  }

  function applyColumnWidths() {
    el.list.style.setProperty(
      "--cols",
      visibleColumns()
        .map((v) => columnWidth(v.column))
        .join(" "),
    );
  }

  function rebuildColumns() {
    const cols = visibleColumns().map((v) => v.column);
    applyColumnWidths();
    el.header.replaceChildren(
      ...cols.map((c) => {
        const cell = document.createElement("div");
        cell.className = "list-row-cell" + (NUMERIC_IDS.has(c.id) ? " num" : "");
        cell.title = `${c.field} (drag to reorder, right-click for options)`;
        cell.dataset.id = c.id;
        cell.draggable = true;
        cell.append(c.title);
        if (state.sort && state.sort.field === c.field) {
          const ind = document.createElement("span");
          ind.className = "sort-indicator";
          ind.textContent = state.sort.desc ? "▼" : "▲";
          cell.append(ind);
        }
        cell.addEventListener("click", (e) => {
          if (/** @type {HTMLElement} */ (e.target).classList.contains("resize-handle")) {
            return;
          }
          toggleSort(c.field);
        });
        if (c.id !== "info") {
          const handle = document.createElement("div");
          handle.className = "resize-handle";
          handle.addEventListener("mousedown", (e) => startColumnResize(e, c.id, cell));
          cell.append(handle);
        }
        return cell;
      }),
    );
    el.header.className = "list-row";
    // Row elements are rebuilt with the new column count on next render.
    el.rows.replaceChildren();
  }

  /**
   * Remove custom columns tshark doesn't know (e.g. a typo added in settings
   * while the file is open) and reload the visible pages without them.
   * @param {string[]} fields
   */
  function dropColumns(fields) {
    const bad = new Set(fields);
    state.customColumns = state.customColumns.filter((c) => !bad.has(c.field));
    if (state.sort && bad.has(state.sort.field)) {
      state.sort = null;
    }
    showFilterError(
      `Unknown field${fields.length > 1 ? "s" : ""} removed from columns: ${fields.join(", ")}`,
      true,
    );
    rebuildColumns();
    resetView({ keepSelection: true });
  }

  /**
   * The list grew (streaming open or filter) to `total` rows: the rows already
   * shown stay, and the last page, cut short where the list ended, is fetched again.
   * @param {number} total
   */
  function growList(total) {
    state.total = total;
    state.matchCount = total;
    const prefix = `${state.viewKey}#`;
    for (const [key, page] of [...state.pages.entries()]) {
      if (key.startsWith(prefix) && page.length < PAGE_SIZE) {
        state.pages.delete(key);
      }
    }
    updateSpacer();
    scheduleRender();
  }

  /**
   * The filtered view's match count from an index event (streaming open): the
   * matches among the packets indexed so far.
   * @param {{filterId: number, matchCount: number} | undefined} view
   */
  function viewCount(view) {
    return state.appliedFilter && view && view.filterId === state.filterId ? view.matchCount : null;
  }

  /**
   * More rows are indexed (streaming open): grow the list. A resumed open first
   * re-reads the rows it shows ("catching-up"); `restarted` means those didn't
   * match and indexing started over.
   * @param {{frames: number, fraction: number | null, view?: {filterId: number, matchCount: number}, phase?: string, resumedAt?: number, restarted?: boolean}} msg
   */
  function onIndexProgress(msg) {
    if (!state.indexing || !state.info) {
      return;
    }
    const frames = Number(msg.frames) || 0;
    const view = msg.view;
    // Live capture: while the end of the list is in view, it stays in view.
    const follow = !!state.capture?.running && atListEnd();
    state.info.frames = frames;
    state.indexFraction = typeof msg.fraction === "number" ? msg.fraction : null;
    const wasResuming = state.indexPhase === "catching-up";
    state.indexPhase = msg.phase === "catching-up" ? "catching-up" : "indexing";
    if (typeof msg.resumedAt === "number") {
      state.resumedAt = msg.resumedAt;
    }
    if (msg.restarted) {
      // A resumed open's saved rows no longer matched: indexed again from scratch.
      state.resumedAt = null;
      const matches = viewCount(view);
      state.total = state.appliedFilter ? (matches ?? 0) : frames;
      state.matchCount = state.total;
      updateSpacer();
      refreshRows();
      updateStatus();
      return;
    }
    const matches = viewCount(view);
    if (!state.appliedFilter) {
      growList(frames);
    } else if (matches !== null && matches !== state.total) {
      growList(matches);
    }
    if (wasResuming && state.indexPhase === "indexing") {
      refreshRows(); // the rows shown at once get their colors by now
    }
    if (follow) {
      el.viewport.scrollTop = el.viewport.scrollHeight;
    }
    updateStatus();
  }

  /** Whether the list is scrolled to its end (or is too short to scroll). */
  function atListEnd() {
    const vp = el.viewport;
    return vp.scrollTop + vp.clientHeight >= vp.scrollHeight - state.rowHeight * 1.5;
  }

  /**
   * The backend's "capture" notification: statistics while capturing, then "stopped".
   * @param {any} msg
   */
  function onCaptureEvent(msg) {
    const capture = state.capture;
    if (!capture) {
      return;
    }
    capture.packets = Number(msg.packets) || capture.packets;
    capture.bytes = Number(msg.bytes) || capture.bytes;
    capture.seconds = Number(msg.seconds) || capture.seconds;
    if (msg.event === "stopped") {
      capture.running = false;
      capture.dropped = typeof msg.dropped === "number" ? msg.dropped : null;
      if (msg.error) {
        showNotice(`The capture stopped: ${msg.error}`);
      }
    }
    tickCapture();
  }

  let captureTimer = 0;
  /** Show the capture's state in the status bar (and keep its clock running). */
  function tickCapture() {
    clearTimeout(captureTimer);
    const capture = state.capture;
    el.statusCapture.classList.toggle("hidden", !capture);
    if (!capture) {
      return;
    }
    const on = capture.interfaces.join(", ");
    el.statusCapture.classList.toggle("stopped", !capture.running);
    el.statusCapture.title = capture.filter ? `Capture filter: ${capture.filter}` : "";
    if (!capture.running) {
      // What was captured, until the capture is reloaded as a plain file.
      const dropped = capture.dropped ? ` · ${capture.dropped.toLocaleString()} dropped` : "";
      el.captureText.textContent = `Captured on ${on} in ${lib.formatDuration(capture.seconds)}${dropped}`;
      return;
    }
    const seconds = Math.max(capture.seconds, Date.now() / 1000 - capture.startedAt);
    el.captureText.textContent = `Capturing on ${on} · ${lib.formatDuration(seconds)} · ${lib.formatBytes(capture.bytes)}`;
    captureTimer = window.setTimeout(tickCapture, 1000);
  }

  /**
   * The index pass ended (streaming open).
   * @param {any} info @param {string | undefined} error @param {{filterId: number, matchCount: number}} [view]
   */
  function onIndexDone(info, error, view) {
    state.indexing = false;
    state.indexFraction = null;
    state.indexPhase = "indexing";
    state.resumedAt = null;
    state.info = info;
    const captured = !!state.capture;
    if (state.capture) {
      state.capture.running = false;
      tickCapture();
    }
    const matches = viewCount(view);
    if (!state.appliedFilter) {
      state.total = info.frames;
      state.matchCount = info.frames;
    } else if (matches !== null) {
      state.total = matches;
      state.matchCount = matches;
    }
    updateSpacer();
    refreshRows(); // columns and time formats that waited for the whole index
    updateStatus();
    if (error) {
      showNotice(`Indexing stopped after ${info.frames.toLocaleString()} packets: ${error}`);
    }
    if (captured && state.appliedFilter) {
      // The filter only saw the packets captured by the time it ran: run it again.
      void applyFilter(state.appliedFilter);
    }
  }

  /**
   * A streaming filter's "filter" event: more matches, or its end.
   * @param {{event: string, filterId: number, matchCount: number, fraction?: number | null, message?: string}} ev
   */
  function onFilterEvent(ev) {
    if (ev.filterId !== state.filterId) {
      if (ev.filterId > state.filterId) {
        state.earlyFilterEvents.set(ev.filterId, ev); // its set_filter result is on the way
      }
      return;
    }
    if (!state.filtering) {
      return;
    }
    if (ev.event === "progress") {
      state.filterFraction = ev.fraction ?? null;
      setBusy(FILTER_BUSY, true, state.filterFraction);
      if (ev.matchCount !== state.total) {
        growList(ev.matchCount);
      }
      updateStatus();
      return;
    }
    state.filtering = false;
    state.filterFraction = null;
    state.filterPartial = ev.event !== "done";
    setBusy(FILTER_BUSY, false);
    el.filterCancel.classList.add("hidden");
    state.total = ev.matchCount;
    state.matchCount = ev.matchCount;
    if (state.sort) {
      resetView({ keepSelection: true }); // the sort applies now
    } else {
      growList(ev.matchCount);
      if (state.selectedFrame !== null && state.selectedIndex === null) {
        void relocateSelection(); // it may have been found since
      }
    }
    updateStatus();
    const found = `${ev.matchCount.toLocaleString()} match${ev.matchCount === 1 ? "" : "es"}`;
    if (ev.event === "stopped") {
      showNotice(`Filter stopped: showing the ${found} found so far.`);
    } else if (ev.event === "failed") {
      showNotice(
        `The filter stopped early (${ev.message ?? "tshark failed"}): showing the ${found} found so far.`,
      );
    }
  }

  /** @param {string} field */
  function toggleSort(field) {
    if (!state.ready) {
      return;
    }
    if (state.indexing) {
      showNotice(
        state.capture
          ? "Sorting is available when the capture stops."
          : "Sorting is available when indexing finishes.",
      );
      return;
    }
    if (state.filtering) {
      showNotice("The list is sorted when the filter finishes.");
    }
    if (!state.sort || state.sort.field !== field) {
      state.sort = { field, desc: false };
    } else if (!state.sort.desc) {
      state.sort = { field, desc: true };
    } else {
      state.sort = null;
    }
    rebuildColumns();
    resetView({ keepSelection: true });
  }

  let resizing = false;

  /** @param {MouseEvent} e @param {string} id @param {HTMLElement} cell */
  function startColumnResize(e, id, cell) {
    e.preventDefault();
    e.stopPropagation();
    const startX = e.clientX;
    const startW = cell.getBoundingClientRect().width;
    /** @param {MouseEvent} ev */
    const move = (ev) => {
      state.widths[id] = Math.max(30, Math.round(startW + ev.clientX - startX));
      applyColumnWidths();
    };
    resizing = true;
    const up = () => {
      resizing = false;
      window.removeEventListener("mousemove", move);
      window.removeEventListener("mouseup", up);
      persist();
    };
    window.addEventListener("mousemove", move);
    window.addEventListener("mouseup", up);
  }

  // ------------------------------------------------------------------ view / paging

  function computeViewKey() {
    return [
      state.filterId,
      state.sort ? `${state.sort.field}:${state.sort.desc}` : "",
      state.customColumns.map((c) => c.field).join(","),
      state.coloring?.id ?? 0,
      state.timeFormat,
      state.timeRef ?? "",
    ].join("|");
  }

  /** The view's order, sent with every request that deals in row indexes (the backend applies it first). */
  function orderParams() {
    return { sort: state.sort, timeFormat: state.timeFormat };
  }

  /** Refetch the visible rows in place (same order and scroll position), e.g. after new colors. */
  function refreshRows() {
    for (const id of state.inflightPages.values()) {
      cancelRpc(id);
    }
    state.inflightPages.clear();
    state.pages.clear();
    state.viewKey = computeViewKey();
    render();
  }

  /** Drop cached pages (filter, sort or columns changed) and re-render. */
  function resetView(opts = { keepSelection: false }) {
    for (const id of state.inflightPages.values()) {
      cancelRpc(id);
    }
    state.inflightPages.clear();
    state.pages.clear();
    state.viewKey = computeViewKey();
    updateSpacer();
    state.anchorIndex = null; // row indexes changed
    if (state.selection.size && state.selectionFilterId !== state.filterId) {
      setSelection(new Set()); // a new filter drops a multi-selection (a new sort keeps it)
    }
    if (opts.keepSelection && state.selectedFrame !== null) {
      state.selectedIndex = null; // unknown until the backend says where it moved
      void relocateSelection();
    } else {
      el.viewport.scrollTop = 0;
    }
    render();
  }

  function updateSpacer() {
    const win = lib.computeWindow({
      scrollTop: 0,
      viewportHeight: el.viewport.clientHeight,
      total: state.total,
      rowHeight: state.rowHeight,
    });
    el.spacer.style.height = `${win.virtualHeight}px`;
    el.empty.classList.toggle("hidden", !state.ready || state.total > 0);
  }

  /** @param {number} index @returns {Row | undefined} */
  function rowAt(index) {
    const page = state.pages.get(`${state.viewKey}#${Math.floor(index / PAGE_SIZE)}`);
    return page ? page[index % PAGE_SIZE] : undefined;
  }

  let renderQueued = false;
  function scheduleRender() {
    if (!renderQueued) {
      renderQueued = true;
      requestAnimationFrame(() => {
        renderQueued = false;
        render();
      });
    }
  }

  function render() {
    if (!state.ready) {
      return;
    }
    const win = lib.computeWindow({
      scrollTop: el.viewport.scrollTop,
      viewportHeight: el.viewport.clientHeight,
      total: state.total,
      rowHeight: state.rowHeight,
    });
    el.rows.style.transform = `translateY(${win.top}px)`;
    const cols = visibleColumns();
    // Reuse row elements (pooling keeps scrolling cheap).
    while (el.rows.children.length < win.count) {
      const row = document.createElement("div");
      row.className = "list-row";
      for (let i = 0; i < cols.length; i++) {
        const cell = document.createElement("div");
        if (NUMERIC_IDS.has(cols[i].column.id)) {
          cell.className = "num";
        }
        row.append(cell);
      }
      el.rows.append(row);
    }
    while (el.rows.children.length > win.count) {
      el.rows.lastChild?.remove();
    }
    for (let i = 0; i < win.count; i++) {
      const index = win.first + i;
      const rowEl = /** @type {HTMLElement} */ (el.rows.children[i]);
      const row = rowAt(index);
      rowEl.dataset.index = String(index);
      rowEl.classList.toggle("odd", index % 2 === 1);
      rowEl.classList.toggle("loading", !row);
      const selected = index === state.selectedIndex || (!!row && state.selection.has(row.number));
      rowEl.classList.toggle("selected", selected);
      rowEl.classList.toggle("focused", index === state.selectedIndex && state.selection.size > 1);
      rowEl.setAttribute("aria-selected", String(selected));
      // Coloring rule colors, except on selected rows (they keep the theme's selection
      // colors) and marked rows (the mark style wins).
      rowEl.classList.toggle("marked", !!row?.marked);
      rowEl.classList.toggle("has-comment", !!row?.comment);
      rowEl.classList.toggle("comment-edited", !!row?.commentEdited);
      const rule = !selected && !row?.marked ? lib.rowColors(row, state.coloring) : null;
      rowEl.classList.toggle("colored", !!rule);
      rowEl.style.backgroundColor = rule ? rule.background : "";
      rowEl.style.color = rule ? rule.foreground : "";
      for (let c = 0; c < cols.length; c++) {
        const cell = /** @type {HTMLElement} */ (rowEl.children[c]);
        // Times arrive formatted by the backend (pcapViewer.timeFormat, time reference).
        const text = row ? (row.cells[cols[c].index] ?? "") : c === 0 ? "…" : "";
        if (cell.textContent !== text) {
          cell.textContent = text;
        }
        // A resolved name: the address as tooltip; the No. cell: the packet's comment.
        const tip =
          (row && cols[c].column.id === "number"
            ? row.comment
            : lib.cellAddress(cols[c].column, row)) ?? "";
        if (cell.title !== tip) {
          cell.title = tip;
        }
      }
    }
    requestPages(win.first, win.count);
  }

  /** @param {number} first @param {number} count */
  function requestPages(first, count) {
    const pages = lib.pagesForRange(first, count, PAGE_SIZE, state.total, 1);
    const viewKey = state.viewKey;
    for (const page of pages) {
      const key = `${viewKey}#${page}`;
      if (
        state.pages.has(key) ||
        state.inflightPages.has(key) ||
        state.inflightPages.size >= MAX_INFLIGHT_PAGES
      ) {
        continue;
      }
      const req = rpc("list_packets", {
        offset: page * PAGE_SIZE,
        limit: PAGE_SIZE,
        columns: state.customColumns.map((c) => c.field),
        sort: state.sort,
        timeFormat: state.timeFormat,
        timeRef: state.timeRef,
      });
      state.inflightPages.set(key, req.id);
      req.promise.then(
        (res) => {
          state.inflightPages.delete(key);
          if (viewKey !== state.viewKey || res.filterId !== state.filterId) {
            return; // stale
          }
          if (res.rejectedColumns?.length) {
            dropColumns(res.rejectedColumns);
            return;
          }
          for (const row of res.rows) {
            row.cid = res.coloringId;
          }
          state.pages.set(key, res.rows);
          if (res.total !== state.total) {
            state.total = res.total;
            updateSpacer();
          }
          if (
            state.selectedIndex !== null &&
            state.selectedFrame === null &&
            Math.floor(state.selectedIndex / PAGE_SIZE) === page
          ) {
            const row = rowAt(state.selectedIndex);
            if (row) {
              selectFrame(row.number);
            }
          }
          scheduleRender();
        },
        (err) => {
          state.inflightPages.delete(key);
          if (err?.code !== CANCELLED && viewKey === state.viewKey) {
            showFilterError(`Could not load packets: ${err?.message ?? err}`);
          }
        },
      );
    }
  }

  el.viewport.addEventListener("scroll", scheduleRender, { passive: true });
  new ResizeObserver(() => {
    updateSpacer();
    scheduleRender();
  }).observe(el.viewport);

  // ------------------------------------------------------------------ selection

  el.rows.addEventListener("mousedown", (e) => {
    const rowEl = /** @type {HTMLElement | null} */ (
      /** @type {HTMLElement} */ (e.target).closest(".list-row")
    );
    if (!rowEl || rowEl.dataset.index === undefined || e.button !== 0) {
      return; // right-click: the context menu decides (it keeps a multi-selection)
    }
    const index = Number(rowEl.dataset.index);
    if (e.shiftKey) {
      e.preventDefault(); // no text selection
      void selectRange(index, e.ctrlKey || e.metaKey);
    } else if (e.ctrlKey || e.metaKey) {
      toggleInSelection(index);
    } else {
      selectIndex(index);
    }
  });

  el.viewport.addEventListener("keydown", (e) => {
    if (!state.ready || state.total === 0 || e.ctrlKey || e.metaKey || e.altKey) {
      return; // Ctrl+Home/End etc. are handled document-wide
    }
    const pageRows = Math.max(1, Math.floor(el.viewport.clientHeight / state.rowHeight) - 1);
    const cur = state.selectedIndex ?? -1;
    /** @type {Record<string, number>} */
    const moves = {
      ArrowDown: cur + 1,
      ArrowUp: cur - 1,
      PageDown: cur + pageRows,
      PageUp: cur - pageRows,
      Home: 0,
      End: state.total - 1,
    };
    if (e.key in moves) {
      e.preventDefault();
      const target = Math.max(0, Math.min(state.total - 1, moves[e.key]));
      if (e.shiftKey) {
        void selectRange(target, false);
      } else {
        selectIndex(target);
      }
    } else if (e.key === "Escape" && state.selection.size) {
      setSelection(new Set());
    } else if (e.key === "Enter" || e.key === "ArrowRight") {
      e.preventDefault();
      el.tree.focus();
    }
  });

  /** Select one row (dropping a multi-selection). @param {number} index @param {boolean} [center] */
  function selectIndex(index, center = false) {
    state.anchorIndex = index;
    if (state.selection.size) {
      setSelection(new Set());
    }
    focusIndex(index, center);
  }

  /** Move the focused row (the one the detail pane shows) without changing the selection. @param {number} index @param {boolean} [center] */
  function focusIndex(index, center = false) {
    state.selectedIndex = index;
    scrollIndexIntoView(index, center);
    const row = rowAt(index);
    state.selectedFrame = row ? row.number : null;
    if (row) {
      selectFrame(row.number);
    }
    scheduleRender();
  }

  /** Frames the row actions (mark, copy, export) apply to: the multi-selection, else the focused row. */
  function selectedFrames() {
    if (state.selection.size) {
      return [...state.selection];
    }
    return state.selectedFrame !== null ? [state.selectedFrame] : [];
  }

  /** @param {Set<number>} frames the new multi-selection (one frame or none = single selection) */
  function setSelection(frames) {
    state.selection = frames.size > 1 ? frames : new Set();
    state.selectionFilterId = state.filterId;
    postSelection();
    updateStatus();
    scheduleRender();
  }

  /** Ctrl/Cmd+click: add a row to the selection, or take it out. @param {number} index */
  function toggleInSelection(index) {
    const row = rowAt(index);
    if (!row) {
      return;
    }
    const next = new Set(selectedFrames());
    state.anchorIndex = index;
    if (!next.has(row.number)) {
      next.add(row.number);
      setSelection(next);
      focusIndex(index);
      return;
    }
    if (next.size === 1) {
      return; // the last selected row stays selected
    }
    next.delete(row.number);
    setSelection(next);
    if (row.number === state.selectedFrame) {
      void focusFrame(next.values().next().value ?? row.number); // focus another selected row
    }
  }

  /** Focus a frame of the current view by number (no scrolling). @param {number} frame */
  async function focusFrame(frame) {
    try {
      const viewKey = state.viewKey;
      const res = await rpc("find_frame", { number: frame, ...orderParams() }).promise;
      if (
        res.filterId === state.filterId &&
        viewKey === state.viewKey &&
        typeof res.index === "number"
      ) {
        focusIndex(res.index);
      }
    } catch {
      /* ignore */
    }
  }

  /**
   * Shift+click / Shift+arrows: select the rows from the anchor to `index`
   * (added to the selection with Ctrl). Rows not loaded yet come from the backend.
   * @param {number} index @param {boolean} add
   */
  async function selectRange(index, add) {
    const anchor = state.anchorIndex ?? state.selectedIndex ?? index;
    state.anchorIndex = anchor;
    const lo = Math.min(anchor, index);
    const count = Math.min(Math.max(anchor, index) - lo + 1, MAX_SELECTION);
    const base = add ? selectedFrames() : [];
    const seq = ++state.rangeSeq;
    focusIndex(index);
    /** @type {number[]} */
    let frames = [];
    for (let i = lo; i < lo + count; i++) {
      const row = rowAt(i);
      if (!row) {
        frames = [];
        break;
      }
      frames.push(row.number);
    }
    if (!frames.length) {
      try {
        const viewKey = state.viewKey;
        const res = await rpc("view_frames", { offset: lo, limit: count, ...orderParams() })
          .promise;
        if (
          seq !== state.rangeSeq ||
          res.filterId !== state.filterId ||
          viewKey !== state.viewKey
        ) {
          return;
        }
        frames = res.frames;
      } catch (err) {
        showNotice(String(/** @type {any} */ (err)?.message ?? err));
        return;
      }
    }
    if (count === MAX_SELECTION) {
      showNotice(`Selected the first ${MAX_SELECTION.toLocaleString()} packets of the range.`);
    }
    setSelection(new Set([...base, ...frames]));
  }

  let selectAllPending = false;
  /** Ctrl+A: every packet of the current view (in the filter bar or find box: its text). */
  async function selectAll() {
    const active = /** @type {HTMLElement | null} */ (document.activeElement);
    if (active?.tagName === "INPUT" || active?.tagName === "TEXTAREA") {
      /** @type {HTMLInputElement} */ (active).select();
      return;
    }
    const all = Math.min(state.total, MAX_SELECTION);
    if (
      !state.ready ||
      state.total === 0 ||
      selectAllPending ||
      (all > 1 && state.selection.size === all)
    ) {
      return; // (the key and VS Code's Select All command can both arrive)
    }
    selectAllPending = true;
    const filterId = state.filterId;
    try {
      const res = await rpc("view_frames", {
        offset: 0,
        limit: Math.min(state.total, MAX_SELECTION),
        ...orderParams(),
      }).promise;
      if (res.filterId !== filterId) {
        return;
      }
      if (state.selectedIndex === null) {
        focusIndex(0);
      }
      setSelection(new Set(res.frames));
      if (state.total > MAX_SELECTION) {
        showNotice(`Selected the first ${MAX_SELECTION.toLocaleString()} packets.`);
      }
    } catch (err) {
      showNotice(String(/** @type {any} */ (err)?.message ?? err));
    } finally {
      selectAllPending = false;
    }
  }

  // Ctrl+A / Cmd+A. VS Code's webview doesn't stop the key, so Chromium selects
  // all of the page's text, and VS Code's own Select All runs execCommand("selectAll")
  // in the webview (a package.json keybinding doesn't win over either). Both start
  // with a cancelable selectstart on <body> (in an input its target is the input,
  // which keeps its normal Ctrl+A): cancel it and select every packet instead.
  let pointerDown = false; // a mouse drag can also start on <body>
  document.addEventListener("mousedown", () => (pointerDown = true), true);
  document.addEventListener("mouseup", () => (pointerDown = false), true);
  document.addEventListener("selectstart", (e) => {
    if (e.target === document.body && !pointerDown) {
      e.preventDefault();
      void selectAll();
    }
  });

  /** Cached rows of `frames` in view order, or null if some aren't loaded. @param {Set<number>} frames */
  function cachedRows(frames) {
    /** @type {{index: number, row: Row}[]} */
    const found = [];
    const prefix = `${state.viewKey}#`;
    for (const [key, page] of state.pages.entries()) {
      if (!key.startsWith(prefix)) {
        continue;
      }
      const first = Number(key.slice(prefix.length)) * PAGE_SIZE;
      page.forEach((/** @type {Row} */ row, /** @type {number} */ i) => {
        if (frames.has(row.number)) {
          found.push({ index: first + i, row });
        }
      });
    }
    if (found.length !== frames.size) {
      return null;
    }
    return found.sort((a, b) => a.index - b.index).map((f) => f.row);
  }

  /** The visible columns' titles and each row's cells, for copying. @param {Row[]} rows */
  function copyText(rows) {
    const cols = visibleColumns();
    const cells = rows.map((r) => cols.map((c) => r.cells[c.index] ?? ""));
    return lib.rowsToText(
      cols.map((c) => c.column.title),
      cells,
      rows.length > 1,
    );
  }

  /** Copy the selected rows (visible columns, view order); rows not loaded come from the backend. */
  async function copyRows() {
    const frames = selectedFrames();
    if (!frames.length) {
      return;
    }
    const cached = cachedRows(new Set(frames));
    if (cached) {
      copy(copyText(cached));
      return;
    }
    const viewKey = state.viewKey;
    try {
      const ordered = (await rpc("view_frames", { frames, ...orderParams() }).promise).frames.slice(
        0,
        MAX_COPY_ROWS,
      );
      /** @type {Row[]} */
      const rows = [];
      for (let i = 0; i < ordered.length; i += COPY_CHUNK) {
        const res = await rpc("list_packets", {
          frames: ordered.slice(i, i + COPY_CHUNK),
          columns: state.customColumns.map((c) => c.field),
          sort: state.sort,
          timeFormat: state.timeFormat,
          timeRef: state.timeRef,
        }).promise;
        if (viewKey !== state.viewKey) {
          return; // the view changed meanwhile
        }
        rows.push(...res.rows);
      }
      copy(copyText(rows));
      if (frames.length > MAX_COPY_ROWS) {
        showNotice(
          `Copied the first ${MAX_COPY_ROWS.toLocaleString()} rows. Export Packet List saves them all.`,
        );
      }
    } catch (err) {
      showNotice(String(/** @type {any} */ (err)?.message ?? err));
    }
  }

  // Ctrl+C in the packet list (VS Code turns it into a "copy" event in the webview).
  document.addEventListener("copy", (e) => {
    const active = document.activeElement;
    if (!active || !el.viewport.contains(active) || !selectedFrames().length) {
      return;
    }
    e.preventDefault();
    const cached = cachedRows(new Set(selectedFrames()));
    if (cached && e.clipboardData) {
      e.clipboardData.setData("text/plain", copyText(cached));
    } else {
      void copyRows();
    }
  });

  /** @param {number} index @param {boolean} center */
  function scrollIndexIntoView(index, center) {
    const top = lib.scrollTopForIndex({
      index,
      scrollTop: el.viewport.scrollTop,
      viewportHeight: el.viewport.clientHeight,
      total: state.total,
      rowHeight: state.rowHeight,
      center,
    });
    if (Math.abs(top - el.viewport.scrollTop) >= 1) {
      el.viewport.scrollTop = top;
    }
  }

  let detailTimer = 0;
  /** @param {number} frame */
  function selectFrame(frame) {
    reportSelection(frame);
    state.selectedFrame = frame;
    updateStatus();
    window.clearTimeout(detailTimer);
    // Debounce so holding an arrow key doesn't start a tshark run per row.
    detailTimer = window.setTimeout(() => {
      void loadDetail(frame);
      void showComment(frame);
    }, 60);
  }

  // ------------------------------------------------------------------ packet comments

  /** Comment shown in the bar: frame, text ("" none), unsaved edit. */
  const comment = { frame: /** @type {number | null} */ (null), text: "", edited: false };

  /**
   * Show `frame`'s comment above its details (edits included), or hide the bar.
   * @param {number | null} frame
   */
  async function showComment(frame) {
    if (frame === null) {
      comment.frame = null;
      el.commentBar.classList.add("hidden");
      return;
    }
    let res;
    try {
      res = await rpc("packet_comments", { frames: [frame] }).promise;
    } catch {
      return; // (no capture)
    }
    if (state.selectedFrame !== frame) {
      return;
    }
    const editing = !el.commentEditor.classList.contains("hidden") && comment.frame === frame;
    comment.frame = frame;
    comment.text = res.comments[String(frame)] ?? "";
    comment.edited = res.edited.includes(frame);
    el.commentText.textContent = comment.text;
    el.commentEdited.classList.toggle("hidden", !comment.edited);
    if (!editing) {
      el.commentEditor.classList.add("hidden");
      el.commentView.classList.remove("hidden");
      el.commentBar.classList.toggle("hidden", !comment.text && !comment.edited);
    }
    if (!comment.text && comment.edited) {
      el.commentText.textContent = "(comment deleted)";
    }
  }

  /** Edit (or add) the selected packet's comment in the bar. */
  function editComment() {
    const frame = state.selectedFrame;
    if (frame === null) {
      return;
    }
    const open = () => {
      el.commentInput.value = comment.frame === frame ? comment.text : "";
      el.commentView.classList.add("hidden");
      el.commentEditor.classList.remove("hidden");
      el.commentBar.classList.remove("hidden");
      el.commentInput.focus();
    };
    if (comment.frame === frame) {
      open();
    } else {
      void showComment(frame).then(open);
    }
  }

  function applyComment() {
    if (comment.frame === null) {
      return;
    }
    const text = el.commentInput.value.replace(/\s+$/, "");
    el.commentEditor.classList.add("hidden");
    el.commentView.classList.remove("hidden");
    if (text !== comment.text) {
      vscode.postMessage({ type: "setComment", frame: comment.frame, text });
    } else {
      el.commentBar.classList.toggle("hidden", !comment.text && !comment.edited);
    }
  }

  function cancelComment() {
    el.commentEditor.classList.add("hidden");
    el.commentView.classList.remove("hidden");
    el.commentBar.classList.toggle("hidden", !comment.text && !comment.edited);
    el.viewport.focus();
  }

  /** @param {number} frame */
  function deleteComment(frame) {
    vscode.postMessage({ type: "setComment", frame, text: "" });
  }

  $("comment-edit").addEventListener("click", () => editComment());
  $("comment-delete").addEventListener("click", () => {
    if (comment.frame !== null) {
      deleteComment(comment.frame);
    }
  });
  $("comment-apply").addEventListener("click", () => applyComment());
  $("comment-cancel").addEventListener("click", () => cancelComment());
  el.commentInput.addEventListener("keydown", (e) => {
    if (e.key === "Enter" && (e.ctrlKey || e.metaKey)) {
      e.preventDefault();
      applyComment();
    } else if (e.key === "Escape") {
      e.preventDefault();
      e.stopPropagation();
      cancelComment();
    }
  });

  /** After a filter/sort change, find where the selected frame went. */
  async function relocateSelection() {
    const frame = state.selectedFrame;
    if (frame === null) {
      return;
    }
    const viewKey = state.viewKey;
    try {
      const res = await rpc("find_frame", { number: frame, ...orderParams() }).promise;
      if (
        res.filterId !== state.filterId ||
        frame !== state.selectedFrame ||
        viewKey !== state.viewKey
      ) {
        return;
      }
      if ((res.index === null || res.index === undefined) && state.filtering) {
        state.selectedIndex = null; // it may still come: looked up again when the filter is done
      } else if (res.index === null || res.index === undefined) {
        state.selectedIndex = null;
        state.selectedFrame = null;
        clearDetail();
        updateStatus();
      } else {
        state.selectedIndex = res.index;
        scrollIndexIntoView(res.index, true);
      }
      scheduleRender();
    } catch {
      /* ignore */
    }
  }

  /**
   * Select a frame by number (go to packet, frame links, history). If the
   * filter hides it, say so and offer to clear the filter.
   * @param {number} frame @param {{record?: boolean}} [opts] record: add the jump to the back history
   * @returns {Promise<boolean>}
   */
  async function gotoFrame(frame, opts = {}) {
    if (!state.ready) {
      return false;
    }
    try {
      const res = await rpc("find_frame", { number: frame, ...orderParams() }).promise;
      if (res.index === null || res.index === undefined) {
        showNotice(
          `Packet ${frame} is not displayed with the current filter.`,
          state.appliedFilter
            ? { label: "Clear filter and go", run: () => void clearFilterAndGo(frame, opts) }
            : undefined,
        );
        return false;
      }
      if (opts.record !== false) {
        recordJump(frame);
      }
      selectIndex(res.index, true);
      el.viewport.focus();
      return true;
    } catch (err) {
      showFilterError(String(/** @type {any} */ (err)?.message ?? err), true);
      return false;
    }
  }

  /** @param {number} frame @param {{record?: boolean}} opts */
  async function clearFilterAndGo(frame, opts) {
    el.filterInput.value = "";
    await applyFilter("");
    await gotoFrame(frame, opts);
  }

  // ------------------------------------------------------------------ detail tree

  /** @param {number} frame */
  /**
   * Show a packet's detail. The exact detail dissects the capture up to the
   * packet (cost grows with its number), so for late packets a quick view
   * (only pcapViewer.quickDetail.window packets dissected) is shown first,
   * marked approximate, until the exact one replaces it.
   * @param {number} frame
   */
  async function loadDetail(frame) {
    for (const id of [state.detailRequest, state.quickRequest]) {
      if (id !== null) {
        cancelRpc(id);
      }
    }
    state.quickRequest = null;
    if (state.detail && state.detail.number === frame && !state.detail.approximate) {
      return;
    }
    showDetailNote("", false); // the note belonged to the previous packet
    const req = rpc("packet_detail", { number: frame });
    state.detailRequest = req.id;
    let exactShown = false;
    el.treePlaceholder.textContent = `Loading packet ${frame}…`;
    el.treePlaceholder.classList.remove("hidden");
    const q = state.quickDetail;
    if (q.after > 0 && frame > q.after && frame > q.window) {
      const quick = rpc("packet_detail", { number: frame, mode: "quick", window: q.window });
      state.quickRequest = quick.id;
      quick.promise.then(
        (detail) => {
          if (state.selectedFrame === frame && !exactShown && !detail.unavailable) {
            showDetail(detail);
          }
        },
        () => {
          /* the exact detail still comes */
        },
      );
    }
    try {
      const detail = await req.promise;
      exactShown = true;
      if (state.quickRequest !== null) {
        cancelRpc(state.quickRequest);
        state.quickRequest = null;
      }
      if (state.selectedFrame !== frame) {
        return;
      }
      showDetail(detail);
    } catch (err) {
      const e = /** @type {any} */ (err);
      if (e?.code !== CANCELLED && state.selectedFrame === frame) {
        if (state.detail?.number === frame && state.detail.approximate) {
          // Keep the quick view, but say the exact one failed.
          showDetailNote(
            `${quickNote(state.detail)} The exact view failed: ${e?.message ?? e}`,
            false,
          );
        } else {
          el.tree.replaceChildren();
          el.treePlaceholder.textContent = `Could not dissect packet ${frame}: ${e?.message ?? e}`;
        }
      }
    } finally {
      if (state.detailRequest === req.id) {
        state.detailRequest = null;
      }
    }
  }

  /** @param {any} detail a quick (approximate) detail */
  function quickNote(detail) {
    const [first] = detail.window;
    return `Quick view: only packets ${first.toLocaleString()}–${detail.number.toLocaleString()} were dissected, so reassembly, TCP analysis and conversation details that depend on earlier packets can be missing.`;
  }

  /** @param {string} text @param {boolean} loading */
  function showDetailNote(text, loading) {
    el.detailNote.textContent = text;
    el.detailNote.classList.toggle("loading", loading);
    el.detailNote.classList.toggle("hidden", !text);
  }

  /**
   * Tell the host which packet is selected (for "Follow Stream" etc.).
   * Tracked separately from state.selectedFrame, which selectIndex sets early.
   * @param {number | null} frame
   */
  function reportSelection(frame) {
    if (frame !== reportedFrame) {
      reportedFrame = frame;
      postSelection();
    }
  }
  /** @type {number | null} */
  let reportedFrame = null;

  /** The focused frame plus, for a multi-selection, every selected frame (Export Selected…). */
  function postSelection() {
    const frames = state.selection.size ? [...state.selection] : undefined;
    vscode.postMessage(
      frames
        ? { type: "selection", frame: reportedFrame, frames }
        : { type: "selection", frame: reportedFrame },
    );
  }

  function clearDetail() {
    reportSelection(null);
    void showComment(null);
    state.detail = null;
    state.selectedNodeId = null;
    nodeIndex.clear();
    showDetailNote("", false);
    el.tree.replaceChildren();
    el.treePlaceholder.textContent = "Select a packet to see its details.";
    el.treePlaceholder.classList.remove("hidden");
    el.bytesView.replaceChildren();
    el.bytesTabs.replaceChildren();
    el.bytesTabs.classList.add("hidden");
    hex = null;
  }

  /**
   * @typedef {{node: any, path: any[], row: HTMLElement, children: HTMLElement | null, built: boolean}} NodeEntry
   * @type {Map<number, NodeEntry>}
   */
  const nodeIndex = new Map();

  /** @param {any} detail */
  function showDetail(detail) {
    const previous =
      state.selectedNodeId !== null ? nodeIndex.get(state.selectedNodeId) : undefined;
    const previousKey = previous ? lib.nodeKey(previous.path) : null;
    // The exact view replacing the quick one: keep the reader where they were.
    const sameFrame = state.detail?.number === detail.number;
    const scrollTop = el.detailPane.scrollTop;
    state.detail = detail;
    showDetailNote(
      detail.approximate ? `${quickNote(detail)} Loading the exact view` : "",
      !!detail.approximate,
    );
    state.selectedNodeId = null;
    nodeIndex.clear();
    el.treePlaceholder.classList.add("hidden");
    const frag = document.createDocumentFragment();
    for (const node of detail.tree) {
      frag.append(buildNode(node, [], 0));
    }
    el.tree.replaceChildren(frag);
    renderSourceTabs(detail.sources);
    hex = null;
    showSource(0);
    void loadFieldTypes(detail);
    // Keep the same field selected when moving between similar packets.
    if (previousKey) {
      for (const entry of nodeIndex.values()) {
        if (lib.nodeKey(entry.path) === previousKey) {
          selectNode(entry.node.id, { scroll: !sameFrame });
          break;
        }
      }
    }
    if (sameFrame) {
      el.detailPane.scrollTop = scrollTop;
    }
  }

  /**
   * @param {any} node @param {any[]} parentPath @param {number} depth
   * @returns {HTMLElement}
   */
  function buildNode(node, parentPath, depth) {
    const path = [...parentPath, node];
    const wrap = document.createElement("div");
    wrap.setAttribute("role", "treeitem");
    const row = document.createElement("div");
    row.className =
      "node-row" +
      (node.proto ? " proto" : "") +
      (node.name && node.name.startsWith("_ws.expert") ? " expert" : "");
    row.dataset.id = String(node.id);
    row.style.paddingLeft = `${depth * 14}px`;
    const twisty = document.createElement("span");
    twisty.className = "twisty";
    const label = document.createElement("span");
    label.className = "label";
    label.textContent = node.label;
    row.append(twisty, label);
    wrap.append(row);
    /** @type {NodeEntry} */
    const entry = { node, path, row, children: null, built: false };
    nodeIndex.set(node.id, entry);
    decorateFrameLink(entry);
    if (node.children && node.children.length) {
      const children = document.createElement("div");
      children.setAttribute("role", "group");
      entry.children = children;
      wrap.append(children);
      const open = state.expanded.has(lib.nodeKey(path));
      setExpanded(entry, open, false);
    }
    return wrap;
  }

  /** @param {NodeEntry} entry @param {boolean} open @param {boolean} [remember] */
  function setExpanded(entry, open, remember = true) {
    if (!entry.children) {
      return;
    }
    if (open && !entry.built) {
      const depth = entry.path.length;
      const frag = document.createDocumentFragment();
      for (const child of entry.node.children) {
        frag.append(buildNode(child, entry.path, depth));
      }
      entry.children.append(frag);
      entry.built = true;
    }
    entry.children.classList.toggle("hidden", !open);
    const twisty = /** @type {HTMLElement} */ (entry.row.firstChild);
    twisty.textContent = open ? "▾" : "▸";
    entry.row.setAttribute("aria-expanded", String(open));
    if (remember) {
      const key = lib.nodeKey(entry.path);
      if (open) {
        state.expanded.add(key);
      } else {
        state.expanded.delete(key);
      }
      persist();
    }
  }

  /** @param {NodeEntry} entry */
  function isExpanded(entry) {
    return !!entry.children && !entry.children.classList.contains("hidden");
  }

  el.tree.addEventListener("click", (e) => {
    const row = /** @type {HTMLElement | null} */ (
      /** @type {HTMLElement} */ (e.target).closest(".node-row")
    );
    if (!row) {
      return;
    }
    const entry = nodeIndex.get(Number(row.dataset.id));
    if (!entry) {
      return;
    }
    if (/** @type {HTMLElement} */ (e.target).classList.contains("twisty")) {
      setExpanded(entry, !isExpanded(entry));
    }
    selectNode(entry.node.id, { scroll: false });
    const target = frameLinkTarget(entry.node);
    if (target !== null && /** @type {HTMLElement} */ (e.target).classList.contains("label")) {
      void gotoFrame(target);
    }
  });

  el.tree.addEventListener("dblclick", (e) => {
    const row = /** @type {HTMLElement | null} */ (
      /** @type {HTMLElement} */ (e.target).closest(".node-row")
    );
    const entry = row && nodeIndex.get(Number(row.dataset.id));
    if (entry) {
      setExpanded(entry, !isExpanded(entry));
    }
  });

  el.tree.addEventListener("keydown", (e) => {
    const visible = [...el.tree.querySelectorAll(".node-row")].filter(
      (r) => /** @type {HTMLElement} */ (r).offsetParent !== null,
    );
    if (!visible.length) {
      return;
    }
    const current = state.selectedNodeId !== null ? nodeIndex.get(state.selectedNodeId) : undefined;
    const idx = current ? visible.indexOf(current.row) : -1;
    /** @param {number} i */
    const go = (i) => {
      const row = /** @type {HTMLElement} */ (
        visible[Math.max(0, Math.min(visible.length - 1, i))]
      );
      selectNode(Number(row.dataset.id), { scroll: true });
    };
    switch (e.key) {
      case "ArrowDown":
        go(idx + 1);
        break;
      case "ArrowUp":
        go(idx - 1);
        break;
      case "Home":
        go(0);
        break;
      case "End":
        go(visible.length - 1);
        break;
      case "ArrowRight":
        if (current && current.children && !isExpanded(current)) {
          setExpanded(current, true);
        } else {
          go(idx + 1);
        }
        break;
      case "ArrowLeft":
        if (current && isExpanded(current)) {
          setExpanded(current, false);
        } else if (current && current.path.length > 1) {
          selectNode(current.path[current.path.length - 2].id, { scroll: true });
        } else {
          el.viewport.focus();
        }
        break;
      case "Enter": {
        const target = current ? frameLinkTarget(current.node) : null;
        if (target !== null) {
          void gotoFrame(target); // frame reference: follow it
        } else if (current) {
          setExpanded(current, !isExpanded(current));
        }
        break;
      }
      case " ":
        if (current) {
          setExpanded(current, !isExpanded(current));
        }
        break;
      default:
        return;
    }
    e.preventDefault();
  });

  /** @param {number} id @param {{scroll: boolean}} opts */
  function selectNode(id, opts) {
    const entry = nodeIndex.get(id);
    if (!entry) {
      return;
    }
    if (state.selectedNodeId !== null) {
      nodeIndex.get(state.selectedNodeId)?.row.classList.remove("selected");
    }
    state.selectedNodeId = id;
    entry.row.classList.add("selected");
    if (opts.scroll) {
      entry.row.scrollIntoView({ block: "nearest" });
    }
    highlightBytes(entry);
  }

  /** Expand ancestors so a node deep in the tree becomes visible, then select it. @param {any[]} path */
  function revealPath(path) {
    for (let i = 0; i < path.length - 1; i++) {
      const entry = nodeIndex.get(path[i].id);
      if (entry && !isExpanded(entry)) {
        setExpanded(entry, true);
      }
    }
    selectNode(path[path.length - 1].id, { scroll: true });
  }

  // ------------------------------------------------------------------ hex view

  /** @type {{src: number, bytes: HTMLElement[], ascii: HTMLElement[], marked: number[]} | null} */
  let hex = null;

  /** @param {{name: string, hex: string}[]} sources */
  function renderSourceTabs(sources) {
    el.bytesTabs.replaceChildren();
    el.bytesTabs.classList.toggle("hidden", sources.length < 2);
    if (sources.length < 2) {
      return;
    }
    sources.forEach((s, i) => {
      const b = document.createElement("button");
      b.type = "button";
      b.setAttribute("role", "tab");
      b.textContent = `${s.name} (${s.hex.length / 2})`;
      b.addEventListener("click", () => showSource(i));
      el.bytesTabs.append(b);
    });
  }

  /** @param {number} src */
  function showSource(src) {
    const detail = state.detail;
    if (!detail || !detail.sources[src]) {
      el.bytesView.replaceChildren();
      hex = null;
      return;
    }
    if (hex && hex.src === src) {
      return;
    }
    state.activeSource = src;
    [...el.bytesTabs.children].forEach((b, i) => b.classList.toggle("active", i === src));
    const data = lib.hexToBytes(detail.sources[src].hex);
    /** @type {HTMLElement[]} */
    const byteEls = [];
    /** @type {HTMLElement[]} */
    const asciiEls = [];
    const frag = document.createDocumentFragment();
    for (let off = 0; off < data.length; off += 16) {
      const row = document.createElement("div");
      row.className = "hex-row";
      const offEl = document.createElement("span");
      offEl.className = "off";
      offEl.textContent = lib.formatOffset(off, data.length);
      row.append(offEl);
      const ascii = document.createElement("span");
      ascii.className = "ascii";
      for (let i = off; i < Math.min(off + 16, data.length); i++) {
        const b = document.createElement("span");
        b.className = "b" + (i - off === 7 ? " gap" : "");
        b.dataset.i = String(i);
        b.textContent = data[i].toString(16).padStart(2, "0");
        row.append(b);
        byteEls.push(b);
        const a = document.createElement("span");
        a.className = "a";
        a.dataset.i = String(i);
        a.textContent = lib.asciiChar(data[i]);
        ascii.append(a);
        asciiEls.push(a);
      }
      // Pad short final rows so the ASCII column lines up.
      for (let i = data.length; i < off + 16; i++) {
        const pad = document.createElement("span");
        pad.className = "b" + (i - off === 7 ? " gap" : "");
        pad.textContent = "  ";
        row.append(pad);
      }
      row.append(ascii);
      frag.append(row);
    }
    el.bytesView.replaceChildren(frag);
    hex = { src, bytes: byteEls, ascii: asciiEls, marked: [] };
    if (state.selectedNodeId !== null) {
      const entry = nodeIndex.get(state.selectedNodeId);
      if (entry) {
        highlightBytes(entry, false);
      }
    }
  }

  /** @param {NodeEntry} entry @param {boolean} [switchSource] follow the field to its byte source */
  function highlightBytes(entry, switchSource = true) {
    const node = entry.node;
    if (switchSource && node.pos !== undefined && hex && node.src !== hex.src) {
      showSource(node.src); // re-renders, then highlights the selected node
      return;
    }
    if (!hex) {
      return;
    }
    for (const i of hex.marked) {
      hex.bytes[i]?.classList.remove("hl", "proto");
      hex.ascii[i]?.classList.remove("hl", "proto");
    }
    hex.marked = [];
    /** @param {any} n @param {string} cls */
    const mark = (n, cls) => {
      if (!hex || n.pos === undefined || n.src !== hex.src) {
        return;
      }
      const end = Math.min(n.pos + n.size, hex.bytes.length);
      for (let i = n.pos; i < end; i++) {
        hex.bytes[i].classList.add(cls);
        hex.ascii[i].classList.add(cls);
        hex.marked.push(i);
      }
    };
    // Lightly mark the enclosing protocol, strongly mark the field itself.
    if (entry.path.length > 1) {
      mark(entry.path[0], "proto");
    }
    mark(node, "hl");
    if (node.pos !== undefined && node.src === hex.src) {
      hex.bytes[Math.min(node.pos, hex.bytes.length - 1)]?.scrollIntoView({ block: "nearest" });
    }
  }

  el.bytesView.addEventListener("click", (e) => {
    const t = /** @type {HTMLElement} */ (e.target);
    if (t.dataset.i === undefined || !state.detail) {
      return;
    }
    const path = lib.findNodeForByte(state.detail.tree, state.activeSource, Number(t.dataset.i));
    if (path) {
      revealPath(path);
    }
  });

  // ------------------------------------------------------------------ context menu

  // Packet list: follow the selected packet's stream.
  el.rows.addEventListener("contextmenu", (e) => {
    const rowEl = /** @type {HTMLElement | null} */ (
      /** @type {HTMLElement} */ (e.target).closest(".list-row")
    );
    if (!rowEl || rowEl.dataset.index === undefined) {
      return;
    }
    e.preventDefault();
    const index = Number(rowEl.dataset.index);
    const row = rowAt(index);
    if (row && state.selection.has(row.number)) {
      focusIndex(index); // right-click inside a multi-selection keeps it
    } else {
      selectIndex(index);
    }
    if (!row) {
      return;
    }
    const multi = state.selection.size;
    const protocol = (row.cells[4] || "").toUpperCase();
    /** @param {"tcp" | "udp" | "tls" | "http"} proto */
    const follow = (proto) => () =>
      vscode.postMessage({ type: "follow", proto, frame: row.number });
    // The clicked cell: Apply as Filter on its value (validated when applied).
    const cellEl = /** @type {HTMLElement | null} */ (
      /** @type {HTMLElement} */ (e.target).closest(".list-row > div")
    );
    const vis = cellEl ? visibleColumns()[[...rowEl.children].indexOf(cellEl)] : undefined;
    // (A resolved name filters on its address.)
    const cellValue = vis ? (lib.cellAddress(vis.column, row) ?? row.cells[vis.index] ?? "") : "";
    const filter = vis ? lib.cellFilter(vis.column, cellValue) : null;
    const current = state.appliedFilter;
    /** @type {[string, (() => void) | null][]} */
    const items = [
      [
        "Apply as Filter",
        filter ? () => applyFromTree(lib.combineFilter(current, filter, "replace"), true) : null,
      ],
      ["Prepare as Filter", filter ? () => applyFromTree(filter, false) : null],
      [
        "…and Selected",
        filter && current
          ? () => applyFromTree(lib.combineFilter(current, filter, "and"), true)
          : null,
      ],
      [
        "…or Selected",
        filter && current
          ? () => applyFromTree(lib.combineFilter(current, filter, "or"), true)
          : null,
      ],
      [
        "…and not Selected",
        filter ? () => applyFromTree(lib.combineFilter(current, filter, "not"), true) : null,
      ],
      ["-", null],
      ["Follow TCP Stream", follow("tcp")],
      ["Follow UDP Stream", follow("udp")],
      ["Follow TLS Stream", /TLS|SSL/.test(protocol) ? follow("tls") : null],
      ["Follow HTTP Stream", /HTTP/.test(protocol) ? follow("http") : null],
      ["TCP Stream Graph", () => vscode.postMessage({ type: "tcpGraph", frame: row.number })],
      ["-", null],
      // Sends packet data: the host asks for consent first (pcapViewer.ai.allowPacketData).
      ...(state.ai.available
        ? /** @type {[string, (() => void) | null][]} */ ([
            [
              multi
                ? `Ask Copilot About ${multi.toLocaleString()} Selected Packets…`
                : "Ask Copilot About This Packet…",
              () =>
                vscode.postMessage({
                  type: "askAboutPackets",
                  frames: selectedFrames().sort((a, b) => a - b),
                }),
            ],
            ["-", null],
          ])
        : []),
      ["Decode As…", () => vscode.postMessage({ type: "decodeAs", frame: row.number })],
      [
        "Export Packet Bytes…",
        () => vscode.postMessage({ type: "exportBytes", frame: row.number }),
      ],
      ["-", null],
      [
        multi
          ? `Mark/Unmark ${multi.toLocaleString()} Selected Packets`
          : row.marked
            ? "Unmark Packet"
            : "Mark Packet",
        () => void toggleMark(),
      ],
      [
        state.timeRef === row.number ? "Unset Time Reference" : "Set Time Reference",
        () => toggleTimeReference(),
      ],
      [row.comment ? "Edit Packet Comment…" : "Add Packet Comment…", () => editComment()],
      ["Delete Packet Comment", row.comment ? () => deleteComment(row.number) : null],
      ["Select All", () => void selectAll()],
      ["-", null],
      ["Copy Value", cellValue ? () => copy(cellValue) : null],
      ...(multi
        ? /** @type {[string, (() => void) | null][]} */ ([
            [`Copy ${multi.toLocaleString()} Rows`, () => void copyRows()],
            [`Copy ${multi.toLocaleString()} Frame Numbers`, () => void copyFrameNumbers()],
            [
              `Export ${multi.toLocaleString()} Selected Packets…`,
              () => vscode.postMessage({ type: "exportSelected" }),
            ],
          ])
        : /** @type {[string, (() => void) | null][]} */ ([
            ["Copy Summary", () => copy(row.cells.join("\t"))],
            ["Copy Frame Number", () => copy(String(row.number))],
          ])),
    ];
    showMenu(e.clientX, e.clientY, items);
  });

  el.tree.addEventListener("contextmenu", (e) => {
    const row = /** @type {HTMLElement | null} */ (
      /** @type {HTMLElement} */ (e.target).closest(".node-row")
    );
    const entry = row && nodeIndex.get(Number(row.dataset.id));
    if (!entry) {
      return;
    }
    e.preventDefault();
    selectNode(entry.node.id, { scroll: false });
    const node = entry.node;
    const filter = lib.buildFieldFilter(node);
    const current = state.appliedFilter;
    /** @type {[string, (() => void) | null][]} */
    const items = [
      [
        "Apply as Filter",
        filter ? () => applyFromTree(lib.combineFilter(current, filter, "replace"), true) : null,
      ],
      ["Prepare as Filter", filter ? () => applyFromTree(filter, false) : null],
      [
        "…and Selected",
        filter && current
          ? () => applyFromTree(lib.combineFilter(current, filter, "and"), true)
          : null,
      ],
      [
        "…or Selected",
        filter && current
          ? () => applyFromTree(lib.combineFilter(current, filter, "or"), true)
          : null,
      ],
      [
        "…and not Selected",
        filter ? () => applyFromTree(lib.combineFilter(current, filter, "not"), true) : null,
      ],
      [
        "Colorize with Filter…",
        filter ? () => vscode.postMessage({ type: "colorize", filter }) : null,
      ],
      ["Apply as Column", canBeColumn(node) ? () => applyColumn(node) : null],
      ...(frameLinkTarget(node) !== null
        ? /** @type {[string, (() => void) | null][]} */ ([
            [
              `Go to Packet ${frameLinkTarget(node)}`,
              () => void gotoFrame(/** @type {number} */ (frameLinkTarget(node))),
            ],
          ])
        : []),
      ["-", null],
      ["Copy Value", node.show !== undefined ? () => copy(node.show) : null],
      ["Copy Line", () => copy(node.label)],
      ["Copy Field Name", node.name ? () => copy(node.name) : null],
      ["Copy as Filter", filter ? () => copy(filter) : null],
      ["Copy Bytes (hex)", node.pos !== undefined ? () => copy(fieldBytes(node)) : null],
      ["-", null],
      ["Expand Subtrees", entry.children ? () => expandAll(entry, true) : null],
      ["Collapse Subtrees", entry.children ? () => expandAll(entry, false) : null],
    ];
    showMenu(e.clientX, e.clientY, items);
  });

  /** @param {any} node */
  function fieldBytes(node) {
    const src = state.detail?.sources[node.src];
    return src ? src.hex.slice(node.pos * 2, (node.pos + node.size) * 2) : "";
  }

  /** @param {NodeEntry} entry @param {boolean} open */
  function expandAll(entry, open) {
    setExpanded(entry, open);
    if (entry.built) {
      for (const child of entry.node.children) {
        const c = nodeIndex.get(child.id);
        if (c && c.children) {
          expandAll(c, open);
        }
      }
    }
  }

  /** @param {string} expr @param {boolean} apply */
  function applyFromTree(expr, apply) {
    el.filterInput.value = expr;
    if (apply) {
      void applyFilter(expr);
    } else {
      el.filterInput.focus();
      validateSoon();
    }
  }

  /** @param {string} text */
  function copy(text) {
    vscode.postMessage({ type: "copy", text });
  }

  /** @param {number} x @param {number} y @param {[string, (() => void) | null][]} items */
  function showMenu(x, y, items) {
    el.menu.replaceChildren(
      ...items.map(([label, action]) => {
        const item = document.createElement("div");
        if (label === "-") {
          item.className = "sep";
          return item;
        }
        item.className = "item" + (action ? "" : " disabled");
        item.setAttribute("role", "menuitem");
        item.tabIndex = -1;
        item.textContent = label;
        if (action) {
          item.addEventListener("click", () => {
            hideMenu();
            action();
          });
        }
        return item;
      }),
    );
    el.menu.classList.remove("hidden");
    const rect = el.menu.getBoundingClientRect();
    el.menu.style.left = `${Math.min(x, window.innerWidth - rect.width - 4)}px`;
    el.menu.style.top = `${Math.min(y, window.innerHeight - rect.height - 4)}px`;
  }

  function hideMenu() {
    el.menu.classList.add("hidden");
  }

  window.addEventListener("mousedown", (e) => {
    if (!el.menu.contains(/** @type {Node} */ (e.target))) {
      hideMenu();
    }
  });
  window.addEventListener("keydown", (e) => {
    if (e.key === "Escape") {
      hideMenu();
    }
  });
  window.addEventListener("blur", hideMenu);

  // ------------------------------------------------------------------ commands menu (☰)

  /**
   * Every PCAP Viewer command, grouped under foldable headings, filtered as
   * you type (lib.groupCommands/filterCommands/commandMenuRows). Groups start
   * folded and the open ones are remembered (`state.menuGroups`); typing
   * shows every match with its heading as a label. Focus stays in the filter
   * box: ↑/↓, Home/End move the active entry (aria-activedescendant), Enter
   * runs it or toggles a heading, → opens a heading, ← goes back to it and
   * folds it, Esc or Tab closes. Entries that can't run now stay listed but
   * disabled, with the reason as their tooltip and in the hint line.
   */
  const commandsMenu = (() => {
    const root = document.createElement("div");
    root.id = "commands-menu";
    root.className = "context-menu command-menu hidden";
    const filter = document.createElement("input");
    filter.id = "commands-filter";
    filter.type = "text";
    filter.spellcheck = false;
    filter.autocomplete = "off";
    filter.placeholder = "Filter commands";
    filter.setAttribute("aria-label", "Filter commands");
    filter.setAttribute("aria-controls", "commands-list");
    const list = document.createElement("div");
    list.id = "commands-list";
    list.setAttribute("role", "menu");
    list.setAttribute("aria-label", "PCAP commands");
    const hint = document.createElement("div");
    hint.className = "command-hint hidden";
    hint.setAttribute("aria-live", "polite");
    root.append(filter, list, hint);
    document.body.append(root);
    return { root, filter, list, hint };
  })();
  const isMac = /Mac|iPhone|iPad/i.test(window.navigator.platform || window.navigator.userAgent);
  /** @type {{items: {group: string, command: any, node: HTMLElement, reason: string | null}[], active: number}} */
  const menuView = { items: [], active: -1 };

  function commandContext() {
    return {
      selected: state.selectedFrame !== null,
      marks: state.markCount,
      filter: !!state.appliedFilter,
      capturing: !!state.capture?.running,
      ai: state.ai.available,
    };
  }

  function menuSearching() {
    return commandsMenu.filter.value.trim() !== "";
  }

  /**
   * @param {{group?: string, id?: string}} [keep] the entry to keep active
   * (a heading by group, a command by id); else the first enabled one.
   */
  function renderCommandsMenu(keep) {
    const ctx = commandContext();
    const shown = lib.filterCommands(state.commands, commandsMenu.filter.value);
    const rows = lib.commandMenuRows(lib.groupCommands(shown), state.menuGroups, menuSearching());
    menuView.items = [];
    /** @type {HTMLElement[]} */
    const groups = [];
    /** @type {HTMLElement | null} */
    let group = null;
    for (const row of rows) {
      const index = menuView.items.length;
      if (row.kind === "group") {
        group = document.createElement("div");
        group.setAttribute("role", "group");
        group.setAttribute("aria-label", row.group);
        groups.push(group);
        const heading = document.createElement("div");
        heading.className = "heading";
        if (!row.foldable) {
          heading.setAttribute("aria-hidden", "true"); // (a label over search results)
          heading.textContent = row.group;
          group.append(heading);
          continue;
        }
        heading.classList.add("item");
        heading.id = `command-item-${index}`;
        heading.setAttribute("role", "menuitem");
        heading.setAttribute("aria-expanded", String(row.open));
        heading.dataset.group = row.group;
        const chevron = document.createElement("span");
        chevron.className = "chevron";
        chevron.setAttribute("aria-hidden", "true");
        chevron.textContent = row.open ? "▾" : "▸";
        const title = document.createElement("span");
        title.className = "title";
        title.textContent = row.group;
        const count = document.createElement("span");
        count.className = "keys count";
        count.textContent = String(row.count);
        heading.append(chevron, title, count);
        heading.addEventListener("mousemove", () => setActiveCommand(index));
        heading.addEventListener("mousedown", (e) => e.preventDefault()); // (keep focus in the box)
        heading.addEventListener("click", () => toggleMenuGroup(row.group));
        group.append(heading);
        menuView.items.push({ group: row.group, command: null, node: heading, reason: null });
        continue;
      }
      const command = row.command;
      const reason = lib.commandUnavailable(command, ctx);
      const node = document.createElement("div");
      node.id = `command-item-${index}`;
      node.className = "item";
      node.setAttribute("role", "menuitem");
      node.dataset.id = command.id;
      const title = document.createElement("span");
      title.className = "title";
      title.textContent = command.title;
      const keys = document.createElement("span");
      keys.className = "keys";
      keys.textContent = lib.formatKeybinding(command.keys, isMac);
      node.append(title, keys);
      if (reason) {
        node.setAttribute("aria-disabled", "true");
        node.title = reason;
      }
      node.addEventListener("mousemove", () => setActiveCommand(index));
      node.addEventListener("mousedown", (e) => e.preventDefault()); // (keep focus in the box)
      node.addEventListener("click", () => runMenuEntry(index));
      group?.append(node);
      menuView.items.push({ group: row.group, command, node, reason });
    }
    commandsMenu.list.replaceChildren(...groups);
    const kept = menuView.items.findIndex((i) =>
      keep?.id ? i.command?.id === keep.id : !i.command && i.group === keep?.group,
    );
    const first = menuView.items.findIndex((i) => !i.reason);
    setActiveCommand(kept >= 0 ? kept : menuView.items.length ? Math.max(0, first) : -1);
  }

  /** Open or fold a heading (it stays the active entry). @param {string} group */
  function toggleMenuGroup(group) {
    if (state.menuGroups.has(group)) {
      state.menuGroups.delete(group);
    } else {
      state.menuGroups.add(group);
    }
    persist();
    renderCommandsMenu({ group });
  }

  /** @param {number} index */
  function setActiveCommand(index) {
    menuView.items[menuView.active]?.node.classList.remove("active");
    menuView.active = index;
    const item = menuView.items[index];
    if (item) {
      item.node.classList.add("active");
      item.node.scrollIntoView({ block: "nearest" });
      commandsMenu.filter.setAttribute("aria-activedescendant", item.node.id);
    } else {
      commandsMenu.filter.removeAttribute("aria-activedescendant");
    }
    const text = !menuView.items.length
      ? "No matching commands"
      : item?.reason
        ? `${item.command.title}: ${item.reason}`
        : "";
    commandsMenu.hint.textContent = text;
    commandsMenu.hint.classList.toggle("hidden", !text);
  }

  function commandsMenuOpen() {
    return !commandsMenu.root.classList.contains("hidden");
  }

  function openCommandsMenu() {
    hideMenu();
    commandsMenu.filter.value = "";
    commandsMenu.root.classList.remove("hidden");
    el.filterMenu.setAttribute("aria-expanded", "true");
    renderCommandsMenu();
    // Below the button, its right edge on the button's, inside the window.
    const button = el.filterMenu.getBoundingClientRect();
    const menu = commandsMenu.root.getBoundingClientRect();
    const left = Math.max(
      4,
      Math.min(button.right - menu.width, window.innerWidth - menu.width - 4),
    );
    commandsMenu.root.style.left = `${left}px`;
    commandsMenu.root.style.top = `${button.bottom + 2}px`;
    commandsMenu.root.style.maxHeight = `${Math.max(120, window.innerHeight - button.bottom - 8)}px`;
    commandsMenu.filter.focus();
  }

  /** @param {boolean} [refocus] give the focus back to the ☰ button */
  function closeCommandsMenu(refocus = false) {
    if (!commandsMenuOpen()) {
      return;
    }
    commandsMenu.root.classList.add("hidden");
    el.filterMenu.setAttribute("aria-expanded", "false");
    if (refocus) {
      el.filterMenu.focus();
    }
  }

  /** Run an enabled entry on this capture (the host checks the id against its list). @param {number} index */
  function runMenuEntry(index) {
    const item = menuView.items[index];
    if (!item) {
      return;
    }
    if (!item.command) {
      toggleMenuGroup(item.group);
      return;
    }
    if (item.reason) {
      setActiveCommand(index); // (shows why in the hint line)
      return;
    }
    closeCommandsMenu(true);
    vscode.postMessage({ type: "runCommand", id: item.command.id });
  }

  /** @param {number} from @param {number} step */
  function moveActiveCommand(from, step) {
    const n = menuView.items.length;
    if (n) {
      setActiveCommand((((from + step) % n) + n) % n);
    }
  }

  el.filterMenu.addEventListener("click", () =>
    commandsMenuOpen() ? closeCommandsMenu(true) : openCommandsMenu(),
  );
  el.filterMenu.addEventListener("keydown", (e) => {
    if (e.key === "ArrowDown" && !commandsMenuOpen()) {
      e.preventDefault();
      openCommandsMenu();
    }
  });
  commandsMenu.filter.addEventListener("input", () => renderCommandsMenu());
  commandsMenu.filter.addEventListener("keydown", (e) => {
    switch (e.key) {
      case "ArrowDown":
        moveActiveCommand(menuView.active, 1);
        break;
      case "ArrowUp":
        moveActiveCommand(menuView.active < 0 ? 0 : menuView.active, -1);
        break;
      case "Home":
        setActiveCommand(menuView.items.length ? 0 : -1);
        break;
      case "End":
        setActiveCommand(menuView.items.length - 1);
        break;
      case "Enter":
        runMenuEntry(menuView.active);
        break;
      case "ArrowRight":
      case "ArrowLeft": {
        const item = menuView.items[menuView.active];
        if (menuSearching() || !item) {
          e.stopPropagation(); // (the caret moves in the typed text)
          return;
        }
        const heading = menuView.items.findIndex((i) => !i.command && i.group === item.group);
        const open = state.menuGroups.has(item.group);
        if (e.key === "ArrowRight") {
          if (item.command) {
            break;
          }
          if (open) {
            moveActiveCommand(menuView.active, 1); // (into the group)
          } else {
            toggleMenuGroup(item.group);
          }
        } else if (item.command) {
          setActiveCommand(heading);
        } else if (open) {
          toggleMenuGroup(item.group);
        }
        break;
      }
      case "Escape":
      case "Tab":
        closeCommandsMenu(true);
        break;
      default:
        e.stopPropagation(); // (typing filters; the viewer's own keys stay out of it)
        return;
    }
    e.preventDefault();
    e.stopPropagation();
  });
  window.addEventListener("mousedown", (e) => {
    const t = /** @type {Node} */ (e.target);
    if (commandsMenuOpen() && !commandsMenu.root.contains(t) && !el.filterMenu.contains(t)) {
      closeCommandsMenu();
    }
  });
  window.addEventListener("blur", () => closeCommandsMenu());

  // ------------------------------------------------------------------ filter bar

  /** @param {string} message @param {boolean} [info] */
  function showFilterError(message, info = false) {
    el.filterError.textContent = message;
    el.filterError.classList.toggle("hidden", !message);
    el.filterError.dataset.info = info ? "1" : "";
  }

  let validateTimer = 0;
  function validateSoon() {
    window.clearTimeout(validateTimer);
    validateTimer = window.setTimeout(validateNow, 250);
  }

  async function validateNow() {
    if (state.ai.asking) {
      return; // the input holds a description, not a filter
    }
    const expr = el.filterInput.value.trim();
    const seq = ++state.validateSeq;
    if (!expr) {
      el.filterInput.classList.remove("valid", "invalid");
      showFilterError("");
      return;
    }
    if (!state.ready) {
      return;
    }
    try {
      const res = await rpc("validate_filter", { expr }).promise;
      if (seq !== state.validateSeq || state.ai.asking) {
        return;
      }
      el.filterInput.classList.toggle("valid", res.valid);
      el.filterInput.classList.toggle("invalid", !res.valid);
      el.filterInput.title = res.valid ? "" : res.error;
      if (!res.valid) {
        showFilterError(res.error);
      } else if (el.filterError.dataset.info !== "1") {
        showFilterError(""); // a valid filter clears a validation error, not a notice
      }
    } catch {
      /* validation is best-effort */
    }
  }

  /** @param {string} raw */
  async function applyFilter(raw) {
    const expr = raw.trim();
    if (!state.ready) {
      return;
    }
    if (state.filterRequest !== null) {
      cancelRpc(state.filterRequest);
    }
    // Applying validates too: drop the typing's pending validation, which would
    // otherwise land later and clear whatever the message area shows by then.
    window.clearTimeout(validateTimer);
    state.validateSeq++;
    showFilterError("");
    // Streaming: the first matches come back at once, the rest as "filter" events.
    const req = rpc("set_filter", { expr, stream: true });
    state.filterRequest = req.id;
    el.filterCancel.classList.remove("hidden");
    setBusy(req.id, true);
    try {
      const res = await req.promise;
      if (state.filterRequest !== req.id) {
        return; // a newer filter was applied meanwhile: its reply decides
      }
      state.appliedFilter = res.expr;
      state.filterId = res.filterId;
      state.total = res.matchCount;
      state.matchCount = res.matchCount;
      state.filtering = !!res.filtering;
      state.filterFraction = res.fraction ?? null;
      state.filterPartial = !!res.partial;
      setBusy(FILTER_BUSY, state.filtering, state.filterFraction);
      el.filterInput.classList.remove("invalid");
      el.filterInput.classList.toggle("valid", !!expr);
      vscode.postMessage({ type: "filterApplied", expr });
      resetView({ keepSelection: true });
      updateStatus();
      const early = state.earlyFilterEvents.get(res.filterId);
      state.earlyFilterEvents.clear();
      if (early) {
        onFilterEvent(early);
      }
    } catch (err) {
      const e = /** @type {any} */ (err);
      if (e?.code === CANCELLED) {
        return;
      }
      el.filterInput.classList.remove("valid");
      el.filterInput.classList.add("invalid");
      showFilterError(e?.code === INVALID_FILTER ? e.message : `Filter failed: ${e?.message ?? e}`);
    } finally {
      if (state.filterRequest === req.id) {
        state.filterRequest = null;
        el.filterCancel.classList.toggle("hidden", !state.filtering); // ■ now stops the filter
      }
    }
  }

  el.filterApply.addEventListener("click", () => {
    if (state.ai.asking) {
      askAi();
      return;
    }
    hideSuggest();
    void applyFilter(el.filterInput.value);
  });
  el.filterClear.addEventListener("click", () => {
    leaveAskMode(false);
    el.filterInput.value = "";
    el.filterInput.classList.remove("valid", "invalid");
    hideSuggest();
    void applyFilter("");
  });
  el.filterCancel.addEventListener("click", () => {
    if (state.filterRequest !== null) {
      cancelRpc(state.filterRequest);
    } else if (state.filtering) {
      void rpc("stop_filter", { filterId: state.filterId }).promise.catch(() => undefined);
    }
  });

  /** @param {string[]} history */
  function setHistory(history) {
    state.history = history || [];
  }

  // ------------------------------------------------------------------ autocomplete

  /**
   * One dropdown serves two modes:
   * - "complete": field/protocol/operator completions for the word at the cursor
   * - "saved": saved filters, recent filters and "Save current filter…"
   *
   * - "ai": validated suggestions from "✨ Ask AI" (picking one fills the filter bar)
   *
   * @typedef {{label: string, detail?: string, desc?: string, kind: "field" | "protocol" | "operator" | "saved" | "recent" | "action" | "ai", value: string}} SuggestItem
   */
  const suggest = {
    /** @type {SuggestItem[]} */ items: [],
    index: -1,
    /** @type {"complete" | "saved" | "ai" | null} */ mode: null,
    /** @type {{kind: string, prefix: string, start: number, end: number} | null} */ ctx: null,
    seq: 0,
    /** @type {number | null} */ request: null,
  };

  const MAX_SUGGESTIONS = 50;
  let suggestTimer = 0;

  /** @param {boolean} explicit shown on Ctrl+Space even with an empty prefix */
  function suggestSoon(explicit = false) {
    window.clearTimeout(suggestTimer);
    suggestTimer = window.setTimeout(() => void updateSuggestions(explicit), explicit ? 0 : 60);
  }

  /** @param {boolean} explicit */
  async function updateSuggestions(explicit) {
    const text = el.filterInput.value;
    const cursor = el.filterInput.selectionStart ?? text.length;
    if (!text.trim() && explicit) {
      showSavedMenu();
      return;
    }
    const ctx = lib.completionContext(text, cursor);
    const seq = ++suggest.seq;
    if (ctx.kind === "operator" || ctx.kind === "logical") {
      // Only offer operators right after a space (or when asked), not while typing a value.
      const typedSpace = ctx.prefix === "" && /\s$/.test(text.slice(0, cursor));
      if (!explicit && !typedSpace && ctx.prefix === "") {
        hideSuggest();
        return;
      }
      const items = lib.operatorSuggestions(ctx.kind, ctx.prefix).map((/** @type {any} */ o) => ({
        label: o.label,
        desc: o.desc,
        kind: "operator",
        value: o.label,
      }));
      renderSuggest(items, "complete", ctx);
      return;
    }
    if (ctx.kind !== "field" || (!ctx.prefix && !explicit)) {
      hideSuggest();
      return;
    }
    if (suggest.request !== null) {
      cancelRpc(suggest.request);
    }
    const req = rpc("field_index", { prefix: ctx.prefix, limit: MAX_SUGGESTIONS });
    suggest.request = req.id;
    try {
      const res = await req.promise;
      if (seq !== suggest.seq) {
        return;
      }
      /** @type {SuggestItem[]} */
      const items = [
        ...res.protocols.map((/** @type {any} */ p) => ({
          label: p.name,
          detail: "protocol",
          desc: p.desc,
          kind: "protocol",
          value: p.name,
        })),
        ...res.fields.map((/** @type {any} */ f) => ({
          label: f.name,
          detail: lib.friendlyType(f.type),
          desc: f.blurb ? `${f.desc} — ${f.blurb}` : f.desc,
          kind: "field",
          value: f.name,
        })),
      ];
      // An exact match first, then protocols before fields (both lists are sorted).
      items.sort(
        (a, b) =>
          Number(b.value.toLowerCase() === ctx.prefix.toLowerCase()) -
          Number(a.value.toLowerCase() === ctx.prefix.toLowerCase()),
      );
      if (items.length === 1 && items[0].value === ctx.prefix) {
        hideSuggest(); // already complete
        return;
      }
      renderSuggest(items.slice(0, MAX_SUGGESTIONS), "complete", ctx);
    } catch {
      /* suggestions are best-effort */
    } finally {
      if (suggest.request === req.id) {
        suggest.request = null;
      }
    }
  }

  function showSavedMenu() {
    // Supersede any pending or in-flight completion update.
    window.clearTimeout(suggestTimer);
    suggest.seq++;
    const current = el.filterInput.value.trim();
    /** @type {SuggestItem[]} */
    const items = [];
    if (current) {
      items.push({ label: "Save this filter…", desc: current, kind: "action", value: "save" });
    }
    for (const f of state.savedFilters) {
      items.push({
        label: f.name,
        detail: "saved",
        desc: f.filter,
        kind: "saved",
        value: f.filter,
      });
    }
    const savedValues = new Set(state.savedFilters.map((f) => f.filter));
    for (const h of state.history.slice(0, 15)) {
      if (!savedValues.has(h)) {
        items.push({ label: h, detail: "recent", kind: "recent", value: h });
      }
    }
    items.push({ label: "Manage saved filters…", kind: "action", value: "manage" });
    renderSuggest(items, "saved", null);
  }

  /**
   * @param {SuggestItem[]} items
   * @param {"complete" | "saved" | "ai"} mode
   * @param {any} ctx
   */
  function renderSuggest(items, mode, ctx) {
    if (!items.length) {
      hideSuggest();
      return;
    }
    suggest.items = items;
    suggest.mode = mode;
    suggest.ctx = ctx;
    // Nothing is preselected: Enter keeps meaning "apply the filter" unless the
    // user picked a suggestion with the arrow keys; Tab takes the first one.
    suggest.index = -1;
    el.suggest.replaceChildren(
      ...items.map((item, i) => {
        const row = document.createElement("div");
        row.className = `suggest-item kind-${item.kind}`;
        row.id = `suggest-${i}`;
        row.setAttribute("role", "option");
        row.dataset.index = String(i);
        const label = document.createElement("span");
        label.className = "suggest-label";
        label.textContent = item.label;
        row.append(label);
        if (item.detail) {
          const detail = document.createElement("span");
          detail.className = "suggest-detail";
          detail.textContent = item.detail;
          row.append(detail);
        }
        if (item.desc) {
          const desc = document.createElement("span");
          desc.className = "suggest-desc";
          desc.textContent = item.desc;
          row.title = item.desc;
          row.append(desc);
        }
        return row;
      }),
    );
    el.suggest.classList.remove("hidden");
    el.filterInput.setAttribute("aria-expanded", "true");
    highlightSuggestion();
  }

  function hideSuggest() {
    window.clearTimeout(suggestTimer);
    suggest.seq++;
    suggest.items = [];
    suggest.mode = null;
    suggest.index = -1;
    el.suggest.classList.add("hidden");
    el.suggest.replaceChildren();
    el.filterInput.setAttribute("aria-expanded", "false");
    el.filterInput.removeAttribute("aria-activedescendant");
  }

  function highlightSuggestion() {
    [...el.suggest.children].forEach((row, i) =>
      row.classList.toggle("active", i === suggest.index),
    );
    const active = suggest.index >= 0 ? el.suggest.children[suggest.index] : null;
    if (active) {
      active.scrollIntoView({ block: "nearest" });
      el.filterInput.setAttribute("aria-activedescendant", active.id);
    } else {
      el.filterInput.removeAttribute("aria-activedescendant");
    }
  }

  /** @param {number} index */
  function acceptSuggestion(index) {
    const item = suggest.items[index];
    const mode = suggest.mode;
    const ctx = suggest.ctx;
    hideSuggest();
    if (!item) {
      return;
    }
    if (item.kind === "action") {
      if (item.value === "save") {
        vscode.postMessage({ type: "saveFilter", expr: el.filterInput.value.trim() });
      } else {
        vscode.postMessage({ type: "manageSavedFilters" });
      }
      return;
    }
    if (mode === "saved") {
      el.filterInput.value = item.value;
      void applyFilter(item.value);
      return;
    }
    if (mode === "ai") {
      // Into the filter bar, not applied: Enter applies as usual.
      el.filterInput.value = item.value;
      el.filterInput.focus();
      el.filterInput.setSelectionRange(item.value.length, item.value.length);
      validateSoon();
      return;
    }
    const res = lib.applyCompletion(
      el.filterInput.value,
      ctx,
      item.value,
      item.kind === "operator",
    );
    el.filterInput.value = res.text;
    el.filterInput.focus();
    el.filterInput.setSelectionRange(res.cursor, res.cursor);
    validateSoon();
  }

  el.filterInput.addEventListener("input", () => {
    if (state.ai.asking) {
      return; // a description, not a filter: no validation or completions
    }
    validateSoon();
    suggestSoon(false);
  });
  el.filterInput.addEventListener("keydown", (e) => {
    if (state.ai.asking) {
      if (e.key === "Enter") {
        e.preventDefault();
        askAi();
      } else if (e.key === "Escape") {
        e.preventDefault();
        leaveAskMode(true);
        showFilterError("");
      }
      return;
    }
    const open = suggest.items.length > 0;
    if (e.key === " " && e.ctrlKey) {
      e.preventDefault();
      suggestSoon(true);
    } else if (open && (e.key === "ArrowDown" || e.key === "ArrowUp")) {
      e.preventDefault();
      const n = suggest.items.length;
      suggest.index = e.key === "ArrowDown" ? (suggest.index + 1) % n : (suggest.index - 1 + n) % n;
      highlightSuggestion();
    } else if (open && (e.key === "Tab" || (e.key === "Enter" && suggest.index >= 0))) {
      e.preventDefault();
      acceptSuggestion(Math.max(0, suggest.index));
    } else if (e.key === "Enter") {
      e.preventDefault();
      hideSuggest();
      void applyFilter(el.filterInput.value);
    } else if (e.key === "Escape") {
      if (open) {
        hideSuggest();
      } else {
        el.filterInput.value = state.appliedFilter;
        validateSoon();
      }
    } else if (e.key === "ArrowDown" && e.altKey) {
      el.viewport.focus();
    } else if (e.key === "ArrowDown" && !el.filterInput.value.trim()) {
      e.preventDefault();
      showSavedMenu();
    }
  });
  // Caret moves (click, Home/End) change the context; close stale completions.
  el.filterInput.addEventListener("click", () => {
    if (suggest.mode === "complete") {
      hideSuggest();
    }
  });
  el.filterInput.addEventListener("blur", () =>
    window.setTimeout(() => {
      if (document.activeElement !== el.filterInput && document.activeElement !== el.filterSaved) {
        hideSuggest();
      }
    }, 150),
  );
  // mousedown (not click) so the input keeps focus.
  el.suggest.addEventListener("mousedown", (e) => {
    e.preventDefault();
    const row = /** @type {HTMLElement | null} */ (
      /** @type {HTMLElement} */ (e.target).closest(".suggest-item")
    );
    if (row) {
      acceptSuggestion(Number(row.dataset.index));
    }
  });
  el.filterSaved.addEventListener("mousedown", (e) => e.preventDefault());
  el.filterSaved.addEventListener("click", () => {
    if (suggest.mode === "saved") {
      hideSuggest();
    } else {
      el.filterInput.focus();
      showSavedMenu();
    }
  });

  // ------------------------------------------------------------------ notices

  /**
   * An info line under the filter bar, optionally with one action button.
   * @param {string} message @param {{label: string, run: () => void}} [action]
   */
  function showNotice(message, action) {
    showFilterError(message, true);
    if (action) {
      const button = document.createElement("button");
      button.type = "button";
      button.className = "notice-action secondary";
      button.textContent = action.label;
      button.addEventListener("click", () => {
        showFilterError("");
        action.run();
      });
      el.filterError.append(button);
    }
  }

  // ------------------------------------------------------------------ navigation history

  const MAX_HISTORY = 100;

  /** Remember where a jump starts (Alt+Left comes back here). @param {number} [target] */
  function recordJump(target) {
    const from = state.selectedFrame;
    if (from !== null && from !== target) {
      state.nav.back.push(from);
      if (state.nav.back.length > MAX_HISTORY) {
        state.nav.back.shift();
      }
      state.nav.forward = [];
    }
  }

  /** Select a row found by the backend (find, marks, conversation, first/last). */
  function jumpToIndex(
    /** @type {number} */ index,
    /** @type {number | null} */ frame,
    /** @type {boolean} */ focusList,
  ) {
    recordJump(frame ?? undefined);
    selectIndex(index, true);
    if (focusList) {
      el.viewport.focus();
    }
  }

  /** @param {"back" | "forward"} which */
  async function goHistory(which) {
    const from = which === "back" ? state.nav.back : state.nav.forward;
    const to = which === "back" ? state.nav.forward : state.nav.back;
    const frame = from.pop();
    if (frame === undefined) {
      showNotice(
        which === "back" ? "No earlier packet to go back to." : "No later packet to go forward to.",
      );
      return;
    }
    if (state.selectedFrame !== null) {
      to.push(state.selectedFrame);
    }
    await gotoFrame(frame, { record: false });
  }

  // ------------------------------------------------------------------ frame links

  /** Frame number a detail-tree node links to (FT_FRAMENUM fields such as tcp.analysis.acks_frame). @param {any} node */
  function frameLinkTarget(node) {
    const type = node.name ? state.fieldTypes.get(node.name)?.type : undefined;
    if (type !== "FT_FRAMENUM") {
      return null;
    }
    const n = Number(node.show);
    return Number.isInteger(n) && n > 0 ? n : null;
  }

  /** @param {NodeEntry} entry */
  function decorateFrameLink(entry) {
    const target = frameLinkTarget(entry.node);
    if (target !== null && !entry.row.classList.contains("frame-link")) {
      entry.row.classList.add("frame-link");
      entry.row.title = `Go to packet ${target} (click or Enter; Alt+Left comes back)`;
    }
  }

  /** Look up the types of the packet's fields (once per name), then mark frame links. @param {any} detail */
  async function loadFieldTypes(detail) {
    /** @type {Set<string>} */
    const names = new Set();
    /** @param {any[]} nodes */
    const walk = (nodes) => {
      for (const n of nodes) {
        if (n.name && !state.fieldTypes.has(n.name)) {
          names.add(n.name);
        }
        if (n.children) {
          walk(n.children);
        }
      }
    };
    walk(detail.tree);
    if (names.size) {
      try {
        const res = await rpc("field_types", { names: [...names].slice(0, 2000) }).promise;
        for (const name of names) {
          state.fieldTypes.set(name, res.types[name] ?? { type: "", desc: "" });
        }
      } catch {
        return;
      }
    }
    if (state.detail === detail) {
      for (const entry of nodeIndex.values()) {
        decorateFrameLink(entry);
      }
    }
  }

  /** @param {any} node */
  function canBeColumn(node) {
    return (
      !!node.name &&
      !node.proto &&
      node.name !== "fake-field-wrapper" &&
      /^[A-Za-z0-9_][A-Za-z0-9_.-]*$/.test(node.name)
    );
  }

  /** "Apply as Column": the host adds it to pcapViewer.columns (capture's folder scope). @param {any} node */
  function applyColumn(node) {
    const desc = state.fieldTypes.get(node.name)?.desc;
    const title = desc || String(node.label).split(":")[0].trim() || node.name;
    vscode.postMessage({ type: "applyColumn", field: node.name, title });
  }

  // ------------------------------------------------------------------ find packet

  /** @type {Record<string, string>} */
  const FIND_PLACEHOLDERS = {
    filter: "Display filter, e.g. dns.flags.rcode != 0 (Enter: next, Shift+Enter: previous)",
    string: "Text in the packet bytes, e.g. index.html",
    hex: "Hex bytes, e.g. 47 45 54 or 47:45:54",
  };
  /** @type {number | null} */
  let findRequest = null;

  function openFind() {
    el.findBar.classList.remove("hidden");
    updateFindMode();
    el.findInput.focus();
    el.findInput.select();
  }

  function closeFind() {
    el.findBar.classList.add("hidden");
    setFindStatus("");
    el.viewport.focus();
  }

  function updateFindMode() {
    el.findInput.placeholder = FIND_PLACEHOLDERS[el.findMode.value] ?? "";
    el.findCaseLabel.classList.toggle("hidden", el.findMode.value !== "string");
    checkFindInput();
  }

  /** Immediate feedback for hex input (the backend validates everything again). */
  function checkFindInput() {
    const bad =
      el.findMode.value === "hex" &&
      el.findInput.value.trim() !== "" &&
      !lib.parseHexBytes(el.findInput.value);
    el.findInput.classList.toggle("invalid", bad);
    if (bad) {
      setFindStatus("Not hex bytes", true);
    } else if (el.findStatus.classList.contains("error")) {
      setFindStatus("");
    }
    return !bad;
  }

  /** @param {string} text @param {boolean} [error] */
  function setFindStatus(text, error = false) {
    el.findStatus.textContent = text;
    el.findStatus.title = text;
    el.findStatus.classList.toggle("error", error);
  }

  /** Next/previous match in the current view (filter and sort order), wrapping around. @param {"next" | "previous"} direction */
  async function find(direction) {
    if (!state.ready) {
      return;
    }
    if (el.findBar.classList.contains("hidden") || !el.findInput.value.trim()) {
      openFind();
      return;
    }
    if (!checkFindInput()) {
      return;
    }
    if (findRequest !== null) {
      cancelRpc(findRequest);
    }
    const req = rpc("find_packet", {
      mode: el.findMode.value,
      value: el.findInput.value,
      caseSensitive: el.findCase.checked,
      from: state.selectedFrame,
      direction,
      ...orderParams(),
    });
    findRequest = req.id;
    setFindStatus("Searching…");
    try {
      const res = await req.promise;
      if (res.filterId !== state.filterId) {
        return;
      }
      if (res.frame === null || res.frame === undefined) {
        setFindStatus("Not found", true);
        return;
      }
      setFindStatus(res.wrapped ? `Packet ${res.frame} (wrapped around)` : `Packet ${res.frame}`);
      jumpToIndex(res.index, res.frame, false);
    } catch (err) {
      const e = /** @type {any} */ (err);
      if (e?.code !== CANCELLED) {
        setFindStatus(String(e?.message ?? e), true);
      }
    } finally {
      if (findRequest === req.id) {
        findRequest = null;
      }
    }
  }

  el.findMode.addEventListener("change", () => {
    updateFindMode();
    el.findInput.focus();
  });
  el.findInput.addEventListener("input", checkFindInput);
  el.findInput.addEventListener("keydown", (e) => {
    if (e.key === "Enter") {
      e.preventDefault();
      void find(e.shiftKey ? "previous" : "next");
    } else if (e.key === "Escape") {
      e.preventDefault();
      closeFind();
    }
  });
  el.findNext.addEventListener("click", () => void find("next"));
  el.findPrev.addEventListener("click", () => void find("previous"));
  el.findClose.addEventListener("click", closeFind);

  // ------------------------------------------------------------------ packet navigation, marks, time reference

  /** @param {"next" | "previous"} direction */
  async function stepConversation(direction) {
    const frame = state.selectedFrame;
    if (frame === null) {
      showNotice("Select a packet first.");
      return;
    }
    try {
      const res = await rpc("neighbor_frame", { frame, direction, ...orderParams() }).promise;
      if (res.frame === null || res.frame === undefined) {
        showNotice(
          `No ${direction} packet in this conversation${state.appliedFilter ? " among the displayed packets" : ""}.`,
        );
        return;
      }
      jumpToIndex(res.index, res.frame, true);
    } catch (err) {
      showNotice(String(/** @type {any} */ (err)?.message ?? err));
    }
  }

  /** Patch cached rows instead of refetching. @param {number[]} marked @param {number[]} unmarked */
  function patchMarks(marked, unmarked) {
    const on = new Set(marked);
    const off = new Set(unmarked);
    for (const page of state.pages.values()) {
      for (const row of page) {
        if (on.has(row.number)) {
          row.marked = true;
        } else if (off.has(row.number)) {
          delete row.marked;
        }
      }
    }
  }

  /** The selected frames in view order, one per line. */
  async function copyFrameNumbers() {
    try {
      const res = await rpc("view_frames", { frames: selectedFrames(), ...orderParams() }).promise;
      copy(res.frames.join("\n"));
    } catch (err) {
      showNotice(String(/** @type {any} */ (err)?.message ?? err));
    }
  }

  function afterMarksChanged() {
    vscode.postMessage({ type: "marks", count: state.markCount });
    updateStatus();
    scheduleRender();
  }

  /** Ctrl+M: mark the selected packets, or unmark them if all of them are marked. */
  async function toggleMark() {
    const frames = selectedFrames();
    if (!frames.length) {
      showNotice("Select a packet to mark.");
      return;
    }
    try {
      const res = await rpc("mark_packets", { frames }).promise;
      patchMarks(res.marked, res.unmarked);
      state.markCount = res.count;
      afterMarksChanged();
    } catch (err) {
      showNotice(String(/** @type {any} */ (err)?.message ?? err));
    }
  }

  async function unmarkAll() {
    try {
      await rpc("unmark_all", {}).promise;
      for (const page of state.pages.values()) {
        for (const row of page) {
          delete row.marked;
        }
      }
      state.markCount = 0;
      afterMarksChanged();
    } catch (err) {
      showNotice(String(/** @type {any} */ (err)?.message ?? err));
    }
  }

  /** @param {"next" | "previous"} direction */
  async function stepMark(direction) {
    if (!state.markCount) {
      showNotice("No packets are marked. Mark packets with Ctrl+M.");
      return;
    }
    try {
      const res = await rpc("find_packet", {
        mode: "marked",
        from: state.selectedFrame,
        direction,
        ...orderParams(),
      }).promise;
      if (res.frame === null || res.frame === undefined) {
        showNotice("None of the marked packets is displayed with the current filter.");
        return;
      }
      jumpToIndex(res.index, res.frame, true);
    } catch (err) {
      showNotice(String(/** @type {any} */ (err)?.message ?? err));
    }
  }

  function toggleTimeReference() {
    const frame = state.selectedFrame;
    if (frame === null) {
      showNotice("Select a packet to use as the time reference.");
      return;
    }
    state.timeRef = state.timeRef === frame ? null : frame;
    updateStatus();
    refreshRows();
  }

  /** Viewer actions from the command palette, keybindings and menus. @param {string} command */
  function runCommand(command) {
    switch (command) {
      case "find":
        openFind();
        break;
      case "findNext":
        void find("next");
        break;
      case "findPrevious":
        void find("previous");
        break;
      case "goBack":
        void goHistory("back");
        break;
      case "goForward":
        void goHistory("forward");
        break;
      case "nextInConversation":
        void stepConversation("next");
        break;
      case "previousInConversation":
        void stepConversation("previous");
        break;
      case "firstPacket":
        if (state.total) {
          jumpToIndex(0, null, true);
        }
        break;
      case "lastPacket":
        if (state.total) {
          jumpToIndex(state.total - 1, null, true);
        }
        break;
      case "selectAll":
        void selectAll();
        break;
      case "toggleMark":
        void toggleMark();
        break;
      case "nextMark":
        void stepMark("next");
        break;
      case "previousMark":
        void stepMark("previous");
        break;
      case "unmarkAll":
        void unmarkAll();
        break;
      case "toggleTimeReference":
        toggleTimeReference();
        break;
      case "editPacketComment":
        editComment();
        break;
      case "deletePacketComment":
        if (state.selectedFrame !== null) {
          deleteComment(state.selectedFrame);
        }
        break;
    }
  }

  // Keys VS Code leaves to a focused webview are handled here. Keys it binds
  // globally (Ctrl+M, Ctrl+T, Ctrl+, …) are package.json keybindings that come
  // back as "command" messages, so nothing runs twice.
  document.addEventListener("keydown", (e) => {
    const mod = e.ctrlKey || e.metaKey;
    if (mod && !e.shiftKey && !e.altKey && e.key.toLowerCase() === "f") {
      e.preventDefault();
      openFind();
    } else if (e.key === "F3") {
      e.preventDefault();
      void find(e.shiftKey ? "previous" : "next");
    } else if (mod && (e.key === "Home" || e.key === "End")) {
      const t = /** @type {HTMLElement} */ (e.target);
      if (t.tagName !== "INPUT" && t.tagName !== "SELECT") {
        e.preventDefault();
        runCommand(e.key === "Home" ? "firstPacket" : "lastPacket");
      }
    }
  });

  el.statusTime.addEventListener("click", () => vscode.postMessage({ type: "pickTimeFormat" }));
  el.captureStop.addEventListener("click", () => vscode.postMessage({ type: "stopCapture" }));
  el.statusNames.addEventListener("click", () =>
    vscode.postMessage({ type: "pickNameResolution" }),
  );

  // ------------------------------------------------------------------ column header menu and drag

  /** @param {string} id */
  const isHidden = (id) => state.layout.hidden.includes(id);

  function saveLayout() {
    rebuildColumns();
    scheduleRender();
    vscode.postMessage({ type: "columnLayout", layout: state.layout });
  }

  /** @param {string} id @param {boolean} hidden */
  function setHidden(id, hidden) {
    const next = hidden
      ? [...new Set([...state.layout.hidden, id])]
      : state.layout.hidden.filter((h) => h !== id);
    if (columns().every((c) => next.includes(c.id))) {
      return; // keep at least one column
    }
    state.layout = { ...state.layout, hidden: next };
    saveLayout();
  }

  /** Width of the widest header/cell text currently rendered in the column. @param {string} id */
  function resizeToContents(id) {
    const pos = visibleColumns().findIndex((v) => v.column.id === id);
    if (pos < 0) {
      return;
    }
    const sample = /** @type {HTMLElement | null} */ (
      el.rows.firstElementChild?.children[pos] ?? el.header.children[pos] ?? null
    );
    const ctx = document.createElement("canvas").getContext("2d");
    if (!ctx || !sample) {
      return;
    }
    ctx.font = getComputedStyle(sample).font;
    let widest = ctx.measureText(visibleColumns()[pos].column.title).width + 16;
    for (const rowEl of el.rows.children) {
      widest = Math.max(widest, ctx.measureText(rowEl.children[pos]?.textContent ?? "").width);
    }
    state.widths[id] = Math.min(800, Math.max(40, Math.ceil(widest + 20)));
    applyColumnWidths();
    persist();
  }

  el.header.addEventListener("contextmenu", (e) => {
    const cell = /** @type {HTMLElement | null} */ (
      /** @type {HTMLElement} */ (e.target).closest("[data-id]")
    );
    const col = cell ? columns().find((c) => c.id === cell.dataset.id) : undefined;
    if (!col) {
      return;
    }
    e.preventDefault();
    const visible = visibleColumns().length;
    /** @type {[string, (() => void) | null][]} */
    const items = [
      [`Hide “${col.title}”`, visible > 1 ? () => setHidden(col.id, true) : null],
      ["Resize to Contents", col.id !== "info" ? () => resizeToContents(col.id) : null],
      ...(col.custom
        ? /** @type {[string, (() => void) | null][]} */ ([
            [
              "Rename Column…",
              () => vscode.postMessage({ type: "renameColumn", field: col.field }),
            ],
            ["Remove Column", () => vscode.postMessage({ type: "removeColumn", field: col.field })],
          ])
        : []),
      ["-", null],
      ...columns().map(
        (c) =>
          /** @type {[string, (() => void) | null]} */ ([
            `${isHidden(c.id) ? "   " : "✓ "}${c.title}`,
            !isHidden(c.id) && visible === 1 ? null : () => setHidden(c.id, !isHidden(c.id)),
          ]),
      ),
      ["-", null],
      [
        "Reset Column Widths",
        () => {
          state.widths = {};
          applyColumnWidths();
          persist();
        },
      ],
      [
        "Reset Column Order and Visibility",
        () => {
          state.layout = { order: [], hidden: [] };
          saveLayout();
        },
      ],
    ];
    showMenu(e.clientX, e.clientY, items);
  });

  /** @type {string | null} */
  let dragId = null;
  const clearDragMarks = () =>
    [...el.header.children].forEach((c) => c.classList.remove("drag-over"));
  el.header.addEventListener("dragstart", (e) => {
    const cell = /** @type {HTMLElement | null} */ (
      /** @type {HTMLElement} */ (e.target).closest?.("[data-id]") ?? null
    );
    if (!cell || resizing) {
      e.preventDefault();
      return;
    }
    dragId = cell.dataset.id ?? null;
    if (e.dataTransfer) {
      e.dataTransfer.effectAllowed = "move";
      e.dataTransfer.setData("text/plain", dragId ?? "");
    }
  });
  el.header.addEventListener("dragover", (e) => {
    const cell = /** @type {HTMLElement | null} */ (
      /** @type {HTMLElement} */ (e.target).closest("[data-id]")
    );
    if (!dragId || !cell) {
      return;
    }
    e.preventDefault();
    clearDragMarks();
    if (cell.dataset.id !== dragId) {
      cell.classList.add("drag-over");
    }
  });
  el.header.addEventListener("drop", (e) => {
    e.preventDefault();
    clearDragMarks();
    const cell = /** @type {HTMLElement | null} */ (
      /** @type {HTMLElement} */ (e.target).closest("[data-id]")
    );
    const moving = dragId;
    dragId = null;
    if (!moving || !cell || cell.dataset.id === moving) {
      return;
    }
    // Reorder over all columns (hidden ones keep their place), dropping in front of the target.
    const order = lib
      .layoutColumns(columns(), { order: state.layout.order })
      .map((/** @type {any} */ c) => c.column.id);
    state.layout = {
      ...state.layout,
      order: lib.moveColumn(order, moving, cell.dataset.id ?? null),
    };
    saveLayout();
  });
  el.header.addEventListener("dragend", () => {
    dragId = null;
    clearDragMarks();
  });

  // ------------------------------------------------------------------ bytes pane copy menu

  /** @type {[string, "hexdump" | "hex" | "c" | "escaped" | "base64" | "text"][]} */
  const BYTE_FORMATS = [
    ["Hex Dump", "hexdump"],
    ["Hex Stream", "hex"],
    ["C Array", "c"],
    ["Escaped String", "escaped"],
    ["Base64", "base64"],
    ["Printable Text", "text"],
  ];

  el.bytesView.addEventListener("contextmenu", (e) => {
    if (!state.detail || !hex) {
      return;
    }
    e.preventDefault();
    const all = lib.hexToBytes(state.detail.sources[hex.src].hex);
    const entry = state.selectedNodeId !== null ? nodeIndex.get(state.selectedNodeId) : undefined;
    const node = entry?.node;
    const field =
      node && node.pos !== undefined && node.src === hex.src
        ? { bytes: all.subarray(node.pos, node.pos + node.size), offset: node.pos }
        : null;
    /** @type {[string, (() => void) | null][]} */
    const items = [
      ...BYTE_FORMATS.map(
        ([label, kind]) =>
          /** @type {[string, (() => void) | null]} */ ([
            `Copy Bytes as ${label}`,
            () => copy(lib.formatBytesAs(all, kind)),
          ]),
      ),
      ["-", null],
      ...BYTE_FORMATS.map(
        ([label, kind]) =>
          /** @type {[string, (() => void) | null]} */ ([
            `Copy Field Bytes as ${label}`,
            field ? () => copy(lib.formatBytesAs(field.bytes, kind, field.offset)) : null,
          ]),
      ),
    ];
    showMenu(e.clientX, e.clientY, items);
  });

  // ------------------------------------------------------------------ AI filter help

  // "✨ Ask AI": the filter bar temporarily takes a description; the host asks
  // the language model, validates the answers with tshark and sends back only
  // valid filters, shown in the suggestion dropdown.
  const FILTER_PLACEHOLDER = el.filterInput.placeholder;
  const AI_PLACEHOLDER =
    "Describe the packets you want, e.g. DNS queries that got no answer (Enter to ask, Esc to cancel)";
  let aiSeq = 0;

  /** @param {boolean} available */
  function setAiAvailable(available) {
    state.ai.available = available;
    el.filterAi.classList.toggle("hidden", !available);
    if (!available && state.ai.asking) {
      leaveAskMode(true);
    }
  }

  function enterAskMode() {
    if (!state.ai.available || state.ai.asking) {
      return;
    }
    hideSuggest();
    // A validation still pending for the old filter text must not clear the AI messages.
    window.clearTimeout(validateTimer);
    state.validateSeq++;
    showFilterError("");
    state.ai.asking = true;
    state.ai.savedText = el.filterInput.value;
    state.ai.savedClasses = ["valid", "invalid"].filter((c) =>
      el.filterInput.classList.contains(c),
    );
    el.filterInput.classList.remove("valid", "invalid");
    el.filterInput.value = "";
    el.filterInput.placeholder = AI_PLACEHOLDER;
    el.filterField.classList.add("ai-mode");
    el.filterAi.setAttribute("aria-pressed", "true");
    el.filterInput.focus();
  }

  /** @param {boolean} restore put the filter text (and its validity) back */
  function leaveAskMode(restore) {
    if (!state.ai.asking) {
      return;
    }
    if (state.ai.request !== null) {
      vscode.postMessage({ type: "aiCancel", id: state.ai.request });
      state.ai.request = null;
    }
    state.ai.asking = false;
    el.filterField.classList.remove("ai-mode", "ai-busy");
    el.filterAi.setAttribute("aria-pressed", "false");
    el.filterInput.placeholder = FILTER_PLACEHOLDER;
    el.filterInput.readOnly = false;
    if (restore) {
      el.filterInput.value = state.ai.savedText;
      el.filterInput.classList.add(...state.ai.savedClasses);
    }
  }

  function askAi() {
    const request = el.filterInput.value.trim();
    if (!request || state.ai.request !== null) {
      return;
    }
    state.ai.request = ++aiSeq;
    el.filterField.classList.add("ai-busy");
    el.filterInput.readOnly = true;
    showFilterError("Asking the language model… (Esc to cancel)", true);
    vscode.postMessage({ type: "aiSuggest", id: state.ai.request, request });
  }

  /** @param {{id: number, suggestions: {filter: string, explanation: string}[], message?: string}} msg */
  function onAiSuggestions(msg) {
    if (msg.id !== state.ai.request) {
      return; // cancelled or superseded
    }
    state.ai.request = null;
    leaveAskMode(true);
    el.filterInput.focus();
    if (!msg.suggestions.length) {
      showFilterError(msg.message || "No display filter suggestions.", true);
      return;
    }
    showFilterError("");
    renderSuggest(
      msg.suggestions.map((s) => ({
        label: s.filter,
        detail: "AI",
        desc: s.explanation,
        kind: "ai",
        value: s.filter,
      })),
      "ai",
      null,
    );
  }

  el.filterAi.addEventListener("mousedown", (e) => e.preventDefault());
  el.filterAi.addEventListener("click", () => {
    if (state.ai.asking) {
      leaveAskMode(true);
      showFilterError("");
    } else {
      enterAskMode();
    }
  });

  // ------------------------------------------------------------------ splitters

  /**
   * @param {HTMLElement} handle
   * @param {"row" | "col"} axis
   */
  function makeSplitter(handle, axis) {
    handle.addEventListener("mousedown", (e) => {
      e.preventDefault();
      handle.classList.add("dragging");
      const container =
        axis === "row"
          ? /** @type {HTMLElement} */ ($("main"))
          : /** @type {HTMLElement} */ ($("bottom"));
      /** @param {MouseEvent} ev */
      const move = (ev) => {
        const rect = container.getBoundingClientRect();
        const ratio =
          axis === "row"
            ? (ev.clientY - rect.top) / rect.height
            : (ev.clientX - rect.left) / rect.width;
        const pct = `${Math.round(Math.max(0.1, Math.min(0.9, ratio)) * 1000) / 10}%`;
        document.documentElement.style.setProperty(
          axis === "row" ? "--list-height" : "--tree-width",
          pct,
        );
      };
      const up = () => {
        handle.classList.remove("dragging");
        window.removeEventListener("mousemove", move);
        window.removeEventListener("mouseup", up);
        persist();
      };
      window.addEventListener("mousemove", move);
      window.addEventListener("mouseup", up);
    });
  }
  makeSplitter(el.splitH, "row");
  makeSplitter(el.splitV, "col");

  // ------------------------------------------------------------------ status & state

  // ------------------------------------------------------------------ filter buttons

  /**
   * The filter-button bar: one button per `pcapViewer.filterButtons` entry
   * (click applies its filter; right-click, Shift+F10 or the context-menu key
   * asks the host to edit, move or remove it) and "+" to add the current
   * filter. Hidden while there are none (PCAP: Add Filter Button… adds the first).
   */
  function renderFilterButtons() {
    const bar = el.filterButtons;
    const buttons = state.filterButtons.map((b, index) => {
      const node = document.createElement("button");
      node.type = "button";
      node.className = "filter-button";
      node.textContent = b.label;
      node.title = lib.filterButtonTitle(b);
      node.dataset.index = String(index);
      node.addEventListener("click", () => {
        el.filterInput.value = b.filter;
        void applyFilter(b.filter);
      });
      const edit = () => vscode.postMessage({ type: "editFilterButton", index, filter: b.filter });
      // Shift+F10 and the menu key: Chromium turns them into "contextmenu" on
      // Windows and Linux but not on macOS, so they're handled here, and the
      // "contextmenu" that may follow them is ignored.
      let keyEditAt = -Infinity;
      node.addEventListener("keydown", (e) => {
        if ((e.key === "F10" && e.shiftKey) || e.key === "ContextMenu") {
          e.preventDefault();
          keyEditAt = Date.now();
          edit();
        }
      });
      node.addEventListener("contextmenu", (e) => {
        e.preventDefault();
        if (Date.now() - keyEditAt > 1000) {
          edit();
        }
      });
      return node;
    });
    const add = document.createElement("button");
    add.type = "button";
    add.id = "filter-button-add";
    add.className = "icon";
    add.textContent = "+";
    add.title = "Add a filter button for the display filter in the filter bar…";
    add.setAttribute("aria-label", "Add filter button");
    add.addEventListener("click", () =>
      vscode.postMessage({ type: "addFilterButton", filter: el.filterInput.value.trim() }),
    );
    bar.replaceChildren(...buttons, add);
    bar.classList.toggle("hidden", !buttons.length);
    updateFilterButtons();
  }

  /** Marks the buttons whose filter is the applied one. */
  function updateFilterButtons() {
    const applied = state.appliedFilter.trim();
    for (const node of el.filterButtons.querySelectorAll("button.filter-button")) {
      const b = state.filterButtons[Number(/** @type {HTMLElement} */ (node).dataset.index)];
      node.setAttribute("aria-pressed", String(!!b && !!applied && b.filter === applied));
    }
  }

  function updateStatus() {
    updateFilterButtons();
    renderProgress();
    const info = state.info;
    el.statusTime.textContent = TIME_LABELS[state.timeFormat] ?? "";
    el.statusTime.classList.toggle("hidden", !info);
    el.statusNames.classList.toggle("hidden", !info);
    if (!info) {
      el.statusLeft.textContent = "";
      el.statusInfo.textContent = "";
      return;
    }
    const parts = [`Packets: ${info.frames.toLocaleString()}`];
    if (state.indexing && !state.capture) {
      parts[0] = lib.indexingLabel({
        phase: state.indexPhase,
        frames: info.frames,
        fraction: state.indexFraction,
        resumedAt: state.resumedAt,
      });
    }
    if (state.filtering) {
      const pct =
        state.filterFraction !== null ? ` (${Math.round(state.filterFraction * 100)}%)` : "";
      parts.push(`Filtering… ${state.matchCount.toLocaleString()} matches so far${pct}`);
    } else if (state.appliedFilter) {
      const pct = info.frames ? ((state.matchCount / info.frames) * 100).toFixed(1) : "0";
      const stopped = state.filterPartial ? ", filter stopped early" : "";
      parts.push(`Displayed: ${state.matchCount.toLocaleString()} (${pct}%${stopped})`);
    }
    if (state.selectedFrame !== null) {
      const multi = state.selection.size
        ? ` (${state.selection.size.toLocaleString()} packets)`
        : "";
      parts.push(`Selected: ${state.selectedFrame}${multi}`);
    }
    if (state.markCount) {
      parts.push(`Marked: ${state.markCount.toLocaleString()}`);
    }
    if (state.coloringProgress !== undefined) {
      const pct =
        state.coloringProgress !== null ? ` ${Math.round(state.coloringProgress * 100)}%` : "";
      parts.push(`Coloring…${pct}`);
    }
    if (state.exportProgress !== undefined) {
      const pct =
        state.exportProgress !== null ? ` ${Math.round(state.exportProgress * 100)}%` : "";
      parts.push(`Exporting…${pct}`);
    }
    if (state.timeRef !== null) {
      parts.push(`Time reference: ${state.timeRef}`);
    }
    el.statusLeft.textContent = parts.join(" · ");
    const right = [info.fileType, info.linkType, lib.formatBytes(info.size)].filter(Boolean);
    if (typeof state.elapsedMs === "number") {
      right.push(`loaded in ${(state.elapsedMs / 1000).toFixed(1)} s`);
    }
    el.statusInfo.textContent = right.join(" · ");
  }

  function persist() {
    const root = document.documentElement.style;
    vscode.setState({
      widths: state.widths,
      expanded: [...state.expanded].slice(-200),
      menuGroups: [...state.menuGroups],
      listHeight: root.getPropertyValue("--list-height"),
      treeWidth: root.getPropertyValue("--tree-width"),
    });
  }

  // ------------------------------------------------------------------ boot

  if (saved.listHeight) {
    document.documentElement.style.setProperty("--list-height", saved.listHeight);
  }
  if (saved.treeWidth) {
    document.documentElement.style.setProperty("--tree-width", saved.treeWidth);
  }
  const rh = parseFloat(
    getComputedStyle(document.documentElement).getPropertyValue("--row-height"),
  );
  if (rh > 0) {
    state.rowHeight = rh;
  }
  showOverlay("Starting…", { progress: true });
  vscode.postMessage({ type: "ready" });
})();
