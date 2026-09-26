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

  const DEFAULT_WIDTHS = { number: 70, time: 100, source: 150, destination: 150, protocol: 80, length: 64 };
  const CUSTOM_WIDTH = 120;
  const NUMERIC_IDS = new Set(["number", "time", "length"]);

  /** @param {string} id */
  const $ = (id) => /** @type {HTMLElement} */ (document.getElementById(id));

  const el = {
    filterInput: /** @type {HTMLInputElement} */ ($("filter-input")),
    filterApply: $("filter-apply"),
    filterClear: $("filter-clear"),
    filterCancel: $("filter-cancel"),
    filterError: $("filter-error"),
    filterSaved: $("filter-saved"),
    suggest: $("suggest"),
    busyBar: $("busy-bar"),
    busyFill: $("busy-bar-fill"),
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
    bytesTabs: $("bytes-tabs"),
    bytesView: $("bytes-view"),
    statusLeft: $("status-left"),
    statusRight: $("status-right"),
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
   * @typedef {{number: number, cells: string[]}} Row
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
    /** @type {any} */ detail: null,
    /** @type {number | null} */ detailRequest: null,
    /** @type {number | null} */ selectedNodeId: null,
    /** @type {Set<string>} */ expanded: new Set(saved.expanded || []),
    activeSource: 0,
    rowHeight: 22,
    /** @type {string[]} */ history: [],
    /** @type {{name: string, filter: string}[]} */ savedFilters: [],
    /** @type {number | null} */ filterRequest: null,
    validateSeq: 0,
    /** @type {number | null} */ elapsedMs: null,
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
        p?.resolve(msg.result);
        break;
      }
      case "rpcError": {
        const p = rpcPending.get(msg.id);
        rpcPending.delete(msg.id);
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
        rebuildColumns();
        resetView();
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
    }
  });

  /** @param {any} msg */
  function onInit(msg) {
    state.info = msg.info;
    // The backend lists the seven base columns first, then any custom ones.
    state.baseColumns = msg.info.columns.slice(0, 7);
    // Only columns tshark accepted; unknown fields were dropped (with a warning) at open.
    state.customColumns = lib.acceptedColumns(msg.columns, msg.info.columns.slice(7));
    state.total = msg.info.frames;
    state.matchCount = msg.info.frames;
    state.filterId = msg.info.filterId;
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
    } else {
      el.busyBar.classList.remove("hidden");
      setProgress(el.busyBar, el.busyFill, fraction);
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
      ...state.customColumns.map((c) => ({ id: `custom:${c.field}`, title: c.title, field: c.field, custom: true })),
    ];
  }

  function rebuildColumns() {
    const cols = columns();
    const template = cols
      .map((c) => (c.id === "info" ? "minmax(200px, 1fr)" : `${state.widths[c.id] ?? DEFAULT_WIDTHS[/** @type {keyof typeof DEFAULT_WIDTHS} */ (c.id)] ?? CUSTOM_WIDTH}px`))
      .join(" ");
    el.list.style.setProperty("--cols", template);
    el.header.replaceChildren(
      ...cols.map((c) => {
        const cell = document.createElement("div");
        cell.className = "list-row-cell" + (NUMERIC_IDS.has(c.id) ? " num" : "");
        cell.title = c.field;
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
    showFilterError(`Unknown field${fields.length > 1 ? "s" : ""} removed from columns: ${fields.join(", ")}`, true);
    rebuildColumns();
    resetView({ keepSelection: true });
  }

  /** @param {string} field */
  function toggleSort(field) {
    if (!state.ready) {
      return;
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

  /** @param {MouseEvent} e @param {string} id @param {HTMLElement} cell */
  function startColumnResize(e, id, cell) {
    e.preventDefault();
    e.stopPropagation();
    const startX = e.clientX;
    const startW = cell.getBoundingClientRect().width;
    /** @param {MouseEvent} ev */
    const move = (ev) => {
      state.widths[id] = Math.max(30, Math.round(startW + ev.clientX - startX));
      const cols = columns();
      el.list.style.setProperty(
        "--cols",
        cols.map((c) => (c.id === "info" ? "minmax(200px, 1fr)" : `${state.widths[c.id] ?? DEFAULT_WIDTHS[/** @type {keyof typeof DEFAULT_WIDTHS} */ (c.id)] ?? CUSTOM_WIDTH}px`)).join(" "),
      );
    };
    const up = () => {
      window.removeEventListener("mousemove", move);
      window.removeEventListener("mouseup", up);
      persist();
    };
    window.addEventListener("mousemove", move);
    window.addEventListener("mouseup", up);
  }

  // ------------------------------------------------------------------ view / paging

  function computeViewKey() {
    return [state.filterId, state.sort ? `${state.sort.field}:${state.sort.desc}` : "", state.customColumns.map((c) => c.field).join(",")].join("|");
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
    if (opts.keepSelection && state.selectedFrame !== null) {
      state.selectedIndex = null; // unknown until the backend says where it moved
      void relocateSelection();
    } else {
      el.viewport.scrollTop = 0;
    }
    render();
  }

  function updateSpacer() {
    const win = lib.computeWindow({ scrollTop: 0, viewportHeight: el.viewport.clientHeight, total: state.total, rowHeight: state.rowHeight });
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
    const cols = columns();
    // Reuse row elements (pooling keeps scrolling cheap).
    while (el.rows.children.length < win.count) {
      const row = document.createElement("div");
      row.className = "list-row";
      for (let i = 0; i < cols.length; i++) {
        const cell = document.createElement("div");
        if (NUMERIC_IDS.has(cols[i].id)) {
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
      rowEl.classList.toggle("selected", index === state.selectedIndex);
      rowEl.setAttribute("aria-selected", String(index === state.selectedIndex));
      for (let c = 0; c < cols.length; c++) {
        const cell = /** @type {HTMLElement} */ (rowEl.children[c]);
        let text = row ? row.cells[c] ?? "" : c === 0 ? "…" : "";
        if (row && cols[c].id === "time") {
          text = lib.formatRelativeTime(text);
        }
        if (cell.textContent !== text) {
          cell.textContent = text;
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
      if (state.pages.has(key) || state.inflightPages.has(key) || state.inflightPages.size >= MAX_INFLIGHT_PAGES) {
        continue;
      }
      const req = rpc("list_packets", {
        offset: page * PAGE_SIZE,
        limit: PAGE_SIZE,
        columns: state.customColumns.map((c) => c.field),
        sort: state.sort,
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
          state.pages.set(key, res.rows);
          if (res.total !== state.total) {
            state.total = res.total;
            updateSpacer();
          }
          if (state.selectedIndex !== null && state.selectedFrame === null && Math.floor(state.selectedIndex / PAGE_SIZE) === page) {
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
    const rowEl = /** @type {HTMLElement | null} */ (/** @type {HTMLElement} */ (e.target).closest(".list-row"));
    if (!rowEl || rowEl.dataset.index === undefined) {
      return;
    }
    selectIndex(Number(rowEl.dataset.index));
  });

  el.viewport.addEventListener("keydown", (e) => {
    if (!state.ready || state.total === 0) {
      return;
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
      selectIndex(Math.max(0, Math.min(state.total - 1, moves[e.key])));
    } else if (e.key === "Enter" || e.key === "ArrowRight") {
      e.preventDefault();
      el.tree.focus();
    }
  });

  /** @param {number} index @param {boolean} [center] */
  function selectIndex(index, center = false) {
    state.selectedIndex = index;
    scrollIndexIntoView(index, center);
    const row = rowAt(index);
    state.selectedFrame = row ? row.number : null;
    if (row) {
      selectFrame(row.number);
    }
    scheduleRender();
  }

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
    detailTimer = window.setTimeout(() => void loadDetail(frame), 60);
  }

  /** After a filter/sort change, find where the selected frame went. */
  async function relocateSelection() {
    const frame = state.selectedFrame;
    if (frame === null) {
      return;
    }
    try {
      const res = await rpc("find_frame", { number: frame }).promise;
      if (res.filterId !== state.filterId || frame !== state.selectedFrame) {
        return;
      }
      if (res.index === null || res.index === undefined) {
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

  /** @param {number} frame */
  async function gotoFrame(frame) {
    if (!state.ready) {
      return;
    }
    try {
      const res = await rpc("find_frame", { number: frame }).promise;
      if (res.index === null || res.index === undefined) {
        showFilterError(`Packet ${frame} is not displayed with the current filter.`, true);
        return;
      }
      selectIndex(res.index, true);
      el.viewport.focus();
    } catch (err) {
      showFilterError(String(/** @type {any} */ (err)?.message ?? err), true);
    }
  }

  // ------------------------------------------------------------------ detail tree

  /** @param {number} frame */
  async function loadDetail(frame) {
    if (state.detailRequest !== null) {
      cancelRpc(state.detailRequest);
    }
    if (state.detail && state.detail.number === frame) {
      return;
    }
    const req = rpc("packet_detail", { number: frame });
    state.detailRequest = req.id;
    el.treePlaceholder.textContent = `Loading packet ${frame}…`;
    el.treePlaceholder.classList.remove("hidden");
    try {
      const detail = await req.promise;
      if (state.selectedFrame !== frame) {
        return;
      }
      showDetail(detail);
    } catch (err) {
      const e = /** @type {any} */ (err);
      if (e?.code !== CANCELLED && state.selectedFrame === frame) {
        el.tree.replaceChildren();
        el.treePlaceholder.textContent = `Could not dissect packet ${frame}: ${e?.message ?? e}`;
      }
    } finally {
      if (state.detailRequest === req.id) {
        state.detailRequest = null;
      }
    }
  }

  /**
   * Tell the host which packet is selected (for "Follow Stream" etc.).
   * Tracked separately from state.selectedFrame, which selectIndex sets early.
   * @param {number | null} frame
   */
  function reportSelection(frame) {
    if (frame !== reportedFrame) {
      reportedFrame = frame;
      vscode.postMessage({ type: "selection", frame });
    }
  }
  /** @type {number | null} */
  let reportedFrame = null;

  function clearDetail() {
    reportSelection(null);
    state.detail = null;
    state.selectedNodeId = null;
    nodeIndex.clear();
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
    const previous = state.selectedNodeId !== null ? nodeIndex.get(state.selectedNodeId) : undefined;
    const previousKey = previous ? lib.nodeKey(previous.path) : null;
    state.detail = detail;
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
    // Keep the same field selected when moving between similar packets.
    if (previousKey) {
      for (const entry of nodeIndex.values()) {
        if (lib.nodeKey(entry.path) === previousKey) {
          selectNode(entry.node.id, { scroll: true });
          break;
        }
      }
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
    row.className = "node-row" + (node.proto ? " proto" : "") + (node.name && node.name.startsWith("_ws.expert") ? " expert" : "");
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
    const row = /** @type {HTMLElement | null} */ (/** @type {HTMLElement} */ (e.target).closest(".node-row"));
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
  });

  el.tree.addEventListener("dblclick", (e) => {
    const row = /** @type {HTMLElement | null} */ (/** @type {HTMLElement} */ (e.target).closest(".node-row"));
    const entry = row && nodeIndex.get(Number(row.dataset.id));
    if (entry) {
      setExpanded(entry, !isExpanded(entry));
    }
  });

  el.tree.addEventListener("keydown", (e) => {
    const visible = [...el.tree.querySelectorAll(".node-row")].filter((r) => /** @type {HTMLElement} */ (r).offsetParent !== null);
    if (!visible.length) {
      return;
    }
    const current = state.selectedNodeId !== null ? nodeIndex.get(state.selectedNodeId) : undefined;
    const idx = current ? visible.indexOf(current.row) : -1;
    /** @param {number} i */
    const go = (i) => {
      const row = /** @type {HTMLElement} */ (visible[Math.max(0, Math.min(visible.length - 1, i))]);
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
      case "Enter":
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
        b.className = "b" + ((i - off) === 7 ? " gap" : "");
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
        pad.className = "b" + ((i - off) === 7 ? " gap" : "");
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
    const rowEl = /** @type {HTMLElement | null} */ (/** @type {HTMLElement} */ (e.target).closest(".list-row"));
    if (!rowEl || rowEl.dataset.index === undefined) {
      return;
    }
    e.preventDefault();
    selectIndex(Number(rowEl.dataset.index));
    const row = rowAt(Number(rowEl.dataset.index));
    if (!row) {
      return;
    }
    const protocol = (row.cells[4] || "").toUpperCase();
    /** @param {"tcp" | "udp" | "tls" | "http"} proto */
    const follow = (proto) => () => vscode.postMessage({ type: "follow", proto, frame: row.number });
    /** @type {[string, (() => void) | null][]} */
    const items = [
      ["Follow TCP Stream", follow("tcp")],
      ["Follow UDP Stream", follow("udp")],
      ["Follow TLS Stream", /TLS|SSL/.test(protocol) ? follow("tls") : null],
      ["Follow HTTP Stream", /HTTP/.test(protocol) ? follow("http") : null],
      ["-", null],
      ["Copy Summary", () => copy(row.cells.join("\t"))],
      ["Copy Frame Number", () => copy(String(row.number))],
    ];
    showMenu(e.clientX, e.clientY, items);
  });

  el.tree.addEventListener("contextmenu", (e) => {
    const row = /** @type {HTMLElement | null} */ (/** @type {HTMLElement} */ (e.target).closest(".node-row"));
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
      ["Apply as Filter", filter ? () => applyFromTree(lib.combineFilter(current, filter, "replace"), true) : null],
      ["Prepare as Filter", filter ? () => applyFromTree(filter, false) : null],
      ["…and Selected", filter && current ? () => applyFromTree(lib.combineFilter(current, filter, "and"), true) : null],
      ["…or Selected", filter && current ? () => applyFromTree(lib.combineFilter(current, filter, "or"), true) : null],
      ["…and not Selected", filter ? () => applyFromTree(lib.combineFilter(current, filter, "not"), true) : null],
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
      if (seq !== state.validateSeq) {
        return;
      }
      el.filterInput.classList.toggle("valid", res.valid);
      el.filterInput.classList.toggle("invalid", !res.valid);
      el.filterInput.title = res.valid ? "" : res.error;
      showFilterError(res.valid ? "" : res.error);
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
    showFilterError("");
    const req = rpc("set_filter", { expr });
    state.filterRequest = req.id;
    el.filterCancel.classList.remove("hidden");
    el.busyBar.classList.remove("hidden");
    setProgress(el.busyBar, el.busyFill, null);
    try {
      const res = await req.promise;
      state.appliedFilter = res.expr;
      state.filterId = res.filterId;
      state.total = res.matchCount;
      state.matchCount = res.matchCount;
      el.filterInput.classList.remove("invalid");
      el.filterInput.classList.toggle("valid", !!expr);
      vscode.postMessage({ type: "filterApplied", expr });
      resetView({ keepSelection: true });
      updateStatus();
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
        el.filterCancel.classList.add("hidden");
        el.busyBar.classList.add("hidden");
      }
    }
  }

  el.filterApply.addEventListener("click", () => {
    hideSuggest();
    void applyFilter(el.filterInput.value);
  });
  el.filterClear.addEventListener("click", () => {
    el.filterInput.value = "";
    el.filterInput.classList.remove("valid", "invalid");
    hideSuggest();
    void applyFilter("");
  });
  el.filterCancel.addEventListener("click", () => {
    if (state.filterRequest !== null) {
      cancelRpc(state.filterRequest);
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
   * @typedef {{label: string, detail?: string, desc?: string, kind: "field" | "protocol" | "operator" | "saved" | "recent" | "action", value: string}} SuggestItem
   */
  const suggest = {
    /** @type {SuggestItem[]} */ items: [],
    index: -1,
    /** @type {"complete" | "saved" | null} */ mode: null,
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
      const items = lib.operatorSuggestions(ctx.kind, ctx.prefix).map((/** @type {any} */ o) => ({ label: o.label, desc: o.desc, kind: "operator", value: o.label }));
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
        ...res.protocols.map((/** @type {any} */ p) => ({ label: p.name, detail: "protocol", desc: p.desc, kind: "protocol", value: p.name })),
        ...res.fields.map((/** @type {any} */ f) => ({ label: f.name, detail: lib.friendlyType(f.type), desc: f.blurb ? `${f.desc} — ${f.blurb}` : f.desc, kind: "field", value: f.name })),
      ];
      // An exact match first, then protocols before fields (both lists are sorted).
      items.sort((a, b) => Number(b.value.toLowerCase() === ctx.prefix.toLowerCase()) - Number(a.value.toLowerCase() === ctx.prefix.toLowerCase()));
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
      items.push({ label: f.name, detail: "saved", desc: f.filter, kind: "saved", value: f.filter });
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
   * @param {"complete" | "saved"} mode
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
    [...el.suggest.children].forEach((row, i) => row.classList.toggle("active", i === suggest.index));
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
    const res = lib.applyCompletion(el.filterInput.value, ctx, item.value, item.kind === "operator");
    el.filterInput.value = res.text;
    el.filterInput.focus();
    el.filterInput.setSelectionRange(res.cursor, res.cursor);
    validateSoon();
  }

  el.filterInput.addEventListener("input", () => {
    validateSoon();
    suggestSoon(false);
  });
  el.filterInput.addEventListener("keydown", (e) => {
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
  el.filterInput.addEventListener("blur", () => window.setTimeout(() => {
    if (document.activeElement !== el.filterInput && document.activeElement !== el.filterSaved) {
      hideSuggest();
    }
  }, 150));
  // mousedown (not click) so the input keeps focus.
  el.suggest.addEventListener("mousedown", (e) => {
    e.preventDefault();
    const row = /** @type {HTMLElement | null} */ (/** @type {HTMLElement} */ (e.target).closest(".suggest-item"));
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

  // ------------------------------------------------------------------ splitters

  /**
   * @param {HTMLElement} handle
   * @param {"row" | "col"} axis
   */
  function makeSplitter(handle, axis) {
    handle.addEventListener("mousedown", (e) => {
      e.preventDefault();
      handle.classList.add("dragging");
      const container = axis === "row" ? /** @type {HTMLElement} */ ($("main")) : /** @type {HTMLElement} */ ($("bottom"));
      /** @param {MouseEvent} ev */
      const move = (ev) => {
        const rect = container.getBoundingClientRect();
        const ratio = axis === "row" ? (ev.clientY - rect.top) / rect.height : (ev.clientX - rect.left) / rect.width;
        const pct = `${Math.round(Math.max(0.1, Math.min(0.9, ratio)) * 1000) / 10}%`;
        document.documentElement.style.setProperty(axis === "row" ? "--list-height" : "--tree-width", pct);
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

  function updateStatus() {
    const info = state.info;
    if (!info) {
      el.statusLeft.textContent = "";
      el.statusRight.textContent = "";
      return;
    }
    const parts = [`Packets: ${info.frames.toLocaleString()}`];
    if (state.appliedFilter) {
      const pct = info.frames ? ((state.matchCount / info.frames) * 100).toFixed(1) : "0";
      parts.push(`Displayed: ${state.matchCount.toLocaleString()} (${pct}%)`);
    }
    if (state.selectedFrame !== null) {
      parts.push(`Selected: ${state.selectedFrame}`);
    }
    el.statusLeft.textContent = parts.join(" · ");
    const right = [info.fileType, info.linkType, lib.formatBytes(info.size)].filter(Boolean);
    if (typeof state.elapsedMs === "number") {
      right.push(`loaded in ${(state.elapsedMs / 1000).toFixed(1)} s`);
    }
    el.statusRight.textContent = right.join(" · ");
  }

  function persist() {
    const root = document.documentElement.style;
    vscode.setState({
      widths: state.widths,
      expanded: [...state.expanded].slice(-200),
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
  const rh = parseFloat(getComputedStyle(document.documentElement).getPropertyValue("--row-height"));
  if (rh > 0) {
    state.rowHeight = rh;
  }
  showOverlay("Starting…", { progress: true });
  vscode.postMessage({ type: "ready" });
})();
