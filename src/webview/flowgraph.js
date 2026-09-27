// @ts-check
/**
 * Flow graph panel: a sequence diagram of the displayed packets (the capture's
 * display filter) between their endpoints, in capture order. One column per
 * endpoint (Source/Destination, in order of first appearance), one arrow per
 * packet, drawn only for the rows on screen (pages of arrows come from the
 * backend's flow_graph). Click or Enter goes to the packet. Text from the
 * capture only goes through textContent.
 */
(function () {
  "use strict";

  const vscode = acquireVsCodeApi();
  /** @type {any} */
  const lib = /** @type {any} */ (window).PcapLib;
  const SVG = "http://www.w3.org/2000/svg";
  const ROW = 26;
  const GUTTER = 150;
  const COLUMN = 160;
  const PAGE = 200;
  const CHAR = 7; // approximate width of a character of the label font

  /**
   * @typedef {{number: number, time: string, from: number, to: number, protocol: string, info: string}} Arrow
   */
  const state = {
    total: 0,
    /** @type {string[]} */ nodes: [],
    more: 0,
    filter: "",
    /** @type {Map<number, Arrow[]>} */ pages: new Map(),
    /** @type {Set<number>} */ requested: new Set(),
    /** Bumped on reset: replies to older queries are dropped. */
    generation: 0,
    queryId: 0,
    /** @type {Map<number, {page: number, generation: number}>} */ queries: new Map(),
    /** @type {number | null} */ selected: null,
    loaded: false,
  };

  const app = /** @type {HTMLElement} */ (document.getElementById("app"));

  /**
   * @param {string} tag @param {Record<string, string>} [attrs] @param {(Node | string)[]} [children]
   */
  function h(tag, attrs = {}, children = []) {
    const node = document.createElement(tag);
    for (const [k, v] of Object.entries(attrs)) {
      node.setAttribute(k === "class" ? "class" : k, v);
    }
    node.append(...children);
    return node;
  }

  /** @param {string} tag @param {Record<string, string | number>} [attrs] */
  function s(tag, attrs = {}) {
    const node = document.createElementNS(SVG, tag);
    for (const [k, v] of Object.entries(attrs)) {
      node.setAttribute(k, String(v));
    }
    return node;
  }

  const title = h("h1", { class: "panel-title" }, ["Flow Graph"]);
  const statusText = h("span");
  const refresh = h("button", { type: "button", class: "secondary" }, ["Refresh"]);
  const toolbar = h("div", { class: "toolbar" }, [
    statusText,
    h("span", { class: "spacer" }),
    refresh,
  ]);
  const notice = h("div", { class: "notice error hidden", role: "alert" });
  const header = h("div", { class: "flow-header" });
  const body = h("div", { class: "flow-body" });
  const svg = /** @type {SVGSVGElement} */ (s("svg", { class: "flow-window" }));
  body.append(svg);
  const scroller = h(
    "div",
    {
      class: "flow-scroll",
      tabindex: "0",
      role: "listbox",
      "aria-label": "Packets between endpoints",
    },
    [header, body],
  );
  app.append(title, toolbar, notice, scroller);
  refresh.addEventListener("click", () => reset());

  function reset() {
    state.generation++;
    state.pages.clear();
    state.requested.clear();
    state.loaded = false;
    state.selected = null;
    notice.classList.add("hidden");
    statusText.textContent = "Reading the displayed packets…";
    request(0);
  }

  /** @param {number} page */
  function request(page) {
    if (state.requested.has(page)) {
      return;
    }
    state.requested.add(page);
    const id = ++state.queryId;
    state.queries.set(id, { page, generation: state.generation });
    vscode.postMessage({ type: "query", id, offset: page * PAGE, limit: PAGE });
  }

  window.addEventListener("message", (event) => {
    const msg = event.data;
    if (msg.type === "init") {
      title.textContent = msg.title;
      state.filter = msg.filter || "";
      reset();
    } else if (msg.type === "reset") {
      state.filter = msg.filter || "";
      reset();
    } else if (msg.type === "page") {
      const query = state.queries.get(msg.id);
      state.queries.delete(msg.id);
      if (!query || query.generation !== state.generation) {
        return;
      }
      const first = !state.loaded;
      state.loaded = true;
      state.total = msg.page.total;
      state.nodes = msg.page.nodes;
      state.more = msg.page.more;
      state.pages.set(query.page, msg.page.rows);
      if (first) {
        layout();
      }
      render();
    } else if (msg.type === "error") {
      const query = state.queries.get(msg.id);
      state.queries.delete(msg.id);
      if (!query || query.generation !== state.generation) {
        return;
      }
      state.requested.delete(query.page);
      if (!msg.cancelled) {
        statusText.textContent = "";
        notice.textContent = msg.busy
          ? "The capture is still being indexed or filtered: refresh when it is done."
          : msg.message;
        notice.classList.remove("hidden");
      }
    }
  });

  /** Columns and sizes, once the nodes are known. */
  function layout() {
    const columns = state.nodes.length + (state.more ? 1 : 0);
    const width = GUTTER + columns * COLUMN;
    header.replaceChildren(h("div", { class: "flow-gutter-title" }, ["Time · No."]));
    header.style.width = `${width}px`;
    const labels = state.more
      ? [...state.nodes, `${state.more.toLocaleString()} other endpoints`]
      : state.nodes;
    labels.forEach((name, i) => {
      const label = h("div", { class: "flow-node" }, [name]);
      label.title = name;
      label.style.left = `${GUTTER + i * COLUMN}px`;
      label.style.width = `${COLUMN}px`;
      header.append(label);
    });
    svg.setAttribute("width", String(width));
    body.style.width = `${width}px`;
    const endpoints = state.nodes.length + state.more;
    const scope = state.filter ? ` matching ${state.filter}` : "";
    statusText.textContent = state.total
      ? `${state.total.toLocaleString()} packets${scope} between ${endpoints.toLocaleString()} endpoints`
      : `No packets${scope}.`;
  }

  /** @param {number} index */
  function arrowAt(index) {
    return state.pages.get(Math.floor(index / PAGE))?.[index % PAGE];
  }

  function render() {
    if (!state.loaded) {
      return;
    }
    const headerHeight = header.offsetHeight;
    const win = lib.computeWindow({
      scrollTop: Math.max(0, scroller.scrollTop),
      viewportHeight: Math.max(0, scroller.clientHeight - headerHeight),
      total: state.total,
      rowHeight: ROW,
    });
    body.style.height = `${win.virtualHeight}px`;
    svg.style.top = `${win.top}px`;
    svg.setAttribute("height", String(Math.max(1, win.count * ROW)));
    svg.replaceChildren();
    const defs = s("defs");
    const marker = s("marker", {
      id: "head",
      markerWidth: 8,
      markerHeight: 8,
      refX: 7,
      refY: 4,
      orient: "auto",
    });
    marker.append(s("path", { d: "M0,0 L8,4 L0,8 z", class: "flow-head" }));
    defs.append(marker);
    svg.append(defs);
    const columns = state.nodes.length + (state.more ? 1 : 0);
    for (let c = 0; c < columns; c++) {
      const x = GUTTER + (c + 0.5) * COLUMN;
      svg.append(s("line", { x1: x, x2: x, y1: 0, y2: win.count * ROW, class: "flow-life" }));
    }
    for (let i = 0; i < win.count; i++) {
      const index = win.first + i;
      const arrow = arrowAt(index);
      if (!arrow) {
        request(Math.floor(index / PAGE));
        continue;
      }
      const y = i * ROW;
      const g = s("g", {
        class: arrow.number === state.selected ? "flow-row selected" : "flow-row",
      });
      g.dataset.frame = String(arrow.number);
      g.append(
        s("rect", { x: 0, y, width: GUTTER + columns * COLUMN, height: ROW, class: "flow-bg" }),
      );
      const when = s("text", { x: 6, y: y + 17, class: "flow-time" });
      when.textContent = `${lib.formatCell(Number(arrow.time))} · ${arrow.number}`;
      g.append(when);
      const { x1, x2, self } = lib.flowArrow(arrow.from, arrow.to, state.nodes.length, {
        gutter: GUTTER,
        column: COLUMN,
      });
      const ay = y + 19;
      if (self) {
        g.append(
          s("path", {
            d: `M${x1},${ay - 6} h24 v8 h-22`,
            class: "flow-arrow",
            "marker-end": "url(#head)",
          }),
        );
      } else {
        g.append(
          s("line", {
            x1,
            x2: x2 + (x2 > x1 ? -2 : 2),
            y1: ay,
            y2: ay,
            class: "flow-arrow",
            "marker-end": "url(#head)",
          }),
        );
      }
      // Centred above the arrow when it fits, else from the arrow's left end
      // to the right edge (a row holds one arrow, so the text can run on).
      const text = `${arrow.protocol}: ${arrow.info}`;
      const left = self ? x1 + 28 : Math.min(x1, x2) + 6;
      const span = self ? 0 : Math.abs(x2 - x1) - 12;
      const fits = text.length * CHAR <= span;
      const room = GUTTER + columns * COLUMN - left - 6;
      const label = s("text", {
        x: fits ? (x1 + x2) / 2 : left,
        y: y + 13,
        class: fits ? "flow-label middle" : "flow-label",
      });
      label.textContent = fits ? text : lib.truncate(text, Math.floor(room / CHAR));
      const tip = s("title");
      tip.textContent = `${arrow.number}: ${text}`;
      g.append(label, tip);
      svg.append(g);
    }
  }

  scroller.addEventListener("scroll", () => render());
  new ResizeObserver(() => render()).observe(scroller);

  svg.addEventListener("click", (e) => {
    const g = /** @type {Element} */ (e.target).closest(".flow-row");
    const frame = g ? Number(/** @type {SVGGElement} */ (g).dataset.frame) : NaN;
    if (Number.isFinite(frame)) {
      select(frame, true);
    }
  });

  /** @param {number} frame @param {boolean} go */
  function select(frame, go) {
    state.selected = frame;
    render();
    if (go) {
      vscode.postMessage({ type: "goto", frame });
    }
  }

  scroller.addEventListener("keydown", (e) => {
    if (!state.loaded || !state.total) {
      return;
    }
    if (e.key === "ArrowDown" || e.key === "ArrowUp") {
      e.preventDefault();
      const current = findIndex(state.selected);
      const next =
        current === null
          ? 0
          : Math.max(0, Math.min(state.total - 1, current + (e.key === "ArrowDown" ? 1 : -1)));
      const arrow = arrowAt(next);
      if (arrow) {
        select(arrow.number, false);
        scrollToIndex(next);
      }
    } else if (e.key === "Enter" && state.selected !== null) {
      e.preventDefault();
      vscode.postMessage({ type: "goto", frame: state.selected });
    }
  });

  /** @param {number | null} frame */
  function findIndex(frame) {
    if (frame === null) {
      return null;
    }
    for (const [page, rows] of state.pages) {
      const i = rows.findIndex((r) => r.number === frame);
      if (i >= 0) {
        return page * PAGE + i;
      }
    }
    return null;
  }

  /** @param {number} index */
  function scrollToIndex(index) {
    const viewportHeight = Math.max(0, scroller.clientHeight - header.offsetHeight);
    scroller.scrollTop = lib.scrollTopForIndex({
      index,
      scrollTop: scroller.scrollTop,
      viewportHeight,
      total: state.total,
      rowHeight: ROW,
    });
    render();
  }

  vscode.postMessage({ type: "ready" });
})();
