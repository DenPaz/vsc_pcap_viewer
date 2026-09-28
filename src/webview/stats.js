// @ts-check
/**
 * Statistics panel: renders a backend `stats` table (conversations, endpoints,
 * protocol hierarchy, IO graph, expert info, capture properties, HTTP, DNS,
 * packet lengths, service response time) with sorting (not of trees),
 * row actions (apply/prepare filter, go to packet), CSV copy and, for the IO
 * graph, a line chart. Untrusted text only goes through textContent.
 */
(function () {
  "use strict";

  const vscode = acquireVsCodeApi();
  /** @type {any} */
  const lib = /** @type {any} */ (window).PcapLib;
  const SVG = "http://www.w3.org/2000/svg";

  const TYPE_LABELS = { eth: "Ethernet", ip: "IPv4", ipv6: "IPv6", tcp: "TCP", udp: "UDP" };
  const HTTP_REPORTS = {
    packets: "Packet Counter",
    requests: "Requests",
    load: "Load Distribution",
  };
  // Mirrors stats.SRT_PROTOCOLS in the backend.
  const SRT_PROTOCOLS = {
    icmp: "ICMP",
    icmpv6: "ICMPv6",
    smb: "SMB",
    smb2: "SMB2",
    ldap: "LDAP",
    snmp: "SNMP",
    diameter: "Diameter",
    gtp: "GTP",
    gtpv2: "GTPv2",
    ncp: "NCP",
    afp: "AFP",
    camel: "CAMEL",
    fc: "Fibre Channel",
  };
  /** Reports that are trees: their row order is the tree's, so no sorting. */
  const TREES = ["phs", "http", "dns", "plen"];
  /** @type {Record<string, string>} */
  const DEFAULT_TYPE = { http: "packets", srt: "auto" };
  const INTERVALS = [
    ["", "Auto"],
    ["0.001", "1 ms"],
    ["0.01", "10 ms"],
    ["0.1", "100 ms"],
    ["1", "1 s"],
    ["10", "10 s"],
    ["60", "1 min"],
  ];

  const state = {
    kind: "",
    filter: "",
    type: "tcp",
    interval: "",
    limit: false,
    metric: "packets",
    /** @type {any} */ table: null,
    /** @type {{col: number, desc: boolean} | null} */ sort: null,
    /** @type {any} */ selected: null,
    queryId: 0,
    /** @type {number | null} */ pending: null,
    /** AI help is available (the host said so): offer "Ask Copilot…" on expert information. */
    ai: false,
  };

  const app = /** @type {HTMLElement} */ (document.getElementById("app"));

  /**
   * @param {string} tag
   * @param {Record<string, string>} [attrs]
   * @param {(Node | string)[]} [children]
   */
  function h(tag, attrs = {}, children = []) {
    const node = document.createElement(tag);
    for (const [k, v] of Object.entries(attrs)) {
      if (k === "class") {
        node.className = v;
      } else {
        node.setAttribute(k, v);
      }
    }
    node.append(...children);
    return node;
  }

  // ------------------------------------------------------------------ skeleton

  const title = h("h1", { class: "panel-title" });
  const toolbar = h("div", { class: "toolbar", role: "toolbar" });
  const actions = h("div", { class: "toolbar" });
  const status = h("div", { class: "status", role: "status" });
  const notice = h("div", { class: "notice error hidden", role: "alert" });
  const chartBox = h("div", { class: "chart hidden", tabindex: "0", "aria-label": "I/O graph" });
  const tableBox = h("div");
  app.append(title, toolbar, actions, notice, status, chartBox, tableBox);

  const applyBtn = h("button", { type: "button", title: "Apply this row as the display filter" }, [
    "Apply as Filter",
  ]);
  const prepareBtn = h(
    "button",
    { type: "button", class: "secondary", title: "Put this row's filter in the filter bar" },
    ["Prepare as Filter"],
  );
  const gotoBtn = h(
    "button",
    { type: "button", class: "secondary", title: "Select the first packet of this row" },
    ["Go to Packet"],
  );
  const copyBtn = h("button", { type: "button", class: "secondary" }, ["Copy as CSV"]);
  const askBtn = h(
    "button",
    {
      type: "button",
      class: "secondary",
      id: "ask-copilot",
      title:
        "Ask Copilot why the selected entry happens (no selection: the capture's errors and warnings). Sends expert information and conversation statistics, never packet contents.",
    },
    ["Ask Copilot…"],
  );
  askBtn.addEventListener("click", () => askCopilot());
  applyBtn.addEventListener("click", () => rowFilter(true));
  prepareBtn.addEventListener("click", () => rowFilter(false));
  gotoBtn.addEventListener("click", () => rowGoto());
  copyBtn.addEventListener("click", () => {
    if (state.table) {
      vscode.postMessage({ type: "copy", text: lib.tableToCsv(state.table.columns, sortedRows()) });
    }
  });

  function buildToolbar() {
    toolbar.replaceChildren();
    if (state.kind === "conversations" || state.kind === "endpoints") {
      const select = h("select", { "aria-label": "Address type" });
      for (const [value, label] of Object.entries(TYPE_LABELS)) {
        const opt = h("option", { value }, [label]);
        if (value === state.type) {
          opt.setAttribute("selected", "");
        }
        select.append(opt);
      }
      select.addEventListener("change", () => {
        state.type = /** @type {HTMLSelectElement} */ (select).value;
        query();
      });
      toolbar.append(h("label", {}, ["Type ", select]));
    }
    if (state.kind === "http" || state.kind === "srt") {
      toolbar.append(typeSelect());
    }
    if (state.kind === "io") {
      const interval = h("select", { "aria-label": "Interval" });
      for (const [value, label] of INTERVALS) {
        interval.append(h("option", { value }, [label]));
      }
      interval.addEventListener("change", () => {
        state.interval = /** @type {HTMLSelectElement} */ (interval).value;
        query();
      });
      const metric = h("select", { "aria-label": "Metric" });
      metric.append(
        h("option", { value: "packets" }, ["Packets"]),
        h("option", { value: "bytes" }, ["Bytes"]),
      );
      metric.addEventListener("change", () => {
        state.metric = /** @type {HTMLSelectElement} */ (metric).value;
        renderChart();
      });
      toolbar.append(h("label", {}, ["Interval ", interval]), h("label", {}, ["Show ", metric]));
    }
    if (state.kind !== "properties") {
      const box = /** @type {HTMLInputElement} */ (h("input", { type: "checkbox" }));
      box.checked = state.limit;
      box.disabled = !state.filter;
      box.addEventListener("change", () => {
        state.limit = box.checked;
        query();
      });
      const label = h(
        "label",
        { title: state.filter ? "" : "No display filter is applied in the capture" },
        [box, "Limit to display filter"],
      );
      if (state.filter) {
        label.append(" ", h("code", {}, [state.filter]));
      }
      toolbar.append(label);
    }
    const refresh = h("button", { type: "button", class: "secondary" }, ["Refresh"]);
    refresh.addEventListener("click", () => query());
    toolbar.append(h("span", { class: "spacer" }), refresh);
    actions.replaceChildren(
      ...(state.kind === "expert"
        ? [gotoBtn, applyBtn, prepareBtn, ...(state.ai ? [askBtn] : [])]
        : state.kind === "srt"
          ? [applyBtn, prepareBtn, gotoBtn]
          : state.kind === "properties" || state.kind === "io"
            ? []
            : [applyBtn, prepareBtn]),
      copyBtn,
    );
    updateActions();
  }

  /** The HTTP report or SRT protocol picker; protocols with traffic are marked. */
  function typeSelect() {
    const http = state.kind === "http";
    const select = /** @type {HTMLSelectElement} */ (
      h("select", { id: "stats-type", "aria-label": http ? "Report" : "Protocol" })
    );
    /** @type {Record<string, string>} */
    const choices = http ? HTTP_REPORTS : SRT_PROTOCOLS;
    const available = (state.table && state.table.available) || [];
    for (const [value, label] of Object.entries(choices)) {
      const withTraffic = !http && available.includes(value);
      select.append(h("option", { value }, [withTraffic ? `${label} ●` : label]));
    }
    select.value = state.type in choices ? state.type : Object.keys(choices)[0];
    select.title = http
      ? ""
      : "● marks protocols this capture has traffic for (DCE-RPC, ONC-RPC and SCSI need arguments and aren't offered)";
    select.addEventListener("change", () => {
      state.type = select.value;
      query();
    });
    return h("label", {}, [http ? "Report " : "Protocol ", select]);
  }

  // ------------------------------------------------------------------ data

  function query() {
    if (state.pending !== null) {
      vscode.postMessage({ type: "cancel", id: state.pending });
    }
    const id = ++state.queryId;
    state.pending = id;
    status.textContent = "Running tshark…";
    notice.classList.add("hidden");
    vscode.postMessage({
      type: "query",
      id,
      params: {
        type: state.type,
        interval: state.interval ? Number(state.interval) : undefined,
        limit: state.limit,
      },
    });
  }

  window.addEventListener("message", (event) => {
    const msg = event.data;
    if (msg.type === "init") {
      state.kind = msg.kind;
      state.type = DEFAULT_TYPE[msg.kind] || state.type;
      state.filter = msg.filter || "";
      state.ai = !!msg.ai;
      title.textContent = msg.title;
      buildToolbar();
      query();
    } else if (msg.type === "result" && msg.id === state.pending) {
      state.pending = null;
      state.table = msg.table;
      state.selected = null;
      state.sort = null;
      title.textContent = msg.table.title;
      if (state.kind === "srt") {
        // "auto" came back as the protocol it picked, with the ones that have traffic.
        state.type = msg.table.type || state.type;
        buildToolbar();
      }
      render();
    } else if (msg.type === "error" && msg.id === state.pending) {
      state.pending = null;
      status.textContent = "";
      if (!msg.cancelled) {
        notice.textContent = msg.message;
        notice.classList.remove("hidden");
      }
    }
  });

  function sortedRows() {
    const rows = state.table ? state.table.rows : [];
    // Trees keep their order.
    if (!state.sort || TREES.includes(state.kind)) {
      return rows;
    }
    return lib.sortRows(rows, state.sort.col, state.sort.desc);
  }

  // ------------------------------------------------------------------ table

  function render() {
    const t = state.table;
    const n = t.rows.length;
    const scope = t.filter ? ` matching ${t.filter}` : "";
    status.textContent =
      t.kind === "io"
        ? `${n} intervals of ${lib.formatCell(t.interval)} s${scope}`
        : t.kind === "properties"
          ? ""
          : `${n.toLocaleString()} ${n === 1 ? "row" : "rows"}${scope}`;
    chartBox.classList.toggle("hidden", t.kind !== "io");
    if (t.kind === "io") {
      renderChart();
    }
    renderTable();
    updateActions();
  }

  function renderTable() {
    const t = state.table;
    const headRow = h("tr");
    t.columns.forEach((/** @type {any} */ col, /** @type {number} */ i) => {
      const indicator = state.sort && state.sort.col === i ? (state.sort.desc ? " ▼" : " ▲") : "";
      const th = h("th", { class: col.numeric ? "num" : "", scope: "col" }, [
        col.label + indicator,
      ]);
      if (!TREES.includes(state.kind) && state.kind !== "properties") {
        th.setAttribute(
          "aria-sort",
          state.sort && state.sort.col === i
            ? state.sort.desc
              ? "descending"
              : "ascending"
            : "none",
        );
        th.addEventListener("click", () => {
          state.sort =
            !state.sort || state.sort.col !== i
              ? { col: i, desc: col.numeric }
              : { col: i, desc: !state.sort.desc };
          renderTable();
        });
      }
      headRow.append(th);
    });
    const body = h("tbody");
    for (const row of sortedRows()) {
      const tr = h("tr");
      row.cells.forEach((/** @type {unknown} */ value, /** @type {number} */ i) => {
        const col = t.columns[i];
        const td = h("td", { class: col.numeric ? "num" : "" });
        if (i === 0 && row.depth) {
          td.style.paddingLeft = `${8 + row.depth * 16}px`;
        }
        if (t.kind === "expert" && col.id === "severity") {
          td.append(h("span", { class: `sev sev-${String(value)}` }, [String(value)]));
        } else {
          td.textContent = lib.formatCell(value);
        }
        if (t.kind === "expert" && col.id === "summary") {
          td.classList.add("wrap");
        }
        tr.append(td);
      });
      if (row === state.selected) {
        tr.classList.add("selected");
      }
      tr.addEventListener("click", () => {
        state.selected = row;
        [...body.children].forEach((r) => r.classList.toggle("selected", r === tr));
        updateActions();
      });
      tr.addEventListener("dblclick", () => (row.frame ? rowGoto() : rowFilter(true)));
      body.append(tr);
    }
    tableBox.replaceChildren(h("table", { class: "stats" }, [h("thead", {}, [headRow]), body]));
  }

  function updateActions() {
    const row = state.selected;
    applyBtn.toggleAttribute("disabled", !row || !row.filter);
    prepareBtn.toggleAttribute("disabled", !row || !row.filter);
    gotoBtn.toggleAttribute("disabled", !row || !row.frame);
    copyBtn.toggleAttribute("disabled", !state.table);
    if (state.kind === "expert" && row && !row.filter) {
      // Expert rows filter on the message text.
      applyBtn.toggleAttribute("disabled", false);
      prepareBtn.toggleAttribute("disabled", false);
    }
  }

  /** @param {boolean} apply */
  function rowFilter(apply) {
    const row = state.selected;
    if (!row) {
      return;
    }
    const expr =
      row.filter ||
      (state.kind === "expert"
        ? `_ws.expert.message == ${lib.quoteFilterString(String(row.cells[1]))}`
        : "");
    if (expr) {
      vscode.postMessage({ type: "filter", expr, apply });
    }
  }

  /** The expert row as the host's anomaly explanation takes it. */
  function expertRow(/** @type {any} */ row) {
    const cols = state.table.columns;
    const cell = (/** @type {string} */ id) =>
      row.cells[cols.findIndex((/** @type {any} */ c) => c.id === id)];
    return {
      severity: String(cell("severity") ?? ""),
      group: String(cell("group") ?? ""),
      protocol: String(cell("protocol") ?? ""),
      summary: String(cell("summary") ?? ""),
      count: Number(cell("count")) || 1,
      frames: (row.frames || (row.frame ? [row.frame] : [])).slice(0, 20),
    };
  }

  function askCopilot() {
    if (state.kind !== "expert" || !state.table) {
      return;
    }
    const rows = state.selected ? [expertRow(state.selected)] : [];
    vscode.postMessage({ type: "askCopilot", rows });
  }

  function rowGoto() {
    if (state.selected && state.selected.frame) {
      vscode.postMessage({ type: "goto", frame: state.selected.frame });
    }
  }

  // ------------------------------------------------------------------ IO chart

  const CHART_HEIGHT = 220;
  const MARGIN = { top: 12, right: 16, bottom: 28, left: 64 };
  let hoverIndex = -1;
  /** Chart width at the last render: only a width change needs a redraw. */
  let renderedWidth = -1;

  /** @param {string} tag @param {Record<string, string | number>} attrs */
  function s(tag, attrs) {
    const node = document.createElementNS(SVG, tag);
    for (const [k, v] of Object.entries(attrs)) {
      node.setAttribute(k, String(v));
    }
    return node;
  }

  function renderChart() {
    const t = state.table;
    if (!t || t.kind !== "io") {
      return;
    }
    const col = state.metric === "bytes" ? 3 : 2;
    const width = Math.max(320, chartBox.clientWidth || 600);
    renderedWidth = chartBox.clientWidth;
    const innerW = width - MARGIN.left - MARGIN.right;
    const innerH = CHART_HEIGHT - MARGIN.top - MARGIN.bottom;
    const rows = t.rows;
    const xMax = rows.length ? rows[rows.length - 1].cells[1] : 1;
    const values = rows.map((/** @type {any} */ r) => r.cells[col]);
    const ticks = lib.niceTicks(Math.max(0, ...values));
    const yMax = ticks[ticks.length - 1] || 1;
    // Each interval is plotted at its midpoint.
    const x = (/** @type {number} */ v) => MARGIN.left + (v / (xMax || 1)) * innerW;
    const y = (/** @type {number} */ v) => MARGIN.top + innerH - (v / yMax) * innerH;
    const points = rows.map((/** @type {any} */ r) => ({
      x: x((r.cells[0] + r.cells[1]) / 2),
      y: y(r.cells[col]),
      row: r,
    }));

    const svg = s("svg", {
      viewBox: `0 0 ${width} ${CHART_HEIGHT}`,
      height: CHART_HEIGHT,
      role: "img",
      "aria-label": `${state.metric === "bytes" ? "Bytes" : "Packets"} per ${lib.formatCell(t.interval)} s interval`,
    });
    const grid = s("g", { class: "grid" });
    const axis = s("g", { class: "axis" });
    for (const tick of ticks) {
      const ty = Math.round(y(tick)) + 0.5;
      grid.append(s("line", { x1: MARGIN.left, x2: width - MARGIN.right, y1: ty, y2: ty }));
      const label = s("text", { x: MARGIN.left - 8, y: ty + 4, "text-anchor": "end" });
      label.textContent = lib.formatCell(tick);
      axis.append(label);
    }
    for (const tick of lib.niceTicks(xMax, 6)) {
      if (tick > xMax) {
        break;
      }
      const label = s("text", { x: x(tick), y: CHART_HEIGHT - 8, "text-anchor": "middle" });
      label.textContent = `${lib.formatCell(tick)} s`;
      axis.append(label);
    }
    svg.append(grid, axis);
    if (points.length) {
      const line = points
        .map((p, i) => `${i ? "L" : "M"}${p.x.toFixed(1)},${p.y.toFixed(1)}`)
        .join("");
      const base = (MARGIN.top + innerH).toFixed(1);
      svg.append(
        s("path", {
          class: "series-area",
          d: `${line}L${points[points.length - 1].x.toFixed(1)},${base}L${points[0].x.toFixed(1)},${base}Z`,
        }),
        s("path", { class: "series-line", d: line }),
      );
    }
    const crosshair = s("line", {
      class: "crosshair hidden",
      y1: MARGIN.top,
      y2: MARGIN.top + innerH,
    });
    const marker = s("circle", { class: "marker hidden", r: 4 });
    // Hit area larger than the marks: the whole plot.
    const overlay = s("rect", {
      x: MARGIN.left,
      y: MARGIN.top,
      width: innerW,
      height: innerH,
      fill: "transparent",
    });
    svg.append(crosshair, marker, overlay);
    const tooltip = h("div", { class: "tooltip hidden", role: "status" });
    chartBox.replaceChildren(svg, tooltip);

    const show = (/** @type {number} */ i) => {
      hoverIndex = i;
      const p = points[i];
      if (!p) {
        return;
      }
      crosshair.setAttribute("x1", String(p.x));
      crosshair.setAttribute("x2", String(p.x));
      marker.setAttribute("cx", String(p.x));
      marker.setAttribute("cy", String(p.y));
      crosshair.classList.remove("hidden");
      marker.classList.remove("hidden");
      const [start, end, packets, bytes] = p.row.cells;
      const value =
        state.metric === "bytes"
          ? `${lib.formatCell(bytes)} bytes`
          : `${lib.formatCell(packets)} packets`;
      tooltip.replaceChildren(
        h("strong", {}, [value]),
        h("span", {}, [`${lib.formatCell(start)}–${lib.formatCell(end)} s`]),
      );
      tooltip.classList.remove("hidden");
      const box = chartBox.getBoundingClientRect();
      const scale = box.width / width;
      const left = p.x * scale + 12;
      tooltip.style.left = `${Math.min(left, box.width - tooltip.offsetWidth - 4)}px`;
      tooltip.style.top = `${Math.max(0, p.y * scale - 40)}px`;
    };
    const hide = () => {
      hoverIndex = -1;
      crosshair.classList.add("hidden");
      marker.classList.add("hidden");
      tooltip.classList.add("hidden");
    };
    overlay.addEventListener("pointermove", (e) => {
      const box = svg.getBoundingClientRect();
      const px = ((e.clientX - box.left) / box.width) * width;
      let best = 0;
      points.forEach((p, i) => {
        if (Math.abs(p.x - px) < Math.abs(points[best].x - px)) {
          best = i;
        }
      });
      show(best);
    });
    overlay.addEventListener("pointerleave", hide);
    chartBox.onkeydown = (e) => {
      if (e.key === "ArrowRight" || e.key === "ArrowLeft") {
        e.preventDefault();
        const next = hoverIndex < 0 ? 0 : hoverIndex + (e.key === "ArrowRight" ? 1 : -1);
        show(Math.max(0, Math.min(points.length - 1, next)));
      } else if (e.key === "Home" || e.key === "End") {
        e.preventDefault();
        show(e.key === "Home" ? 0 : points.length - 1);
      } else if (e.key === "Escape") {
        hide();
      }
    };
    chartBox.onblur = hide;
    // A redraw (resize, metric switch) keeps the hovered point: the old overlay is
    // gone without a pointerleave, and the pointer may not move again.
    if (hoverIndex >= 0) {
      show(Math.min(hoverIndex, points.length - 1));
    }
  }

  new ResizeObserver(() => {
    if (state.table && state.table.kind === "io" && chartBox.clientWidth !== renderedWidth) {
      renderChart();
    }
  }).observe(chartBox);

  vscode.postMessage({ type: "ready" });
})();
