// @ts-check
/**
 * TCP stream graphs panel: Stevens (sequence number over time), throughput,
 * round-trip time and window scaling for one direction of one TCP stream,
 * from the backend's tcp_graph. Hover shows the nearest packet, click goes to
 * it; ←/→ step through the points, Enter goes to the highlighted one.
 */
(function () {
  "use strict";

  const vscode = acquireVsCodeApi();
  /** @type {any} */
  const lib = /** @type {any} */ (window).PcapLib;
  const SVG = "http://www.w3.org/2000/svg";
  const HEIGHT = 340;
  const MARGIN = { top: 14, right: 18, bottom: 34, left: 78 };
  const MAX_DRAWN = 6000;

  const KINDS = {
    stevens: "Stevens (sequence numbers)",
    throughput: "Throughput",
    rtt: "Round-trip time",
    window: "Window scaling",
  };

  const state = {
    /** @type {{stream: number, endpoints: string[], points: any[][]} | null} */ data: null,
    /** @type {keyof typeof KINDS} */ kind: "stevens",
    /** @type {0 | 1} */ dir: 0,
    queryId: 0,
    /** @type {any} */ series: null,
    hover: -1,
  };

  const app = /** @type {HTMLElement} */ (document.getElementById("app"));

  /** @param {string} tag @param {Record<string, string>} [attrs] @param {(Node | string)[]} [children] */
  function h(tag, attrs = {}, children = []) {
    const node = document.createElement(tag);
    for (const [k, v] of Object.entries(attrs)) {
      node.setAttribute(k, v);
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

  const title = h("h1", { class: "panel-title" }, ["TCP Stream Graph"]);
  const kindSelect = /** @type {HTMLSelectElement} */ (h("select", { "aria-label": "Graph" }));
  for (const [value, label] of Object.entries(KINDS)) {
    kindSelect.append(h("option", { value }, [label]));
  }
  const dirButton = h("button", {
    type: "button",
    class: "secondary",
    id: "tcp-direction",
    title: "Show the other direction",
  });
  const askButton = h(
    "button",
    {
      type: "button",
      class: "secondary hidden",
      id: "tcp-ask",
      title:
        "Ask Copilot to explain this stream (sends its sequence numbers, windows, round-trip times and flags, never payloads)",
    },
    ["Ask Copilot…"],
  );
  const prev = h("button", { type: "button", class: "secondary", title: "Previous stream" }, ["◀"]);
  const next = h("button", { type: "button", class: "secondary", title: "Next stream" }, ["▶"]);
  const toolbar = h("div", { class: "toolbar", role: "toolbar" }, [
    h("label", {}, ["Graph ", kindSelect]),
    dirButton,
    askButton,
    h("span", { class: "spacer" }),
    prev,
    next,
  ]);
  const status = h("div", { class: "status", role: "status" });
  const notice = h("div", { class: "notice error hidden", role: "alert" });
  const chart = h("div", { class: "chart", tabindex: "0", "aria-label": "TCP stream graph" });
  const tooltip = h("div", { class: "tooltip hidden" });
  chart.append(tooltip);
  app.append(title, toolbar, notice, status, chart);

  kindSelect.addEventListener("change", () => {
    state.kind = /** @type {keyof typeof KINDS} */ (kindSelect.value);
    draw();
  });
  dirButton.addEventListener("click", () => {
    state.dir = state.dir === 0 ? 1 : 0;
    draw();
  });
  askButton.addEventListener(
    "click",
    () => state.data && vscode.postMessage({ type: "askCopilot", stream: state.data.stream }),
  );
  prev.addEventListener("click", () => state.data && query({ stream: state.data.stream - 1 }));
  next.addEventListener("click", () => state.data && query({ stream: state.data.stream + 1 }));

  /** @param {{stream?: number, frame?: number}} what */
  function query(what) {
    if (what.stream !== undefined && what.stream < 0) {
      return;
    }
    const id = ++state.queryId;
    status.textContent = "Reading the TCP stream…";
    notice.classList.add("hidden");
    vscode.postMessage({ type: "query", id, ...what });
  }

  window.addEventListener("message", (event) => {
    const msg = event.data;
    if (msg.type === "init" || msg.type === "show") {
      if (msg.type === "init") {
        askButton.classList.toggle("hidden", !msg.ai);
      }
      query({ frame: msg.frame });
    } else if (msg.type === "stream" && msg.id === state.queryId) {
      state.data = msg.result;
      // The direction that carries the most data (usually what the graph is about).
      const bytes = [0, 0];
      for (const p of msg.result.points) {
        bytes[p[2]] += p[4];
      }
      state.dir = bytes[1] > bytes[0] ? 1 : 0;
      draw();
    } else if (msg.type === "error" && msg.id === state.queryId) {
      status.textContent = "";
      if (!msg.cancelled) {
        notice.textContent = msg.message;
        notice.classList.remove("hidden");
      }
    }
  });

  function draw() {
    const data = state.data;
    if (!data) {
      return;
    }
    const [a, b] = data.endpoints;
    const from = state.dir === 0 ? a : b;
    const to = state.dir === 0 ? b : a;
    title.textContent = `TCP stream ${data.stream}: ${from ?? "?"} → ${to ?? "?"}`;
    dirButton.textContent = "Switch Direction";
    dirButton.toggleAttribute("disabled", data.endpoints.length < 2);
    prev.toggleAttribute("disabled", data.stream <= 0);
    const series = lib.tcpGraphSeries(data.points, state.dir, state.kind);
    state.series = series;
    state.hover = -1;
    const segments = data.points.filter((p) => p[2] === state.dir && p[4] > 0);
    const bytes = segments.reduce((sum, p) => sum + p[4], 0);
    status.textContent = data.points.length
      ? `${data.points.length.toLocaleString()} packets; ${segments.length.toLocaleString()} data segments, ${lib.formatBytes(bytes)} from ${from}`
      : "No packets in this stream (it may not exist).";
    render();
  }

  function render() {
    const series = state.series;
    [...chart.querySelectorAll("svg")].forEach((n) => n.remove());
    if (!series) {
      return;
    }
    const width = Math.max(320, chart.clientWidth);
    const plotW = width - MARGIN.left - MARGIN.right;
    const plotH = HEIGHT - MARGIN.top - MARGIN.bottom;
    const svg = s("svg", { width, height: HEIGHT, role: "img", "aria-label": series.yLabel });
    const all = [...series.points, ...(series.line ?? [])];
    const xs = all.map((p) => p.x);
    const maxY = Math.max(1, ...all.map((p) => p.y2 ?? p.y));
    // Time: from just before the stream's first packet (streams start anywhere).
    const xt = lib.niceRange(Math.min(...xs, Infinity), Math.max(...xs, 0));
    const yt = lib.niceTicks(maxY);
    const xMin = xt[0];
    const xMax = xt[xt.length - 1];
    const yMax = yt[yt.length - 1];
    const X = (/** @type {number} */ v) => MARGIN.left + ((v - xMin) / (xMax - xMin || 1)) * plotW;
    const Y = (/** @type {number} */ v) => MARGIN.top + plotH - (v / yMax) * plotH;
    for (const t of yt) {
      svg.append(
        s("line", { x1: MARGIN.left, x2: MARGIN.left + plotW, y1: Y(t), y2: Y(t), class: "grid" }),
      );
      const label = s("text", {
        x: MARGIN.left - 6,
        y: Y(t) + 4,
        class: "axis-label",
        "text-anchor": "end",
      });
      label.textContent = lib.formatCell(t);
      svg.append(label);
    }
    for (const t of xt) {
      const label = s("text", {
        x: X(t),
        y: MARGIN.top + plotH + 16,
        class: "axis-label",
        "text-anchor": "middle",
      });
      label.textContent = lib.formatCell(t);
      svg.append(label);
    }
    const xName = s("text", {
      x: MARGIN.left + plotW / 2,
      y: HEIGHT - 4,
      class: "axis-label",
      "text-anchor": "middle",
    });
    xName.textContent = series.xLabel;
    const yName = s("text", {
      x: 12,
      y: MARGIN.top + plotH / 2,
      class: "axis-label",
      "text-anchor": "middle",
      transform: `rotate(-90 12 ${MARGIN.top + plotH / 2})`,
    });
    yName.textContent = series.yLabel;
    svg.append(xName, yName);
    if (series.line && series.line.length) {
      const d = series.line
        .map((p, i) => `${i ? "L" : "M"}${X(p.x).toFixed(1)},${Y(p.y).toFixed(1)}`)
        .join(" ");
      svg.append(s("path", { d, class: "series-line" }));
    }
    const step = Math.max(1, Math.ceil(series.points.length / MAX_DRAWN));
    for (let i = 0; i < series.points.length; i += step) {
      const p = series.points[i];
      if (p.y2 !== undefined) {
        svg.append(
          s("line", {
            x1: X(p.x),
            x2: X(p.x),
            y1: Y(p.y),
            y2: Y(p.y2),
            class: p.flag ? "seg retrans" : "seg",
          }),
        );
      } else {
        svg.append(
          s("circle", { cx: X(p.x), cy: Y(p.y), r: 2.5, class: p.flag ? "dot retrans" : "dot" }),
        );
      }
    }
    if (state.hover >= 0 && series.points[state.hover]) {
      const p = series.points[state.hover];
      svg.append(
        s("line", {
          x1: X(p.x),
          x2: X(p.x),
          y1: MARGIN.top,
          y2: MARGIN.top + plotH,
          class: "crosshair",
        }),
      );
      svg.append(s("circle", { cx: X(p.x), cy: Y(p.y2 ?? p.y), r: 4, class: "focus" }));
      tooltip.textContent = `Packet ${p.frame} · ${lib.formatCell(p.x)} s · ${lib.formatCell(p.y2 ?? p.y)}${p.flag ? " · retransmission" : ""}`;
      tooltip.style.left = `${Math.min(width - 220, X(p.x) + 8)}px`;
      tooltip.style.top = `${MARGIN.top}px`;
      tooltip.classList.remove("hidden");
    } else {
      tooltip.classList.add("hidden");
    }
    chart.insertBefore(svg, tooltip);
    geometry = { X, plotLeft: MARGIN.left, plotW, xMin, xMax };
  }

  /** @type {{X: (v: number) => number, plotLeft: number, plotW: number, xMin: number, xMax: number} | null} */
  let geometry = null;

  /** @param {number} clientX */
  function nearest(clientX) {
    const series = state.series;
    if (!series || !series.points.length || !geometry) {
      return -1;
    }
    const svg = chart.querySelector("svg");
    const left = svg ? svg.getBoundingClientRect().left : 0;
    const x =
      geometry.xMin +
      ((clientX - left - geometry.plotLeft) / geometry.plotW) * (geometry.xMax - geometry.xMin);
    let best = 0;
    for (let i = 1; i < series.points.length; i++) {
      if (Math.abs(series.points[i].x - x) < Math.abs(series.points[best].x - x)) {
        best = i;
      }
    }
    return best;
  }

  chart.addEventListener("mousemove", (e) => {
    const i = nearest(e.clientX);
    if (i !== state.hover) {
      state.hover = i;
      render();
    }
  });
  chart.addEventListener("mouseleave", () => {
    state.hover = -1;
    render();
  });
  chart.addEventListener("click", (e) => {
    const i = nearest(e.clientX);
    const p = state.series?.points[i];
    if (p) {
      vscode.postMessage({ type: "goto", frame: p.frame });
    }
  });
  chart.addEventListener("keydown", (e) => {
    const n = state.series?.points.length ?? 0;
    if (!n) {
      return;
    }
    if (e.key === "ArrowRight" || e.key === "ArrowLeft") {
      e.preventDefault();
      const d = e.key === "ArrowRight" ? 1 : -1;
      state.hover = state.hover < 0 ? 0 : Math.max(0, Math.min(n - 1, state.hover + d));
      render();
    } else if (e.key === "Enter" && state.hover >= 0) {
      e.preventDefault();
      vscode.postMessage({ type: "goto", frame: state.series.points[state.hover].frame });
    }
  });

  let width = -1;
  new ResizeObserver(() => {
    if (chart.clientWidth !== width) {
      width = chart.clientWidth;
      render();
    }
  }).observe(chart);

  vscode.postMessage({ type: "ready" });
})();
