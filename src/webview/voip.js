// @ts-check
/**
 * VoIP calls panel: the SIP calls of a capture with a sequence diagram of the
 * selected call, its RTP streams (packets, loss, jitter), the analysis of a
 * stream packet by packet with a jitter graph, and its audio (played here
 * from a WAV file the host writes, or saved). Everything is built with
 * createElement/textContent: SIP URIs and payload names come from packets.
 */
(function () {
  "use strict";

  const vscode = acquireVsCodeApi();
  /** @type {any} */
  const lib = /** @type {any} */ (window).PcapLib;
  const SVG = "http://www.w3.org/2000/svg";
  const FLOW = { gutter: 96, column: 190, row: 26, top: 30 };
  const CHART = { height: 220, top: 12, right: 16, bottom: 32, left: 56 };

  const state = {
    /** @type {any[]} */ calls: [],
    /** @type {any[]} */ streams: [],
    heuristic: false,
    /** @type {number | null} */ call: null,
    /** @type {number | null} */ stream: null,
    requestId: 0,
    /** @type {any} */ analysis: null,
    listing: false,
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

  /** @param {string} tag @param {Record<string, string | number>} [attrs] @param {string} [text] */
  function s(tag, attrs = {}, text) {
    const node = document.createElementNS(SVG, tag);
    for (const [k, v] of Object.entries(attrs)) {
      node.setAttribute(k, String(v));
    }
    if (text !== undefined) {
      node.textContent = text;
    }
    return node;
  }

  /** @param {string} label @param {string} id @param {string} title */
  function button(label, id, title) {
    return h("button", { type: "button", class: "secondary", id, title }, [label]);
  }

  /** @param {number | null | undefined} v @param {number} [digits] */
  function num(v, digits = 3) {
    return v === null || v === undefined ? "" : Number(v).toFixed(digits);
  }

  // ------------------------------------------------------------------ layout

  const title = h("h1", { class: "panel-title" }, ["VoIP Calls"]);
  const refresh = button("Refresh", "voip-refresh", "Read the calls and streams again");
  const heuristic = /** @type {HTMLInputElement} */ (
    h("input", { type: "checkbox", id: "voip-heuristic" })
  );
  const status = h("div", { class: "status", role: "status" });
  const notice = h("div", { class: "notice error hidden", role: "alert" });
  app.append(
    title,
    h("div", { class: "toolbar", role: "toolbar" }, [
      refresh,
      h("label", { title: "Also find RTP that no SIP/SDP set up (tshark's RTP heuristic)" }, [
        heuristic,
        "Find RTP without signalling",
      ]),
      h("span", { class: "spacer" }),
    ]),
    status,
    notice,
  );

  const callsTable = h("table", { class: "stats", id: "voip-calls", "aria-label": "SIP calls" });
  const filterCall = button(
    "Filter Call",
    "voip-filter-call",
    "Show the call's SIP messages and RTP in the capture",
  );
  const callTools = h("div", { class: "toolbar", role: "toolbar" }, [filterCall]);
  const flow = h("div", { class: "voip-flow", id: "voip-flow", "aria-label": "Call flow" });
  app.append(h("h2", { class: "panel-subtitle-h" }, ["SIP Calls"]), callsTable, callTools, flow);

  const streamsTable = h("table", {
    class: "stats",
    id: "voip-streams",
    "aria-label": "RTP streams",
  });
  const analyse = button(
    "Analyse",
    "voip-analyse",
    "Packet-by-packet analysis: jitter, delta, lost packets",
  );
  const play = button("Play", "voip-play", "Decode the stream's G.711 audio and play it here");
  const save = button("Save Audio…", "voip-save", "Save the stream's audio as a WAV file");
  const filterStream = button(
    "Filter Stream",
    "voip-filter-stream",
    "Show the stream's packets in the capture",
  );
  const audio = /** @type {HTMLAudioElement} */ (
    h("audio", { controls: "", id: "voip-audio", class: "hidden", preload: "auto" })
  );
  const audioNote = h("span", { class: "status", id: "voip-audio-note" });
  const streamTools = h("div", { class: "toolbar", role: "toolbar" }, [
    analyse,
    play,
    save,
    filterStream,
    audio,
    audioNote,
  ]);
  const analysisBox = h("section", {
    class: "hidden",
    id: "voip-analysis",
    "aria-label": "Stream analysis",
  });
  app.append(
    h("h2", { class: "panel-subtitle-h" }, ["RTP Streams"]),
    streamsTable,
    streamTools,
    analysisBox,
  );

  refresh.addEventListener("click", () => list());
  heuristic.addEventListener("change", () => list());
  filterCall.addEventListener("click", () => {
    const call = state.call !== null ? state.calls[state.call] : null;
    if (call) {
      vscode.postMessage({ type: "filter", expr: call.filter });
    }
  });
  filterStream.addEventListener("click", () => {
    const stream = selectedStream();
    if (stream) {
      vscode.postMessage({ type: "filter", expr: stream.filter });
    }
  });
  analyse.addEventListener("click", () => request("analyse"));
  play.addEventListener("click", () => request("play"));
  save.addEventListener("click", () => {
    const stream = selectedStream();
    if (stream) {
      vscode.postMessage({ type: "save", stream, format: "wav" });
    }
  });

  function list() {
    state.listing = true;
    state.heuristic = heuristic.checked;
    status.textContent = "Reading SIP calls and RTP streams…";
    notice.classList.add("hidden");
    vscode.postMessage({ type: "list", heuristic: state.heuristic });
  }

  function selectedStream() {
    return state.stream !== null ? state.streams[state.stream] : null;
  }

  /** @param {"analyse" | "play"} kind */
  function request(kind) {
    const stream = selectedStream();
    if (!stream) {
      return;
    }
    const id = ++state.requestId;
    notice.classList.add("hidden");
    audioNote.textContent = kind === "play" ? "Decoding audio…" : "Analysing the stream…";
    vscode.postMessage({ type: kind, id, stream });
  }

  // ------------------------------------------------------------------ tables

  /**
   * @param {HTMLElement} table @param {string[]} headers @param {string[]} numeric
   * @param {(string | number)[][]} rows @param {number | null} selected
   * @param {(i: number) => void} onSelect @param {Set<number>} [linked]
   */
  function fillTable(table, headers, numeric, rows, selected, onSelect, linked) {
    table.replaceChildren();
    const head = h(
      "tr",
      {},
      headers.map((t) => h("th", numeric.includes(t) ? { class: "num" } : {}, [t])),
    );
    const body = h("tbody");
    rows.forEach((cells, i) => {
      const tr = h(
        "tr",
        {
          tabindex: "0",
          "aria-selected": String(i === selected),
          class: [i === selected ? "selected" : "", linked?.has(i) ? "linked" : ""]
            .join(" ")
            .trim(),
        },
        cells.map((c, j) =>
          h("td", numeric.includes(headers[j]) ? { class: "num" } : {}, [String(c)]),
        ),
      );
      tr.addEventListener("click", () => onSelect(i));
      tr.addEventListener("keydown", (e) => {
        if (e.key === "Enter" || e.key === " ") {
          e.preventDefault();
          onSelect(i);
        } else if (e.key === "ArrowDown" || e.key === "ArrowUp") {
          e.preventDefault();
          const next = /** @type {HTMLElement | null} */ (
            e.key === "ArrowDown" ? tr.nextElementSibling : tr.previousElementSibling
          );
          next?.focus();
        }
      });
      body.append(tr);
    });
    table.append(h("thead", {}, [head]), body);
  }

  function renderCalls() {
    const rows = state.calls.map((c) => [
      num(c.start, 3),
      c.from,
      c.to,
      c.reason ? `${c.state} (${c.reason})` : c.state,
      c.setup === null ? "" : num(c.setup, 3),
      c.duration === null ? "" : lib.formatDuration(c.duration),
      c.streams.length,
      c.messages.length,
    ]);
    fillTable(
      callsTable,
      ["Start (s)", "From", "To", "State", "Setup (s)", "Duration", "Streams", "Messages"],
      ["Start (s)", "Setup (s)", "Streams", "Messages"],
      rows,
      state.call,
      selectCall,
    );
    if (!state.calls.length) {
      callsTable.append(h("caption", {}, ["No SIP calls in this capture."]));
    }
    filterCall.toggleAttribute("disabled", state.call === null);
  }

  function renderStreams() {
    const call = state.call !== null ? state.calls[state.call] : null;
    const rows = state.streams.map((st) => [
      `${st.src}:${st.srcPort}`,
      `${st.dst}:${st.dstPort}`,
      st.ssrc,
      st.payload,
      st.packets,
      st.lost > 0 ? `${st.lost} (${num(st.lostPercent, 1)}%)` : st.lost,
      num(st.maxDelta),
      num(st.maxJitter),
      num(st.meanJitter),
      st.problem ? "⚠" : "",
    ]);
    fillTable(
      streamsTable,
      [
        "Source",
        "Destination",
        "SSRC",
        "Payload",
        "Packets",
        "Lost",
        "Max Delta (ms)",
        "Max Jitter (ms)",
        "Mean Jitter (ms)",
        "Problem",
      ],
      ["Packets", "Lost", "Max Delta (ms)", "Max Jitter (ms)", "Mean Jitter (ms)"],
      rows,
      state.stream,
      selectStream,
      new Set(call ? call.streams : []),
    );
    if (!state.streams.length) {
      streamsTable.append(
        h("caption", {}, [
          state.heuristic
            ? "No RTP streams found."
            : "No RTP streams set up by SIP/SDP. Try “Find RTP without signalling”.",
        ]),
      );
    }
    for (const b of [analyse, play, save, filterStream]) {
      b.toggleAttribute("disabled", state.stream === null);
    }
  }

  /** @param {number} i */
  function selectCall(i) {
    state.call = i;
    renderCalls();
    renderStreams();
    renderFlow();
    /** @type {HTMLElement | null} */ (callsTable.querySelector("tr.selected"))?.focus();
  }

  /** @param {number} i */
  function selectStream(i) {
    if (state.stream !== i) {
      state.analysis = null;
      analysisBox.classList.add("hidden");
      audio.classList.add("hidden");
      audio.removeAttribute("src");
      audioNote.textContent = "";
    }
    state.stream = i;
    renderStreams();
    /** @type {HTMLElement | null} */ (streamsTable.querySelector("tr.selected"))?.focus();
  }

  // ------------------------------------------------------------------ call flow

  function renderFlow() {
    flow.replaceChildren();
    const call = state.call !== null ? state.calls[state.call] : null;
    if (!call) {
      return;
    }
    const { nodes, rows } = lib.callFlow(call, state.streams);
    const width = FLOW.gutter + nodes.length * FLOW.column;
    const height = FLOW.top + rows.length * FLOW.row + 8;
    const svg = s("svg", {
      width,
      height,
      role: "img",
      "aria-label": `Call flow of ${call.from} to ${call.to}`,
    });
    nodes.forEach((/** @type {string} */ addr, /** @type {number} */ i) => {
      const x = FLOW.gutter + (i + 0.5) * FLOW.column;
      svg.append(
        s("text", { x, y: 16, class: "flow-label middle voip-node" }, addr),
        s("line", { x1: x, x2: x, y1: FLOW.top - 6, y2: height, class: "flow-life" }),
      );
    });
    rows.forEach((/** @type {any} */ row, /** @type {number} */ i) => {
      const y = FLOW.top + i * FLOW.row;
      const { x1, x2 } = lib.flowArrow(row.from, row.to, nodes.length, FLOW);
      const rtp = row.stream !== undefined;
      const g = s("g", {
        class: `flow-row${rtp ? " voip-rtp" : ""}`,
        tabindex: "0",
        role: "button",
        "aria-label": `${num(row.time)} s ${row.label}`,
      });
      g.append(
        s("rect", { x: 0, y, width, height: FLOW.row, class: "flow-bg" }),
        s("text", { x: 6, y: y + 17, class: "flow-time" }, num(row.time)),
        s(
          "text",
          { x: (x1 + x2) / 2, y: y + 11, class: "flow-label middle" },
          lib.truncate(row.label, 34),
        ),
        s("line", { x1, x2, y1: y + 18, y2: y + 18, class: `flow-arrow${rtp ? " rtp" : ""}` }),
      );
      const dir = x2 >= x1 ? 1 : -1;
      g.append(
        s("path", {
          d: `M${x2},${y + 18} l${-7 * dir},-4 v8 z`,
          class: `flow-head${rtp ? " rtp" : ""}`,
        }),
      );
      const activate = () => {
        if (rtp) {
          selectStream(row.stream);
        } else {
          vscode.postMessage({ type: "goto", frame: row.frame });
        }
      };
      g.addEventListener("click", activate);
      g.addEventListener("keydown", (e) => {
        if (/** @type {KeyboardEvent} */ (e).key === "Enter") {
          activate();
        }
      });
      svg.append(g);
    });
    flow.append(svg);
  }

  // ------------------------------------------------------------------ analysis

  function renderAnalysis() {
    const a = state.analysis;
    analysisBox.replaceChildren();
    if (!a) {
      analysisBox.classList.add("hidden");
      return;
    }
    const sum = a.summary;
    analysisBox.classList.remove("hidden");
    const facts = [
      `${sum.packets.toLocaleString()} of ${sum.expected.toLocaleString()} packets`,
      `${sum.lost.toLocaleString()} lost (${num(sum.lostPercent, 1)}%)`,
      `max delta ${num(sum.maxDelta)} ms (packet ${sum.maxDeltaFrame})`,
      `max jitter ${num(sum.maxJitter)} ms`,
      `mean jitter ${num(sum.meanJitter)} ms`,
      `max skew ${num(sum.maxSkew)} ms`,
      `${sum.sequenceErrors} sequence error${sum.sequenceErrors === 1 ? "" : "s"}`,
    ];
    analysisBox.append(
      h("h2", { class: "panel-subtitle-h" }, ["Stream Analysis"]),
      h("div", { class: "status", id: "voip-summary" }, [facts.join(" · ")]),
      jitterChart(a.points),
    );
    const problems = lib.rtpProblems(a.points);
    if (problems.length) {
      const ul = h("ul", { class: "voip-problems", id: "voip-problems" });
      for (const p of problems) {
        const link = h("button", { type: "button", class: "link" }, [`Packet ${p.frame}`]);
        link.addEventListener("click", () => vscode.postMessage({ type: "goto", frame: p.frame }));
        ul.append(h("li", {}, [link, `: ${p.text}`]));
      }
      analysisBox.append(ul);
    } else {
      analysisBox.append(h("div", { class: "status" }, ["No sequence errors."]));
    }
  }

  /** Jitter (ms) over time, problem packets marked. @param {any[][]} points */
  function jitterChart(points) {
    const box = h("div", { class: "chart", "aria-label": "Jitter over time" });
    const width = Math.max(320, analysisBox.clientWidth || app.clientWidth - 30);
    const plotW = width - CHART.left - CHART.right;
    const plotH = CHART.height - CHART.top - CHART.bottom;
    const svg = s("svg", {
      width,
      height: CHART.height,
      role: "img",
      "aria-label": "Jitter (ms) over time (s)",
    });
    const xs = points.map((p) => p[lib.RP.time]);
    const ys = points.map((p) => p[lib.RP.jitter]);
    const xt = lib.niceRange(0, Math.max(0.001, ...xs));
    const yt = lib.niceTicks(Math.max(0.1, ...ys));
    const xMax = xt[xt.length - 1];
    const yMax = yt[yt.length - 1];
    const X = (/** @type {number} */ v) => CHART.left + (v / (xMax || 1)) * plotW;
    const Y = (/** @type {number} */ v) => CHART.top + plotH - (v / (yMax || 1)) * plotH;
    for (const t of yt) {
      svg.append(
        s("line", { x1: CHART.left, x2: CHART.left + plotW, y1: Y(t), y2: Y(t), class: "grid" }),
        s(
          "text",
          { x: CHART.left - 6, y: Y(t) + 4, class: "axis-label", "text-anchor": "end" },
          lib.formatCell(t),
        ),
      );
    }
    for (const t of xt) {
      svg.append(
        s(
          "text",
          { x: X(t), y: CHART.top + plotH + 16, class: "axis-label", "text-anchor": "middle" },
          lib.formatCell(t),
        ),
      );
    }
    svg.append(
      s(
        "text",
        {
          x: CHART.left + plotW / 2,
          y: CHART.height - 4,
          class: "axis-label",
          "text-anchor": "middle",
        },
        "Time (s)",
      ),
      s(
        "text",
        {
          x: 12,
          y: CHART.top + plotH / 2,
          class: "axis-label",
          "text-anchor": "middle",
          transform: `rotate(-90 12 ${CHART.top + plotH / 2})`,
        },
        "Jitter (ms)",
      ),
    );
    if (points.length) {
      const step = Math.max(1, Math.ceil(points.length / 4000));
      let d = "";
      for (let i = 0; i < points.length; i += step) {
        d += `${d ? "L" : "M"}${X(xs[i]).toFixed(1)},${Y(ys[i]).toFixed(1)}`;
      }
      svg.append(s("path", { d, class: "series-line" }));
      for (const p of points) {
        if (p[lib.RP.status] !== 0) {
          const dot = s("circle", {
            cx: X(p[lib.RP.time]),
            cy: Y(p[lib.RP.jitter]),
            r: 3.5,
            class: "dot retrans",
          });
          const tip = s("title", {}, `Packet ${p[lib.RP.frame]}`);
          dot.append(tip);
          svg.append(dot);
        }
      }
    }
    box.append(svg);
    return box;
  }

  // ------------------------------------------------------------------ messages

  window.addEventListener("message", (event) => {
    const msg = event.data;
    switch (msg.type) {
      case "init":
        title.textContent = msg.title;
        list();
        return;
      case "calls": {
        state.listing = false;
        state.calls = msg.calls;
        state.streams = msg.streams;
        state.call = state.calls.length ? 0 : null;
        state.stream = null;
        state.analysis = null;
        status.textContent = `${msg.calls.length} SIP call${msg.calls.length === 1 ? "" : "s"}, ${msg.streams.length} RTP stream${msg.streams.length === 1 ? "" : "s"}`;
        renderCalls();
        renderStreams();
        renderFlow();
        renderAnalysis();
        audio.classList.add("hidden");
        return;
      }
      case "analysis":
        if (msg.id === state.requestId) {
          audioNote.textContent = "";
          state.analysis = msg.result;
          renderAnalysis();
        }
        return;
      case "audio":
        if (msg.id === state.requestId) {
          const lost =
            msg.silence > 0 ? `, ${num(msg.silence, 2)} s of silence for lost packets` : "";
          audioNote.textContent = `${msg.codec}, ${num(msg.seconds, 1)} s${lost}`;
          audio.src = msg.uri;
          audio.classList.remove("hidden");
          void audio.play().catch(() => undefined);
        }
        return;
      case "error":
        if (msg.id !== undefined && msg.id !== state.requestId) {
          return;
        }
        state.listing = false;
        status.textContent = "";
        audioNote.textContent = "";
        if (!msg.cancelled) {
          notice.textContent = msg.unsupported
            ? `${msg.message}. Use Save Audio… to save the raw payload instead.`
            : msg.message;
          notice.classList.remove("hidden");
        }
        return;
    }
  });

  renderCalls();
  renderStreams();
  vscode.postMessage({ type: "ready" });
})();
