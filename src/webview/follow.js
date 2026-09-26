// @ts-check
/**
 * Follow-stream panel: the reassembled payload of one conversation, colored
 * by direction, with a direction filter, ASCII / hex dump / raw views,
 * stream stepping, "filter to this stream" and save. Payload is untrusted and
 * only ever inserted with textContent.
 */
(function () {
  "use strict";

  const vscode = acquireVsCodeApi();
  /** @type {any} */
  const lib = /** @type {any} */ (window).PcapLib;
  /** Characters rendered at most; the rest is available via "Save as…". */
  const RENDER_BUDGET = 2_000_000;

  const state = {
    /** @type {any} */ result: null,
    label: "",
    /** @type {"both" | 0 | 1} */ dir: "both",
    /** @type {"ascii" | "hex" | "raw"} */ format: "ascii",
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

  const title = h("h1", { class: "panel-title" }, ["Follow Stream"]);
  const legend = h("div", { class: "follow-legend" });
  const toolbar = h("div", { class: "toolbar", role: "toolbar" });
  const status = h("div", { class: "status", role: "status" }, ["Loading…"]);
  const notice = h("div", { class: "notice hidden", role: "alert" });
  const body = h("div", { class: "follow-body" });
  app.append(title, legend, toolbar, notice, status, body);

  const dirSelect = /** @type {HTMLSelectElement} */ (h("select", { "aria-label": "Direction" }));
  const formatSelect = /** @type {HTMLSelectElement} */ (h("select", { "aria-label": "Show data as" }));
  for (const [value, label] of [
    ["ascii", "ASCII"],
    ["hex", "Hex dump"],
    ["raw", "Raw (hex)"],
  ]) {
    formatSelect.append(h("option", { value }, [label]));
  }
  const streamInput = /** @type {HTMLInputElement} */ (h("input", { type: "number", min: "0", "aria-label": "Stream number" }));
  const prev = h("button", { type: "button", class: "secondary", title: "Previous stream" }, ["◀"]);
  const next = h("button", { type: "button", class: "secondary", title: "Next stream" }, ["▶"]);
  const filterBtn = h("button", { type: "button", title: "Apply a display filter for this stream in the capture" }, ["Filter to Stream"]);
  const saveBtn = h("button", { type: "button", class: "secondary" }, ["Save as…"]);
  toolbar.append(
    h("label", {}, ["Show ", dirSelect]),
    h("label", {}, ["as ", formatSelect]),
    h("label", {}, ["Stream ", streamInput]),
    prev,
    next,
    h("span", { class: "spacer" }),
    filterBtn,
    saveBtn,
  );

  dirSelect.addEventListener("change", () => {
    state.dir = dirSelect.value === "both" ? "both" : dirSelect.value === "0" ? 0 : 1;
    renderBody();
  });
  formatSelect.addEventListener("change", () => {
    state.format = /** @type {any} */ (formatSelect.value);
    renderBody();
  });
  /** @param {number} n */
  const goStream = (n) => {
    if (Number.isInteger(n) && n >= 0) {
      vscode.postMessage({ type: "stream", stream: n });
    }
  };
  streamInput.addEventListener("change", () => goStream(Number(streamInput.value)));
  prev.addEventListener("click", () => state.result && goStream(state.result.stream - 1));
  next.addEventListener("click", () => state.result && goStream(state.result.stream + 1));
  filterBtn.addEventListener("click", () => {
    if (state.result) {
      vscode.postMessage({ type: "filter", expr: lib.streamFilter(state.result.proto, state.result.stream), apply: true });
    }
  });
  saveBtn.addEventListener("click", () => {
    if (!state.result) {
      return;
    }
    const raw = state.format === "raw";
    vscode.postMessage({ type: "save", dir: state.dir, format: raw ? "raw" : "text", text: raw ? undefined : renderText(Infinity).text });
  });

  window.addEventListener("message", (event) => {
    const msg = event.data;
    if (msg.type === "loading") {
      status.textContent = "Running tshark…";
      notice.classList.add("hidden");
    } else if (msg.type === "error") {
      status.textContent = "";
      notice.textContent = msg.message;
      notice.classList.add("error");
      notice.classList.remove("hidden");
    } else if (msg.type === "result") {
      state.result = msg.result;
      state.label = msg.label;
      render();
    }
  });

  function render() {
    const r = state.result;
    const [a, b] = r.nodes;
    title.textContent = `${state.label} stream ${r.stream}`;
    streamInput.value = String(r.stream);
    prev.toggleAttribute("disabled", r.stream <= 0);
    const total = r.bytes[0] + r.bytes[1];
    dirSelect.replaceChildren(
      h("option", { value: "both" }, [`Entire conversation (${total.toLocaleString()} bytes)`]),
      h("option", { value: "0" }, [`${a} → ${b} (${r.bytes[0].toLocaleString()} bytes)`]),
      h("option", { value: "1" }, [`${b} → ${a} (${r.bytes[1].toLocaleString()} bytes)`]),
    );
    dirSelect.value = String(state.dir);
    // Identity is spelled out, not left to color alone.
    legend.replaceChildren(
      h("span", { class: "dir0" }, [h("span", { class: "key" }), `${a || "?"} → ${b || "?"}`]),
      h("span", { class: "dir1" }, [h("span", { class: "key" }), `${b || "?"} → ${a || "?"}`]),
    );
    const notes = [];
    if (r.truncated) {
      notes.push("The stream is larger than the transfer limit; only its beginning is shown.");
    }
    if (r.hint) {
      notes.push(r.hint);
    }
    notice.classList.remove("error");
    notice.textContent = notes.join(" ");
    notice.classList.toggle("hidden", !notes.length);
    renderBody();
  }

  /**
   * Text for the current direction/format, split into segments.
   * @param {number} budget maximum characters
   */
  function renderText(budget) {
    const r = state.result;
    const parts = [];
    const offsets = [0, 0];
    let used = 0;
    let clipped = false;
    for (const seg of r.segments) {
      if (state.dir !== "both" && seg.dir !== state.dir) {
        continue;
      }
      const bytes = lib.hexToBytes(seg.hex);
      let text =
        state.format === "ascii"
          ? lib.bytesToAscii(bytes)
          : state.format === "hex"
            ? lib.hexDump(bytes, offsets[seg.dir])
            : seg.hex.replace(/(.{64})/g, "$1\n").trimEnd();
      offsets[seg.dir] += bytes.length;
      if (used + text.length > budget) {
        text = text.slice(0, Math.max(0, budget - used));
        clipped = true;
      }
      used += text.length;
      parts.push({ dir: seg.dir, text });
      if (clipped) {
        break;
      }
    }
    return { parts, clipped, text: parts.map((p) => p.text).join(state.format === "ascii" ? "" : "\n") };
  }

  function renderBody() {
    if (!state.result) {
      return;
    }
    const { parts, clipped } = renderText(RENDER_BUDGET);
    const frag = document.createDocumentFragment();
    for (const p of parts) {
      const pre = h("pre", { class: `segment dir${p.dir}` });
      pre.textContent = p.text;
      frag.append(pre);
    }
    body.replaceChildren(frag);
    const r = state.result;
    const segs = r.segments.length;
    status.textContent = segs
      ? `${segs} ${segs === 1 ? "segment" : "segments"}${clipped ? ` · showing the first ${RENDER_BUDGET.toLocaleString()} characters (save to get everything)` : ""}`
      : "No payload in this stream.";
    saveBtn.toggleAttribute("disabled", !segs);
  }

  vscode.postMessage({ type: "ready" });
})();
