// @ts-check
/**
 * Export Objects panel: the files carried by HTTP, SMB, TFTP, IMF, DICOM and
 * FTP-DATA, as listed by the backend. Filter by protocol and text, sort, go to
 * the packet, save one or all shown (the host saves them: file contents never
 * reach this page). Names come from the capture, so they only go through
 * textContent.
 */
(function () {
  "use strict";

  const vscode = acquireVsCodeApi();
  /** @type {any} */
  const lib = /** @type {any} */ (window).PcapLib;

  const PROTOCOL_LABELS = {
    http: "HTTP",
    smb: "SMB",
    tftp: "TFTP",
    imf: "IMF",
    dicom: "DICOM",
    "ftp-data": "FTP-DATA",
  };
  const COLUMNS = [
    { id: "frame", label: "Packet", numeric: true },
    { id: "protocol", label: "Protocol", numeric: false },
    { id: "host", label: "Host", numeric: false },
    { id: "contentType", label: "Content Type", numeric: false },
    { id: "size", label: "Size", numeric: true },
    { id: "name", label: "File Name", numeric: false },
  ];

  /**
   * @typedef {{id: number, protocol: string, name: string, size: number, frame: number | null, host: string, contentType: string}} Obj
   */
  const state = {
    /** @type {Obj[] | null} */ objects: null,
    protocol: "",
    text: "",
    /** @type {{col: number, desc: boolean} | null} */ sort: null,
    /** @type {number | null} */ selected: null,
    loading: false,
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

  const title = h("h1", { class: "panel-title" }, ["Export Objects"]);
  const protocolSelect = /** @type {HTMLSelectElement} */ (
    h("select", { id: "objects-protocol", "aria-label": "Protocol" })
  );
  const textInput = /** @type {HTMLInputElement} */ (
    h("input", {
      id: "objects-text",
      type: "search",
      placeholder: "Filter by name, host or type",
      "aria-label": "Text filter",
    })
  );
  const refreshBtn = h("button", { type: "button", class: "secondary" }, ["Refresh"]);
  const toolbar = h("div", { class: "toolbar", role: "toolbar" }, [
    h("label", {}, ["Protocol ", protocolSelect]),
    textInput,
    h("span", { class: "spacer" }),
    refreshBtn,
  ]);
  const saveBtn = h(
    "button",
    { type: "button", id: "objects-save", title: "Save the selected object" },
    ["Save…"],
  );
  const saveAllBtn = h(
    "button",
    {
      type: "button",
      id: "objects-save-all",
      class: "secondary",
      title: "Save every object shown into a folder",
    },
    ["Save All…"],
  );
  const gotoBtn = h(
    "button",
    {
      type: "button",
      id: "objects-goto",
      class: "secondary",
      title: "Select the packet that carried the object",
    },
    ["Go to Packet"],
  );
  const actions = h("div", { class: "toolbar" }, [saveBtn, saveAllBtn, gotoBtn]);
  const statusText = h("span");
  const cancelBtn = h("button", { type: "button", class: "secondary hidden" }, ["Cancel"]);
  const status = h("div", { class: "status", role: "status" }, [statusText, " ", cancelBtn]);
  const notice = h("div", { class: "notice error hidden", role: "alert" });
  const tableBox = h("div");
  app.append(title, toolbar, actions, notice, status, tableBox);

  protocolSelect.addEventListener("change", () => {
    state.protocol = protocolSelect.value;
    render();
  });
  textInput.addEventListener("input", () => {
    state.text = textInput.value;
    render();
  });
  refreshBtn.addEventListener("click", () => {
    vscode.postMessage({ type: "list" });
    loading(null);
  });
  cancelBtn.addEventListener("click", () => vscode.postMessage({ type: "cancel" }));
  saveBtn.addEventListener("click", () => {
    if (state.selected !== null) {
      vscode.postMessage({ type: "save", id: state.selected });
    }
  });
  saveAllBtn.addEventListener("click", () => {
    const ids = shown().map((o) => o.id);
    if (ids.length) {
      vscode.postMessage({ type: "saveAll", ids });
    }
  });
  gotoBtn.addEventListener("click", () => gotoSelected());

  // ------------------------------------------------------------------ data

  /** @param {number | null} fraction */
  function loading(fraction) {
    state.loading = true;
    statusText.textContent =
      fraction === null
        ? "Extracting objects…"
        : `Extracting objects… ${Math.round(fraction * 100)}%`;
    cancelBtn.classList.remove("hidden");
    notice.classList.add("hidden");
    updateActions();
  }

  window.addEventListener("message", (event) => {
    const msg = event.data;
    if (msg.type === "init") {
      title.textContent = msg.title;
      loading(null);
    } else if (msg.type === "progress") {
      loading(msg.fraction);
    } else if (msg.type === "objects") {
      state.loading = false;
      state.objects = msg.objects;
      if (!state.objects?.some((o) => o.id === state.selected)) {
        state.selected = null;
      }
      cancelBtn.classList.add("hidden");
      buildProtocols();
      render();
    } else if (msg.type === "error") {
      state.loading = false;
      cancelBtn.classList.add("hidden");
      statusText.textContent = msg.cancelled ? "Cancelled." : "";
      if (!msg.cancelled) {
        notice.textContent = msg.message;
        notice.classList.remove("hidden");
      }
      updateActions();
    }
  });

  function buildProtocols() {
    const counts = new Map();
    for (const o of state.objects ?? []) {
      counts.set(o.protocol, (counts.get(o.protocol) ?? 0) + 1);
    }
    if (state.protocol && !counts.has(state.protocol)) {
      state.protocol = "";
    }
    protocolSelect.replaceChildren(
      h("option", { value: "" }, [`All (${state.objects?.length ?? 0})`]),
    );
    for (const [protocol, label] of Object.entries(PROTOCOL_LABELS)) {
      if (counts.has(protocol)) {
        const opt = h("option", { value: protocol }, [`${label} (${counts.get(protocol)})`]);
        protocolSelect.append(opt);
      }
    }
    protocolSelect.value = state.protocol;
  }

  /** @returns {Obj[]} */
  function shown() {
    return lib.filterObjects(state.objects ?? [], state.protocol, state.text);
  }

  /** @param {Obj} o */
  function cells(o) {
    return [
      o.frame ?? "",
      PROTOCOL_LABELS[/** @type {keyof typeof PROTOCOL_LABELS} */ (o.protocol)] ?? o.protocol,
      o.host,
      o.contentType,
      o.size,
      o.name,
    ];
  }

  // ------------------------------------------------------------------ table

  function render() {
    const all = state.objects ?? [];
    const rows = shown().map((o) => ({ o, cells: cells(o) }));
    const sorted = state.sort ? lib.sortRows(rows, state.sort.col, state.sort.desc) : rows;
    const bytes = rows.reduce((sum, r) => sum + r.o.size, 0);
    statusText.textContent = !all.length
      ? "No objects found. Export Objects finds files sent over HTTP, SMB, TFTP, IMF (mail), DICOM and FTP-DATA."
      : rows.length === all.length
        ? `${all.length.toLocaleString()} ${all.length === 1 ? "object" : "objects"}, ${lib.formatBytes(bytes)}`
        : `${rows.length.toLocaleString()} of ${all.length.toLocaleString()} objects shown, ${lib.formatBytes(bytes)}`;

    const headRow = h("tr");
    COLUMNS.forEach((col, i) => {
      const on = state.sort && state.sort.col === i;
      const th = h(
        "th",
        {
          class: col.numeric ? "num" : "",
          scope: "col",
          "aria-sort": on ? (state.sort?.desc ? "descending" : "ascending") : "none",
        },
        [col.label + (on ? (state.sort?.desc ? " ▼" : " ▲") : "")],
      );
      th.addEventListener("click", () => {
        state.sort =
          !state.sort || state.sort.col !== i
            ? { col: i, desc: col.numeric }
            : { col: i, desc: !state.sort.desc };
        render();
      });
      headRow.append(th);
    });
    const body = h("tbody");
    for (const row of sorted) {
      const tr = h("tr", { "data-id": String(row.o.id) });
      row.cells.forEach((value, i) => {
        const td = h("td", { class: COLUMNS[i].numeric ? "num" : "" });
        td.textContent = COLUMNS[i].id === "size" ? lib.formatBytes(Number(value)) : String(value);
        if (COLUMNS[i].id === "size") {
          td.title = `${Number(value).toLocaleString()} bytes`;
        }
        tr.append(td);
      });
      tr.classList.toggle("selected", row.o.id === state.selected);
      tr.addEventListener("click", () => select(row.o.id));
      tr.addEventListener("dblclick", () => {
        select(row.o.id);
        gotoSelected();
      });
      body.append(tr);
    }
    const table = h("table", { class: "stats", tabindex: "0", "aria-label": "Objects" }, [
      h("thead", {}, [headRow]),
      body,
    ]);
    table.addEventListener("keydown", (e) =>
      onKey(
        /** @type {KeyboardEvent} */ (e),
        sorted.map((r) => r.o.id),
      ),
    );
    tableBox.replaceChildren(all.length ? table : "");
    updateActions();
  }

  /** @param {number} id */
  function select(id) {
    state.selected = id;
    for (const tr of tableBox.querySelectorAll("tbody tr")) {
      tr.classList.toggle("selected", tr.getAttribute("data-id") === String(id));
    }
    tableBox.querySelector("tbody tr.selected")?.scrollIntoView({ block: "nearest" });
    updateActions();
  }

  /** @param {KeyboardEvent} e @param {number[]} order */
  function onKey(e, order) {
    if (!order.length) {
      return;
    }
    const at = state.selected === null ? -1 : order.indexOf(state.selected);
    if (e.key === "ArrowDown" || e.key === "ArrowUp") {
      e.preventDefault();
      const next =
        at < 0 ? 0 : Math.max(0, Math.min(order.length - 1, at + (e.key === "ArrowDown" ? 1 : -1)));
      select(order[next]);
    } else if (e.key === "Enter" && at >= 0) {
      e.preventDefault();
      gotoSelected();
    }
  }

  function selectedObject() {
    return (state.objects ?? []).find((o) => o.id === state.selected);
  }

  function gotoSelected() {
    const o = selectedObject();
    if (o && o.frame) {
      vscode.postMessage({ type: "goto", frame: o.frame });
    }
  }

  function updateActions() {
    const o = selectedObject();
    saveBtn.toggleAttribute("disabled", !o);
    gotoBtn.toggleAttribute("disabled", !o || !o.frame);
    const n = state.loading ? 0 : shown().length;
    saveAllBtn.toggleAttribute("disabled", !n);
    saveAllBtn.textContent =
      n && n !== (state.objects?.length ?? 0) ? `Save ${n} Shown…` : "Save All…";
    refreshBtn.toggleAttribute("disabled", state.loading);
  }

  updateActions();
  vscode.postMessage({ type: "ready" });
})();
