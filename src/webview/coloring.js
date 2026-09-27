// @ts-check
/**
 * Coloring rules editor: one row per rule (order = priority, the first match
 * wins), with enable, name, filter, text and row colors, a sample, reorder and
 * remove. Filters are checked by tshark as you type (via the host). Saving
 * writes pcapViewer.coloringRules. Rule text only goes through textContent /
 * input values; colors are set through the style API (the CSP allows no
 * inline styles).
 */
(function () {
  "use strict";

  const vscode = acquireVsCodeApi();
  const VALIDATE_DELAY_MS = 300;

  /**
   * @typedef {{name: string, filter: string, foreground: string, background: string, enabled: boolean}} Rule
   * @typedef {Rule & {id: number}} Row
   */
  const state = {
    /** @type {Row[]} */ rows: [],
    /** @type {Rule[]} */ defaults: [],
    /** JSON of the rules as last saved or loaded: dirty when it differs. */
    saved: "[]",
    canValidate: false,
    /** Rule id → tshark's error (null: valid; absent: unchecked). */
    /** @type {Map<number, string | null>} */ errors: new Map(),
    /** @type {Map<number, number>} */ timers: new Map(),
    nextId: 1,
    /** The setting changed elsewhere while there were unsaved edits. */
    changedElsewhere: false,
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

  /** @param {Rule[]} rules @returns {Row[]} */
  function toRows(rules) {
    return rules.map((r) => ({ ...r, id: state.nextId++ }));
  }

  /** @returns {Rule[]} */
  function currentRules() {
    return state.rows.map(({ name, filter, foreground, background, enabled }) => ({ name, filter, foreground, background, enabled }));
  }

  const isDirty = () => JSON.stringify(currentRules()) !== state.saved;

  /** Rules as the setting stores them (an empty name becomes the filter), to compare. @param {Rule[]} rules */
  const stored = (rules) =>
    JSON.stringify(
      rules.map((r) => ({
        name: r.name.trim() || r.filter.trim(),
        filter: r.filter.trim(),
        foreground: r.foreground.toLowerCase(),
        background: r.background.toLowerCase(),
        enabled: r.enabled,
      })),
    );

  /** Problems that block saving (the backend rejects these rules). @param {Row} row */
  function blocking(row) {
    if (!row.filter.trim()) {
      return "Enter a display filter";
    }
    if (row.filter.includes("@")) {
      return "Coloring rule filters cannot contain '@'";
    }
    return undefined;
  }

  /** @param {Rule[]} rules */
  function load(rules) {
    for (const t of state.timers.values()) {
      window.clearTimeout(t);
    }
    state.timers.clear();
    state.errors.clear();
    state.rows = toRows(rules);
    state.saved = JSON.stringify(currentRules());
    state.changedElsewhere = false;
    render();
    state.rows.forEach((row) => validate(row, 0));
  }

  /** Ask tshark whether the rule's filter compiles (debounced). @param {Row} row @param {number} delay */
  function validate(row, delay = VALIDATE_DELAY_MS) {
    window.clearTimeout(state.timers.get(row.id));
    state.errors.delete(row.id);
    if (!state.canValidate || blocking(row)) {
      return;
    }
    state.timers.set(
      row.id,
      window.setTimeout(() => {
        state.timers.delete(row.id);
        vscode.postMessage({ type: "validate", id: row.id, filter: row.filter });
      }, delay),
    );
  }

  // ------------------------------------------------------------------ rendering

  const tbody = h("tbody");
  const saveButton = /** @type {HTMLButtonElement} */ (h("button", { type: "button" }, ["Save"]));
  const revertButton = /** @type {HTMLButtonElement} */ (h("button", { type: "button", class: "secondary" }, ["Revert"]));
  const statusLine = h("span", { class: "status", role: "status" });

  function render() {
    tbody.replaceChildren(...state.rows.map((row, i) => renderRow(row, i)));
    if (!state.rows.length) {
      tbody.append(h("tr", {}, [h("td", { colspan: "7", class: "empty-rules" }, ["No coloring rules. Add one, or restore the defaults."])]));
    }
    updateStatus();
  }

  /** @param {Row} row @param {number} index */
  function renderRow(row, index) {
    const tr = h("tr", { "data-id": String(row.id) });
    tr.classList.toggle("disabled", !row.enabled);

    const enabled = /** @type {HTMLInputElement} */ (h("input", { type: "checkbox", "aria-label": `Enable rule ${index + 1}` }));
    enabled.checked = row.enabled;
    enabled.addEventListener("change", () => {
      row.enabled = enabled.checked;
      tr.classList.toggle("disabled", !row.enabled);
      updateStatus();
    });

    const name = /** @type {HTMLInputElement} */ (h("input", { type: "text", class: "rule-name", "aria-label": "Name", placeholder: "Name" }));
    name.value = row.name;
    name.addEventListener("input", () => {
      row.name = name.value;
      sample.textContent = row.name.trim() || row.filter.trim() || "Sample packet";
      updateStatus();
    });

    const filter = /** @type {HTMLInputElement} */ (h("input", { type: "text", class: "rule-filter", "aria-label": "Display filter", placeholder: "Display filter", spellcheck: "false" }));
    filter.value = row.filter;
    const problem = h("div", { class: "rule-problem" });
    filter.addEventListener("input", () => {
      row.filter = filter.value;
      if (!row.name.trim()) {
        sample.textContent = row.filter.trim() || "Sample packet";
      }
      validate(row);
      showProblem(row, filter, problem);
      updateStatus();
    });

    const sample = h("div", { class: "rule-sample" }, [row.name.trim() || row.filter.trim() || "Sample packet"]);
    const paint = () => {
      sample.style.color = row.foreground;
      sample.style.backgroundColor = row.background;
    };
    paint();
    /** @param {"foreground" | "background"} key @param {string} label */
    const colorInput = (key, label) => {
      const input = /** @type {HTMLInputElement} */ (h("input", { type: "color", "aria-label": label, title: label }));
      input.value = row[key];
      input.addEventListener("input", () => {
        row[key] = input.value;
        paint();
        updateStatus();
      });
      return input;
    };

    const button = (/** @type {string} */ text, /** @type {string} */ label, /** @type {() => void} */ action, disabled = false) => {
      const b = /** @type {HTMLButtonElement} */ (h("button", { type: "button", class: "icon", "aria-label": label, title: label }, [text]));
      b.disabled = disabled;
      b.addEventListener("click", action);
      return b;
    };

    tr.append(
      h("td", { class: "rule-enabled" }, [enabled]),
      h("td", {}, [name]),
      h("td", { class: "rule-filter-cell" }, [filter, problem]),
      h("td", { class: "rule-colors" }, [colorInput("foreground", "Text color"), colorInput("background", "Row color")]),
      h("td", {}, [sample]),
      h("td", { class: "rule-actions" }, [
        button("↑", "Move up (Alt+↑)", () => move(index, -1), index === 0),
        button("↓", "Move down (Alt+↓)", () => move(index, 1), index === state.rows.length - 1),
        button("✕", "Remove rule", () => remove(index)),
      ]),
    );
    tr.addEventListener("keydown", (e) => {
      if (e.altKey && (e.key === "ArrowUp" || e.key === "ArrowDown")) {
        e.preventDefault();
        move(index, e.key === "ArrowUp" ? -1 : 1, /** @type {HTMLElement} */ (e.target));
      }
    });
    showProblem(row, filter, problem);
    return tr;
  }

  /** @param {Row} row @param {HTMLInputElement} input @param {HTMLElement} problem */
  function showProblem(row, input, problem) {
    const message = blocking(row) ?? state.errors.get(row.id) ?? "";
    input.classList.toggle("invalid", !!message);
    input.setAttribute("aria-invalid", String(!!message));
    problem.textContent = message;
  }

  function updateStatus() {
    const dirty = isDirty();
    const blocked = state.rows.some((r) => blocking(r));
    saveButton.disabled = !dirty || blocked;
    revertButton.disabled = !dirty;
    const parts = [`${state.rows.length} rule${state.rows.length === 1 ? "" : "s"}, ${state.rows.filter((r) => r.enabled).length} enabled`];
    if (state.changedElsewhere) {
      parts.push("the rules changed in settings: Revert loads them");
    } else if (blocked) {
      parts.push("fix the marked filters to save");
    } else if (dirty) {
      parts.push("unsaved changes");
    }
    if (!state.canValidate) {
      parts.push("open a capture to check filters with tshark");
    }
    statusLine.textContent = parts.join(" · ");
  }

  // ------------------------------------------------------------------ editing

  /** @param {number} index @param {number} delta @param {HTMLElement} [focus] */
  function move(index, delta, focus) {
    const to = index + delta;
    if (to < 0 || to >= state.rows.length) {
      return;
    }
    const [row] = state.rows.splice(index, 1);
    state.rows.splice(to, 0, row);
    render();
    // Keep focus on the same control of the moved row (keyboard reordering).
    const cls = focus?.className.split(" ").find((c) => c.startsWith("rule-"));
    const target = /** @type {HTMLElement | null} */ (tbody.querySelector(`tr[data-id="${row.id}"] ${cls ? `.${cls}` : "input"}`));
    target?.focus();
  }

  /** @param {number} index */
  function remove(index) {
    const [row] = state.rows.splice(index, 1);
    window.clearTimeout(state.timers.get(row.id));
    state.errors.delete(row.id);
    render();
  }

  function add() {
    const row = { name: "", filter: "", foreground: "#000000", background: "#fff3b0", enabled: true, id: state.nextId++ };
    state.rows.unshift(row); // on top: it wins
    render();
    /** @type {HTMLElement | null} */ (tbody.querySelector(`tr[data-id="${row.id}"] .rule-filter`))?.focus();
  }

  // ------------------------------------------------------------------ layout

  const addButton = h("button", { type: "button" }, ["Add Rule"]);
  addButton.addEventListener("click", add);
  saveButton.addEventListener("click", () => vscode.postMessage({ type: "save", rules: currentRules() }));
  revertButton.addEventListener("click", () => vscode.postMessage({ type: "ready" }));
  const defaultsButton = h("button", { type: "button", class: "secondary" }, ["Restore Defaults"]);
  defaultsButton.addEventListener("click", () => {
    state.rows = toRows(state.defaults);
    state.errors.clear();
    render();
    state.rows.forEach((row) => validate(row, 0));
  });
  const settingsButton = h("button", { type: "button", class: "secondary" }, ["Open settings.json"]);
  settingsButton.addEventListener("click", () => vscode.postMessage({ type: "openSettings" }));

  app.append(
    h("h1", { class: "panel-title" }, ["Coloring Rules"]),
    h("div", { class: "panel-subtitle" }, ["The first matching rule colors a packet. Alt+↑ / Alt+↓ reorder a rule."]),
    h("div", { class: "toolbar" }, [addButton, saveButton, revertButton, h("span", { class: "spacer" }), defaultsButton, settingsButton]),
    statusLine,
    h("table", { class: "stats rules" }, [
      h("thead", {}, [
        h("tr", {}, [h("th", {}, ["On"]), h("th", {}, ["Name"]), h("th", {}, ["Filter"]), h("th", {}, ["Colors"]), h("th", {}, ["Sample"]), h("th", {}, [""])]),
      ]),
      tbody,
    ]),
  );

  window.addEventListener("message", (event) => {
    const msg = event.data;
    switch (msg?.type) {
      case "init":
        state.defaults = msg.defaults ?? [];
        state.canValidate = !!msg.canValidate;
        load(msg.rules ?? []);
        break;
      case "rules":
        // Saved here, or edited elsewhere (settings.json, Colorize with Filter).
        if (!isDirty()) {
          load(msg.rules ?? []);
        } else if (stored(msg.rules ?? []) !== stored(currentRules())) {
          state.changedElsewhere = true;
          updateStatus();
        }
        break;
      case "validation": {
        const row = state.rows.find((r) => r.id === msg.id);
        if (!row || row.filter !== msg.filter || msg.error === undefined) {
          return; // edited since, removed, or nobody to ask
        }
        state.errors.set(row.id, msg.error);
        const tr = tbody.querySelector(`tr[data-id="${row.id}"]`);
        const input = /** @type {HTMLInputElement | null} */ (tr?.querySelector(".rule-filter") ?? null);
        const problem = /** @type {HTMLElement | null} */ (tr?.querySelector(".rule-problem") ?? null);
        if (input && problem) {
          showProblem(row, input, problem);
        }
        break;
      }
      case "saved":
        load(msg.rules ?? currentRules()); // what the setting now holds
        break;
    }
  });

  vscode.postMessage({ type: "ready" });
})();
