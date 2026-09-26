// @ts-check
/**
 * Pure helpers for the webview (no DOM access). Loaded as a classic script in
 * the webview (exposes `window.PcapLib`) and as a CommonJS module by the Node
 * unit tests in test/webview/.
 */
(function (root) {
  "use strict";

  /** Browsers cap element heights (~33M px in Chromium); stay well below. */
  const MAX_SCROLL_HEIGHT = 10_000_000;

  /**
   * Compute which rows to render for a virtualized list with fixed row height.
   * Above MAX_SCROLL_HEIGHT the scroll range is compressed: scroll position maps
   * proportionally to the first row and the rows are drawn at the viewport top.
   *
   * @param {{scrollTop: number, viewportHeight: number, total: number, rowHeight: number, maxScrollHeight?: number}} p
   * @returns {{first: number, count: number, top: number, virtualHeight: number, scaled: boolean}}
   */
  function computeWindow(p) {
    const max = p.maxScrollHeight ?? MAX_SCROLL_HEIGHT;
    const full = p.total * p.rowHeight;
    const scaled = full > max;
    const virtualHeight = scaled ? max : full;
    const visible = Math.ceil(p.viewportHeight / p.rowHeight) + 1;
    let first;
    let top;
    if (!scaled) {
      first = Math.max(0, Math.floor(p.scrollTop / p.rowHeight));
      top = first * p.rowHeight;
    } else {
      const maxFirst = Math.max(0, p.total - Math.floor(p.viewportHeight / p.rowHeight));
      const range = Math.max(1, virtualHeight - p.viewportHeight);
      first = Math.min(maxFirst, Math.floor((Math.max(0, p.scrollTop) / range) * maxFirst));
      top = Math.max(0, p.scrollTop);
    }
    first = Math.min(first, Math.max(0, p.total - 1));
    const count = Math.max(0, Math.min(visible, p.total - first));
    return { first, count, top, virtualHeight, scaled };
  }

  /**
   * Scroll position that makes row `index` visible (minimal movement), or the
   * current position if it already is.
   *
   * @param {{index: number, scrollTop: number, viewportHeight: number, total: number, rowHeight: number, maxScrollHeight?: number, center?: boolean}} p
   */
  function scrollTopForIndex(p) {
    const win = computeWindow(p);
    const fully = Math.max(1, Math.floor(p.viewportHeight / p.rowHeight));
    let targetFirst;
    if (p.center) {
      targetFirst = Math.max(0, p.index - Math.floor(fully / 2));
    } else if (p.index < win.first) {
      targetFirst = p.index;
    } else if (p.index >= win.first + fully) {
      targetFirst = p.index - fully + 1;
    } else if (!win.scaled && p.index === win.first && p.scrollTop > p.index * p.rowHeight) {
      targetFirst = p.index; // partially hidden at the top
    } else {
      return p.scrollTop;
    }
    if (!win.scaled) {
      if (!p.center && p.index >= win.first + fully) {
        return Math.max(0, (p.index + 1) * p.rowHeight - p.viewportHeight);
      }
      return targetFirst * p.rowHeight;
    }
    const maxFirst = Math.max(0, p.total - fully);
    const range = Math.max(1, win.virtualHeight - p.viewportHeight);
    targetFirst = Math.min(targetFirst, maxFirst);
    // Aim for the middle of the scroll band that maps to targetFirst.
    return maxFirst === 0 ? 0 : Math.min(range, ((targetFirst + 0.5) / maxFirst) * range);
  }

  /**
   * @param {number} first
   * @param {number} count
   * @param {number} pageSize
   * @param {number} total
   * @param {number} [prefetch] extra pages before/after
   */
  function pagesForRange(first, count, pageSize, total, prefetch = 0) {
    if (total <= 0) {
      return [];
    }
    const lastPage = Math.floor((total - 1) / pageSize);
    const start = Math.max(0, Math.floor(first / pageSize) - prefetch);
    const end = Math.min(lastPage, Math.floor(Math.max(first, first + count - 1) / pageSize) + prefetch);
    const pages = [];
    for (let p = start; p <= end; p++) {
      pages.push(p);
    }
    return pages;
  }

  /** Small LRU map for page caches. */
  class LruMap {
    /** @param {number} max */
    constructor(max) {
      this.max = max;
      /** @type {Map<any, any>} */
      this.map = new Map();
    }
    /** @param {any} key */
    get(key) {
      if (!this.map.has(key)) {
        return undefined;
      }
      const v = this.map.get(key);
      this.map.delete(key);
      this.map.set(key, v);
      return v;
    }
    /** @param {any} key @param {any} value */
    set(key, value) {
      this.map.delete(key);
      this.map.set(key, value);
      while (this.map.size > this.max) {
        const oldest = this.map.keys().next().value;
        this.map.delete(oldest);
      }
    }
    /** @param {any} key */
    has(key) {
      return this.map.has(key);
    }
    clear() {
      this.map.clear();
    }
    get size() {
      return this.map.size;
    }
  }

  const NUMBER_RE = /^-?\d+(\.\d+)?$/;
  const HEX_RE = /^0x[0-9a-fA-F]+$/;
  const IPV4_RE = /^\d{1,3}(\.\d{1,3}){3}(\/\d{1,2})?$/;
  const IPV6_RE = /^[0-9a-fA-F:]*:[0-9a-fA-F:.]*$/;
  const MAC_RE = /^[0-9a-fA-F]{2}([:\-.][0-9a-fA-F]{2}){2,}$/;

  /** Quote a string for a Wireshark display filter. @param {string} s */
  function quoteFilterString(s) {
    return '"' + s.replace(/\\/g, "\\\\").replace(/"/g, '\\"') + '"';
  }

  /**
   * Build a display filter matching a detail-tree node, like Wireshark's
   * "Apply as Filter". Returns null for nodes that can't be filtered on.
   *
   * @param {{name?: string, show?: string, proto?: boolean}} node
   * @returns {string | null}
   */
  function buildFieldFilter(node) {
    const name = node.name;
    if (!name || !/^[A-Za-z0-9_][A-Za-z0-9_.-]*$/.test(name) || name === "fake-field-wrapper") {
      return null;
    }
    const show = node.show;
    if (node.proto || show === undefined || show === "") {
      return name;
    }
    if (show === "True" || show === "False") {
      return `${name} == ${show === "True" ? 1 : 0}`;
    }
    if (NUMBER_RE.test(show) || HEX_RE.test(show) || IPV4_RE.test(show) || MAC_RE.test(show) || (show.includes(":") && IPV6_RE.test(show))) {
      return `${name} == ${show}`;
    }
    return `${name} == ${quoteFilterString(show)}`;
  }

  /**
   * Combine an existing filter with a new term (Wireshark "…and Selected" etc).
   * @param {string} current @param {string} term @param {"replace"|"and"|"or"|"not"} op
   */
  function combineFilter(current, term, op) {
    const cur = current.trim();
    if (op === "replace" || !cur) {
      return op === "not" ? `!(${term})` : term;
    }
    if (op === "and") {
      return `(${cur}) && (${term})`;
    }
    if (op === "or") {
      return `(${cur}) || (${term})`;
    }
    return `(${cur}) && !(${term})`;
  }

  /**
   * @typedef {{id: number, label: string, name?: string, show?: string, pos?: number, size?: number, src: number, children?: TreeNode[]}} TreeNode
   */

  /**
   * Path (root → node) to the deepest, smallest node whose byte range in
   * source `src` contains `offset`; null if none does.
   *
   * @param {TreeNode[]} tree @param {number} src @param {number} offset
   * @returns {TreeNode[] | null}
   */
  function findNodeForByte(tree, src, offset) {
    /** @type {TreeNode[] | null} */
    let best = null;
    let bestSize = Infinity;
    /** @param {TreeNode[]} nodes @param {TreeNode[]} path */
    function walk(nodes, path) {
      for (const n of nodes) {
        const here = [...path, n];
        const hit = n.src === src && n.pos !== undefined && n.size !== undefined && offset >= n.pos && offset < n.pos + n.size;
        if (hit && (n.size ?? Infinity) <= bestSize) {
          best = here;
          bestSize = n.size ?? Infinity;
        }
        if (n.children) {
          walk(n.children, here);
        }
      }
    }
    walk(tree, []);
    return best;
  }

  /** Stable key for remembering expanded nodes across packets. @param {TreeNode[]} path */
  function nodeKey(path) {
    return path.map((n) => n.name || n.label.replace(/\d+/g, "#")).join("/");
  }

  /** @param {string} hex */
  function hexToBytes(hex) {
    const out = new Uint8Array(hex.length >> 1);
    for (let i = 0; i < out.length; i++) {
      out[i] = parseInt(hex.substr(i * 2, 2), 16);
    }
    return out;
  }

  /** Printable ASCII for the hex pane. @param {number} b */
  function asciiChar(b) {
    return b >= 0x20 && b < 0x7f ? String.fromCharCode(b) : ".";
  }

  /** @param {number} offset @param {number} length total bytes (sets width) */
  function formatOffset(offset, length) {
    const width = length > 0xffff ? 8 : 4;
    return offset.toString(16).padStart(width, "0");
  }

  /** "0.001000000" -> "0.001000" (Wireshark's default precision). @param {string} s */
  function formatRelativeTime(s) {
    const n = Number(s);
    return s === "" || !Number.isFinite(n) ? s : n.toFixed(6);
  }

  /** @param {number} bytes */
  function formatBytes(bytes) {
    const units = ["B", "KB", "MB", "GB", "TB"];
    let v = bytes;
    let u = 0;
    while (v >= 1024 && u < units.length - 1) {
      v /= 1024;
      u++;
    }
    return `${u === 0 ? v : v.toFixed(1)} ${units[u]}`;
  }

  const api = {
    MAX_SCROLL_HEIGHT,
    computeWindow,
    scrollTopForIndex,
    pagesForRange,
    LruMap,
    quoteFilterString,
    buildFieldFilter,
    combineFilter,
    findNodeForByte,
    nodeKey,
    hexToBytes,
    asciiChar,
    formatOffset,
    formatRelativeTime,
    formatBytes,
  };

  if (typeof module === "object" && module.exports) {
    module.exports = api;
  } else {
    root.PcapLib = api;
  }
})(typeof window !== "undefined" ? window : globalThis);
