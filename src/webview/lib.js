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

  // ---------------------------------------------------------------- autocomplete

  /** Comparison operators offered after a field name. */
  const COMPARISON_OPERATORS = [
    { label: "==", desc: "Equal" },
    { label: "!=", desc: "Not equal" },
    { label: ">", desc: "Greater than" },
    { label: "<", desc: "Less than" },
    { label: ">=", desc: "Greater than or equal" },
    { label: "<=", desc: "Less than or equal" },
    { label: "contains", desc: "Protocol, field or slice contains a value" },
    { label: "matches", desc: "Matches a case-insensitive Perl-compatible regular expression" },
    { label: "in", desc: "Membership, e.g. tcp.port in {80 443 8080}" },
    { label: "&&", desc: "Logical AND (the field just has to be present)" },
    { label: "||", desc: "Logical OR (the field just has to be present)" },
    { label: "and", desc: "Logical AND (the field just has to be present)" },
    { label: "or", desc: "Logical OR (the field just has to be present)" },
  ];

  /** Logical operators offered after a complete comparison. */
  const LOGICAL_OPERATORS = [
    { label: "&&", desc: "Logical AND" },
    { label: "||", desc: "Logical OR" },
    { label: "and", desc: "Logical AND" },
    { label: "or", desc: "Logical OR" },
    { label: "^^", desc: "Logical XOR" },
  ];

  const WORD_CHARS = /[A-Za-z0-9_.-]/;
  const LOGICAL_WORDS = new Set(["and", "or", "not", "xor", "&&", "||", "!", "^^", "("]);
  const COMPARISON_WORDS = new Set(["==", "!=", ">", "<", ">=", "<=", "eq", "ne", "gt", "lt", "ge", "le", "contains", "matches", "in", "~", "===", "!==", "~="]);

  /**
   * Work out what can be completed at `cursor` in a display filter.
   *
   * - `field`: the cursor is in (or starting) a field/protocol name
   * - `operator`: after a field name, a comparison operator is expected
   * - `logical`: after a complete comparison, `&&`/`||` is expected
   * - `none`: inside a string, a value, or anything else
   *
   * `start`/`end` delimit the word under the cursor, which a completion replaces.
   *
   * @param {string} text @param {number} cursor
   * @returns {{kind: "field" | "operator" | "logical" | "none", prefix: string, start: number, end: number}}
   */
  function completionContext(text, cursor) {
    const before = text.slice(0, cursor);
    let start = cursor;
    while (start > 0 && WORD_CHARS.test(before[start - 1])) {
      start--;
    }
    let end = cursor;
    while (end < text.length && WORD_CHARS.test(text[end])) {
      end++;
    }
    const prefix = text.slice(start, cursor);
    const none = { kind: /** @type {const} */ ("none"), prefix, start, end };
    if (insideString(before)) {
      return none;
    }
    const prev = previousToken(before.slice(0, start));
    const prevIsValue = prev !== null && (/^["\d]/.test(prev) || prev === ")" || prev.startsWith("{") || /^[0-9a-f]{2}([:.-][0-9a-f]{2})+$/i.test(prev));
    if (prev === null || LOGICAL_WORDS.has(prev.toLowerCase())) {
      // Start of an expression: a field or protocol name, unless a value is being typed.
      return /^\d/.test(prefix) ? none : { kind: "field", prefix, start, end };
    }
    if (COMPARISON_WORDS.has(prev.toLowerCase())) {
      return none; // a value is expected here
    }
    if (prevIsValue) {
      return { kind: "logical", prefix, start, end };
    }
    // The previous token is a field name (or a value typed without quotes, e.g. an IP
    // or a bare string, which looks the same): after a field an operator is expected;
    // after `field op value` a logical operator is.
    const prevPrev = previousToken(before.slice(0, before.slice(0, start).trimEnd().length - prev.length));
    if (prevPrev !== null && COMPARISON_WORDS.has(prevPrev.toLowerCase())) {
      return { kind: "logical", prefix, start, end };
    }
    return { kind: "operator", prefix, start, end };
  }

  /** @param {string} before */
  function insideString(before) {
    let inside = false;
    for (let i = 0; i < before.length; i++) {
      if (before[i] === "\\" && inside) {
        i++;
      } else if (before[i] === '"') {
        inside = !inside;
      }
    }
    return inside;
  }

  /**
   * Last complete token of `text` (ignoring trailing spaces), or null at the start.
   * @param {string} text
   * @returns {string | null}
   */
  function previousToken(text) {
    const t = text.trimEnd();
    if (!t) {
      return null;
    }
    const m = t.match(/("(?:[^"\\]|\\.)*"|\{[^}]*\}|===|!==|==|!=|>=|<=|~=|&&|\|\||\^\^|[<>!~()]|[A-Za-z0-9_.:-]+)$/);
    return m ? m[1] : t.slice(-1);
  }

  /**
   * Static operator suggestions for an `operator`/`logical` context.
   * @param {"operator" | "logical"} kind @param {string} prefix
   */
  function operatorSuggestions(kind, prefix) {
    const list = kind === "operator" ? COMPARISON_OPERATORS : LOGICAL_OPERATORS;
    const p = prefix.toLowerCase();
    return list.filter((o) => o.label.startsWith(p));
  }

  /**
   * Insert a completion, replacing the word under the cursor.
   * Operators get spaces around them; field names are inserted as-is.
   *
   * @param {string} text
   * @param {{start: number, end: number}} ctx
   * @param {string} insert
   * @param {boolean} isOperator
   * @returns {{text: string, cursor: number}}
   */
  function applyCompletion(text, ctx, insert, isOperator) {
    let head = text.slice(0, ctx.start);
    let tail = text.slice(ctx.end);
    let piece = insert;
    if (isOperator) {
      if (head && !/\s$/.test(head)) {
        head += " ";
      }
      piece += " ";
      tail = tail.replace(/^\s+/, "");
    }
    return { text: head + piece + tail, cursor: head.length + piece.length };
  }

  const FT_NAMES = {
    FT_NONE: "label",
    FT_PROTOCOL: "protocol",
    FT_BOOLEAN: "boolean",
    FT_CHAR: "character",
    FT_STRING: "character string",
    FT_STRINGZ: "character string",
    FT_STRINGZPAD: "character string",
    FT_STRINGZTRUNC: "character string",
    FT_UINT_STRING: "character string",
    FT_BYTES: "byte sequence",
    FT_UINT_BYTES: "byte sequence",
    FT_ETHER: "Ethernet (MAC) address",
    FT_IPv4: "IPv4 address",
    FT_IPv6: "IPv6 address",
    FT_IPXNET: "IPX network number",
    FT_FCWWN: "Fibre Channel WWN",
    FT_ABSOLUTE_TIME: "date and time",
    FT_RELATIVE_TIME: "time offset",
    FT_FRAMENUM: "frame number",
    FT_FLOAT: "floating point (single precision)",
    FT_DOUBLE: "floating point (double precision)",
    FT_GUID: "GUID",
    FT_OID: "ASN.1 object identifier",
    FT_REL_OID: "ASN.1 relative object identifier",
    FT_EUI64: "EUI64 address",
    FT_AX25: "AX.25 address",
    FT_VINES: "VINES address",
    FT_SYSTEM_ID: "OSI System-ID",
    FT_PCRE: "regular expression",
  };

  /** Human-readable name for a tshark field type (FT_UINT16 -> "unsigned integer, 2 bytes"). @param {string} ft */
  function friendlyType(ft) {
    if (ft in FT_NAMES) {
      return FT_NAMES[/** @type {keyof typeof FT_NAMES} */ (ft)];
    }
    const m = ft.match(/^FT_(U?)INT(\d+)$/);
    if (m) {
      const bytes = Number(m[2]) / 8;
      return `${m[1] ? "unsigned" : "signed"} integer, ${bytes} byte${bytes === 1 ? "" : "s"}`;
    }
    return ft.replace(/^FT_/, "").toLowerCase();
  }

  /**
   * Custom columns to show: the configured ones (keeping their titles) that the
   * backend accepted when opening the file. tshark drops unknown fields there.
   *
   * @param {{field: string, title: string}[]} configured
   * @param {{field: string}[]} accepted column descriptors from `open` (base + custom)
   */
  function acceptedColumns(configured, accepted) {
    const ok = new Set(accepted.map((c) => c.field));
    return configured.filter((c) => ok.has(c.field));
  }

  // ---------------------------------------------------------------- follow stream

  /**
   * Payload as text the way Wireshark's "ASCII" view shows it: printable
   * characters, tabs and newlines kept (CR before LF dropped), everything
   * else as ".".
   * @param {Uint8Array} bytes
   */
  function bytesToAscii(bytes) {
    let out = "";
    for (let i = 0; i < bytes.length; i++) {
      const b = bytes[i];
      if (b === 0x0d && bytes[i + 1] === 0x0a) {
        continue;
      }
      out += b === 0x0a || b === 0x09 || (b >= 0x20 && b < 0x7f) ? String.fromCharCode(b) : ".";
    }
    return out;
  }

  /**
   * Classic hex dump (offset, 16 bytes, ASCII) starting at `offset`.
   * @param {Uint8Array} bytes @param {number} [offset]
   */
  function hexDump(bytes, offset = 0) {
    const lines = [];
    for (let i = 0; i < bytes.length; i += 16) {
      const chunk = bytes.subarray(i, i + 16);
      const hex = [...chunk].map((b) => b.toString(16).padStart(2, "0"));
      const left = hex.slice(0, 8).join(" ");
      const right = hex.slice(8).join(" ");
      const ascii = [...chunk].map(asciiChar).join("");
      lines.push(`${(offset + i).toString(16).padStart(8, "0")}  ${left.padEnd(23)}  ${right.padEnd(23)}  ${ascii}`);
    }
    return lines.join("\n");
  }

  /** Display filter for a followed stream. @param {string} proto @param {number} stream */
  function streamFilter(proto, stream) {
    return `${proto === "udp" ? "udp" : "tcp"}.stream eq ${stream}`;
  }

  // ---------------------------------------------------------------- statistics tables

  /** 1234567 -> "1,234,567"; floats keep up to 6 decimals. @param {unknown} v */
  function formatCell(v) {
    if (typeof v !== "number") {
      return v === null || v === undefined ? "" : String(v);
    }
    return Number.isInteger(v) ? v.toLocaleString("en-US") : v.toLocaleString("en-US", { maximumFractionDigits: 6 });
  }

  /**
   * Stable sort of table rows by one column (numbers numerically, text case-insensitively).
   * @param {{cells: unknown[]}[]} rows @param {number} col @param {boolean} desc
   */
  function sortRows(rows, col, desc) {
    const dir = desc ? -1 : 1;
    return rows
      .map((row, i) => ({ row, i }))
      .sort((a, b) => {
        const x = a.row.cells[col];
        const y = b.row.cells[col];
        const c =
          typeof x === "number" && typeof y === "number"
            ? x - y
            : String(x ?? "").localeCompare(String(y ?? ""), undefined, { sensitivity: "base", numeric: true });
        return c * dir || a.i - b.i;
      })
      .map((e) => e.row);
  }

  /** @param {{label: string}[]} columns @param {{cells: unknown[]}[]} rows */
  function tableToCsv(columns, rows) {
    /** @param {unknown} v */
    const q = (v) => {
      const s = v === null || v === undefined ? "" : String(v);
      return /[",\n\r]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
    };
    return [columns.map((c) => q(c.label)).join(","), ...rows.map((r) => r.cells.map(q).join(","))].join("\n");
  }

  /**
   * Clean axis ticks from 0 to at least `max` (1-2-5 steps), e.g. 0, 20, 40, 60.
   * @param {number} max @param {number} [target] approximate number of intervals
   */
  function niceTicks(max, target = 4) {
    if (!(max > 0)) {
      return [0, 1];
    }
    const raw = max / target;
    const mag = 10 ** Math.floor(Math.log10(raw));
    const step = [1, 2, 5, 10].map((m) => m * mag).find((s) => s >= raw) ?? 10 * mag;
    const ticks = [];
    for (let v = 0; v < max + step / 2; v += step) {
      ticks.push(Math.round(v * 1e9) / 1e9);
    }
    if (ticks[ticks.length - 1] < max) {
      ticks.push(Math.round((ticks[ticks.length - 1] + step) * 1e9) / 1e9);
    }
    return ticks;
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

  const COLOR_RE = /^#[0-9a-fA-F]{6}$/;

  /**
   * Colors for a packet-list row: the coloring rule its `color` index names,
   * if the row came from the current coloring (`cid`) and both colors are valid.
   * @param {{color?: number, cid?: number} | undefined} row
   * @param {{id: number, rules: {foreground: string, background: string}[]} | null} coloring
   * @returns {{foreground: string, background: string} | null}
   */
  function rowColors(row, coloring) {
    if (!row || !coloring || row.cid !== coloring.id || typeof row.color !== "number") {
      return null;
    }
    const rule = coloring.rules[row.color];
    return rule && COLOR_RE.test(rule.foreground) && COLOR_RE.test(rule.background) ? rule : null;
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
    completionContext,
    operatorSuggestions,
    applyCompletion,
    friendlyType,
    acceptedColumns,
    bytesToAscii,
    hexDump,
    streamFilter,
    formatCell,
    sortRows,
    tableToCsv,
    niceTicks,
    hexToBytes,
    asciiChar,
    formatOffset,
    formatRelativeTime,
    formatBytes,
    rowColors,
  };

  if (typeof module === "object" && module.exports) {
    module.exports = api;
  } else {
    root.PcapLib = api;
  }
})(typeof window !== "undefined" ? window : globalThis);
