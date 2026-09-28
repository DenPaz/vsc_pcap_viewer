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
    const end = Math.min(
      lastPage,
      Math.floor(Math.max(first, first + count - 1) / pageSize) + prefetch,
    );
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
    /** @param {any} key @returns {boolean} whether it was cached */
    delete(key) {
      return this.map.delete(key);
    }
    clear() {
      this.map.clear();
    }
    /** Cached values (does not change the LRU order). */
    values() {
      return this.map.values();
    }
    /** Cached [key, value] pairs (does not change the LRU order). */
    entries() {
      return this.map.entries();
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
    if (
      NUMBER_RE.test(show) ||
      HEX_RE.test(show) ||
      IPV4_RE.test(show) ||
      MAC_RE.test(show) ||
      (show.includes(":") && IPV6_RE.test(show))
    ) {
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
        const hit =
          n.src === src &&
          n.pos !== undefined &&
          n.size !== undefined &&
          offset >= n.pos &&
          offset < n.pos + n.size;
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
  const COMPARISON_WORDS = new Set([
    "==",
    "!=",
    ">",
    "<",
    ">=",
    "<=",
    "eq",
    "ne",
    "gt",
    "lt",
    "ge",
    "le",
    "contains",
    "matches",
    "in",
    "~",
    "===",
    "!==",
    "~=",
  ]);

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
    const prevIsValue =
      prev !== null &&
      (/^["\d]/.test(prev) ||
        prev === ")" ||
        prev.startsWith("{") ||
        /^[0-9a-f]{2}([:.-][0-9a-f]{2})+$/i.test(prev));
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
    const prevPrev = previousToken(
      before.slice(0, before.slice(0, start).trimEnd().length - prev.length),
    );
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
    const m = t.match(
      /("(?:[^"\\]|\\.)*"|\{[^}]*\}|===|!==|==|!=|>=|<=|~=|&&|\|\||\^\^|[<>!~()]|[A-Za-z0-9_.:-]+)$/,
    );
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
      lines.push(
        `${(offset + i).toString(16).padStart(8, "0")}  ${left.padEnd(23)}  ${right.padEnd(23)}  ${ascii}`,
      );
    }
    return lines.join("\n");
  }

  /** Display filter for a followed stream. @param {string} proto @param {number} stream */
  function streamFilter(proto, stream) {
    return `${proto === "udp" ? "udp" : "tcp"}.stream eq ${stream}`;
  }

  // ---------------------------------------------------------------- statistics tables

  /** 1234567 -> "1,234,567"; floats keep up to 6 decimals. @param {unknown} v */
  /**
   * A filter button's tooltip: its comment (if any) above its filter.
   * @param {{filter: string, comment?: string}} button
   */
  function filterButtonTitle(button) {
    return button.comment ? `${button.comment}\n${button.filter}` : button.filter;
  }

  function formatCell(v) {
    if (typeof v !== "number") {
      return v === null || v === undefined ? "" : String(v);
    }
    return Number.isInteger(v)
      ? v.toLocaleString("en-US")
      : v.toLocaleString("en-US", { maximumFractionDigits: 6 });
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
            : String(x ?? "").localeCompare(String(y ?? ""), undefined, {
                sensitivity: "base",
                numeric: true,
              });
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
    return [
      columns.map((c) => q(c.label)).join(","),
      ...rows.map((r) => r.cells.map(q).join(",")),
    ].join("\n");
  }

  /**
   * Packet-list rows as tab-separated text (what Copy puts on the clipboard):
   * one line per row, optionally a header line first. Tabs and line breaks in
   * cells become spaces so every row stays one line.
   * @param {string[]} titles @param {string[][]} rows @param {boolean} header
   */
  function rowsToText(titles, rows, header) {
    /** @param {string} v */
    const clean = (v) => String(v ?? "").replace(/[\t\r\n]+/g, " ");
    const lines = rows.map((cells) => cells.map(clean).join("\t"));
    return (header ? [titles.map(clean).join("\t"), ...lines] : lines).join("\n");
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

  /**
   * A duration as a clock: "0:05", "12:34", "1:02:03".
   * @param {number} seconds
   */
  function formatDuration(seconds) {
    const s = Math.max(0, Math.floor(seconds));
    const h = Math.floor(s / 3600);
    const m = Math.floor((s % 3600) / 60);
    const ss = String(s % 60).padStart(2, "0");
    return h ? `${h}:${String(m).padStart(2, "0")}:${ss}` : `${m}:${ss}`;
  }

  // ------------------------------------------------------------------ packet-list cells

  const MAC6_RE = /^[0-9a-fA-F]{2}(:[0-9a-fA-F]{2}){5}$/;

  /**
   * Display-filter name for a Protocol column label: "TLSv1.3" → "tls",
   * "HTTP/JSON" → "http", "DNS" → "dns". null when it can't be a filter name.
   * @param {string} label
   */
  function protocolFilterName(label) {
    const first = label.trim().split(/[/\s]/)[0].toLowerCase();
    if (/^(tls|ssl)v?[\d.]*$/.test(first)) {
      return "tls";
    }
    return /^[a-z][a-z0-9_.-]*$/.test(first) ? first : null;
  }

  /**
   * Filter for a packet-list cell ("Apply as Filter" on the list), or null for
   * columns without one (Time, Info) and values that can't be matched.
   * Source/Destination pick ip/ipv6/eth by the value's form.
   * @param {{id: string, field: string, custom?: boolean}} column @param {string} value
   * @returns {string | null}
   */
  function cellFilter(column, value) {
    const v = (value ?? "").trim();
    if (!v) {
      return null;
    }
    switch (column.id) {
      case "number":
        return NUMBER_RE.test(v) ? `frame.number == ${v}` : null;
      case "length":
        return NUMBER_RE.test(v) ? `frame.len == ${v}` : null;
      case "time":
      case "info":
        return null;
      case "source":
      case "destination": {
        const dir = column.id === "source" ? "src" : "dst";
        if (IPV4_RE.test(v)) {
          return `ip.${dir} == ${v}`;
        }
        if (MAC6_RE.test(v)) {
          return `eth.${dir} == ${v}`;
        }
        return v.includes(":") && IPV6_RE.test(v) ? `ipv6.${dir} == ${v}` : null;
      }
      case "protocol":
        return protocolFilterName(v);
    }
    if (column.custom && column.field) {
      // Several occurrences come comma-separated: match the first.
      return buildFieldFilter({ name: column.field, show: v.split(",")[0].trim() });
    }
    return null;
  }

  /**
   * Flow graph: x positions of an arrow between node columns `from` and `to`
   * (-1 = a node past the limit, drawn in the "other" column after the
   * `nodes` shown). `self`: both ends are the same node.
   * @param {number} from @param {number} to @param {number} nodes
   * @param {{gutter: number, column: number}} layout
   * @returns {{x1: number, x2: number, self: boolean}}
   */
  function flowArrow(from, to, nodes, layout) {
    const x = (/** @type {number} */ i) =>
      layout.gutter + ((i < 0 ? nodes : i) + 0.5) * layout.column;
    return { x1: x(from), x2: x(to), self: from === to };
  }

  /**
   * Round axis ticks covering `min`..`max` (for axes that don't start at 0).
   * @param {number} min @param {number} max @param {number} [target]
   * @returns {number[]}
   */
  function niceRange(min, max, target = 4) {
    if (!(max > min)) {
      return niceTicks(max > 0 ? max : 1, target);
    }
    const ticks = niceTicks(max - min, target);
    const step = ticks[1] - ticks[0];
    const start = Math.floor(min / step) * step;
    const out = [];
    for (let v = start; v < max + step / 2; v += step) {
      out.push(Math.round(v * 1e9) / 1e9);
    }
    if (out[out.length - 1] < max) {
      out.push(Math.round((out[out.length - 1] + step) * 1e9) / 1e9);
    }
    return out;
  }

  /** TCP stream graphs (tcp_graph points): index of each field in a point. */
  const TP = { frame: 0, time: 1, dir: 2, seq: 3, len: 4, ack: 5, win: 6, rtt: 7, retrans: 8 };

  /**
   * One TCP stream graph for the data sent in direction `dir` (0 = A→B):
   * - "stevens": sequence number over time, one segment per data packet
   *   (`y`..`y2`), retransmissions flagged;
   * - "throughput": bytes per second over time, a moving average over `window`
   *   seconds (default: a twentieth of the stream's duration, 1 ms to 1 s);
   * - "rtt": round-trip times (ms) of the receiver's ACKs;
   * - "window": the receiver's advertised window (the line) and the bytes in
   *   flight (the dots) over time.
   * @param {any[][]} points @param {0 | 1} dir
   * @param {"stevens" | "throughput" | "rtt" | "window"} kind
   * @param {{window?: number}} [opts]
   * @returns {{points: {x: number, y: number, y2?: number, frame: number, flag?: boolean}[], line?: {x: number, y: number}[], xLabel: string, yLabel: string}}
   */
  function tcpGraphSeries(points, dir, kind, opts = {}) {
    const data = points.filter((p) => p[TP.dir] === dir && p[TP.len] > 0);
    const back = points.filter((p) => p[TP.dir] !== dir);
    const time = "Time (s)";
    if (kind === "stevens") {
      return {
        points: data.map((p) => ({
          x: p[TP.time],
          y: p[TP.seq],
          y2: p[TP.seq] + p[TP.len],
          frame: p[TP.frame],
          flag: !!p[TP.retrans],
        })),
        xLabel: time,
        yLabel: "Sequence number (bytes)",
      };
    }
    if (kind === "throughput") {
      const times = data.map((p) => p[TP.time]);
      const span = times.length ? times[times.length - 1] - times[0] : 0;
      const w = opts.window ?? Math.min(1, Math.max(0.001, span / 20));
      let start = 0;
      let bytes = 0;
      const out = data.map((p, i) => {
        bytes += p[TP.len];
        while (data[start][TP.time] <= p[TP.time] - w && start < i) {
          bytes -= data[start][TP.len];
          start++;
        }
        return { x: p[TP.time], y: bytes / w, frame: p[TP.frame] };
      });
      return {
        points: out,
        line: out,
        xLabel: time,
        yLabel: `Throughput (bytes/s, ${w} s average)`,
      };
    }
    if (kind === "rtt") {
      return {
        points: back
          .filter((p) => typeof p[TP.rtt] === "number")
          .map((p) => ({ x: p[TP.time], y: p[TP.rtt] * 1000, frame: p[TP.frame] })),
        xLabel: time,
        yLabel: "Round-trip time (ms)",
      };
    }
    const line = back.map((p) => ({ x: p[TP.time], y: p[TP.win] }));
    /** @type {{x: number, y: number, frame: number}[]} */
    const flight = [];
    let acked = null;
    let j = 0;
    for (const p of data) {
      while (j < back.length && back[j][TP.time] <= p[TP.time]) {
        acked = Math.max(acked ?? 0, back[j][TP.ack]);
        j++;
      }
      const sent = p[TP.seq] + p[TP.len];
      flight.push({
        x: p[TP.time],
        y: Math.max(0, sent - (acked ?? p[TP.seq])),
        frame: p[TP.frame],
      });
    }
    return { points: flight, line, xLabel: time, yLabel: "Bytes (window: line, in flight: dots)" };
  }

  /**
   * `text` cut to `max` characters with an ellipsis.
   * @param {string} text @param {number} max
   */
  function truncate(text, max) {
    if (max <= 0) {
      return "";
    }
    return text.length <= max ? text : `${text.slice(0, Math.max(0, max - 1))}…`;
  }

  /**
   * Export Objects rows shown for a protocol ("" = all) and a text that must
   * appear (case-insensitively) in the name, host or content type.
   * @template {{protocol: string, name: string, host: string, contentType: string}} T
   * @param {T[]} objects @param {string} protocol @param {string} text
   * @returns {T[]}
   */
  function filterObjects(objects, protocol, text) {
    const needle = text.trim().toLowerCase();
    return objects.filter(
      (o) =>
        (!protocol || o.protocol === protocol) &&
        (!needle || [o.name, o.host, o.contentType].some((v) => v.toLowerCase().includes(needle))),
    );
  }

  /**
   * The address behind a Source/Destination cell that shows a name (name
   * resolution: the row's `addresses`), else null.
   * @param {{id: string}} column @param {{cells: string[], addresses?: string[]} | undefined} row
   * @returns {string | null}
   */
  function cellAddress(column, row) {
    const i = column.id === "source" ? 0 : column.id === "destination" ? 1 : -1;
    const address = i >= 0 ? row?.addresses?.[i] : undefined;
    return address && address !== row?.cells[2 + i] ? address : null;
  }

  /**
   * Visible columns in display order: ids in `layout.order` first, the rest in
   * their natural order; hidden ones left out (at least one always stays).
   * `index` is the column's position in `all` (= its cell index in a row).
   * @template {{id: string}} C
   * @param {C[]} all @param {{order?: string[], hidden?: string[]} | undefined} layout
   * @returns {{column: C, index: number}[]}
   */
  function layoutColumns(all, layout) {
    const order = layout?.order ?? [];
    const hidden = new Set(layout?.hidden ?? []);
    const rank = (/** @type {string} */ id) => {
      const i = order.indexOf(id);
      return i < 0 ? order.length : i;
    };
    const indexed = all.map((column, index) => ({ column, index }));
    const sorted = [...indexed].sort(
      (a, b) => rank(a.column.id) - rank(b.column.id) || a.index - b.index,
    );
    const visible = sorted.filter((c) => !hidden.has(c.column.id));
    return visible.length ? visible : sorted.slice(0, 1);
  }

  /**
   * New display order after dragging column `id` in front of `beforeId`
   * (null: to the end). `current` is the current display order of all ids.
   * @param {string[]} current @param {string} id @param {string | null} beforeId
   */
  function moveColumn(current, id, beforeId) {
    const rest = current.filter((c) => c !== id);
    const at = beforeId === null ? rest.length : rest.indexOf(beforeId);
    rest.splice(at < 0 ? rest.length : at, 0, id);
    return rest;
  }

  // ------------------------------------------------------------------ find / bytes

  /**
   * Hex bytes for Find Packet: "474554", "47 45 54", "47:45:54", "0x47 0x45".
   * Returns lower-case byte pairs, or null when the input isn't hex bytes.
   * (The backend parses the same way; this gives immediate feedback.)
   * @param {string} text
   * @returns {string[] | null}
   */
  function parseHexBytes(text) {
    const tokens = text
      .trim()
      .split(/[\s:.,-]+/)
      .filter(Boolean)
      .map((t) => t.toLowerCase());
    /** @type {string[]} */
    const out = [];
    for (const token of tokens) {
      let t = token.startsWith("0x") ? token.slice(2) : token;
      if (tokens.length > 1 && t.length === 1) {
        t = "0" + t;
      }
      if (!t || t.length % 2 || !/^[0-9a-f]+$/.test(t)) {
        return null;
      }
      for (let i = 0; i < t.length; i += 2) {
        out.push(t.slice(i, i + 2));
      }
    }
    return out.length ? out : null;
  }

  const BASE64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

  /** @param {Uint8Array} bytes */
  function toBase64(bytes) {
    let out = "";
    for (let i = 0; i < bytes.length; i += 3) {
      const n = (bytes[i] << 16) | ((bytes[i + 1] ?? 0) << 8) | (bytes[i + 2] ?? 0);
      out += BASE64[(n >> 18) & 63] + BASE64[(n >> 12) & 63];
      out += i + 1 < bytes.length ? BASE64[(n >> 6) & 63] : "=";
      out += i + 2 < bytes.length ? BASE64[n & 63] : "=";
    }
    return out;
  }

  /** @typedef {"hexdump" | "hex" | "c" | "escaped" | "base64" | "text"} BytesFormat */

  /**
   * Bytes pane "Copy as…" formats, like Wireshark's: hex dump (offsets + ASCII),
   * hex stream, C array, escaped string, Base64 and printable text (non-printable
   * bytes dropped, line breaks and tabs kept).
   * @param {Uint8Array} bytes @param {BytesFormat} kind @param {number} [offset] first offset of the dump
   */
  function formatBytesAs(bytes, kind, offset = 0) {
    const hex2 = (/** @type {number} */ b) => b.toString(16).padStart(2, "0");
    switch (kind) {
      case "hexdump":
        return hexDump(bytes, offset);
      case "hex":
        return [...bytes].map(hex2).join("");
      case "c": {
        const lines = [];
        for (let i = 0; i < bytes.length; i += 8) {
          lines.push(
            "  " +
              [...bytes.subarray(i, i + 8)].map((b) => `0x${hex2(b)}`).join(", ") +
              (i + 8 < bytes.length ? "," : ""),
          );
        }
        return `static const unsigned char packet_bytes[${bytes.length}] = {\n${lines.join("\n")}\n};`;
      }
      case "escaped":
        return [...bytes].map((b) => `\\x${hex2(b)}`).join("");
      case "base64":
        return toBase64(bytes);
      case "text": {
        let out = "";
        for (let i = 0; i < bytes.length; i++) {
          const b = bytes[i];
          if (b === 0x0d && bytes[i + 1] === 0x0a) {
            continue;
          }
          if (b === 0x0a || b === 0x09 || (b >= 0x20 && b < 0x7f)) {
            out += String.fromCharCode(b);
          }
        }
        return out;
      }
    }
    return "";
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

  /**
   * @typedef {object} IndexProgress
   * @property {string} [phase] "catching-up" (a resumed open re-reads the rows it
   *   already shows) or "indexing"
   * @property {number} frames packets indexed (shown) so far
   * @property {number | null} fraction null when it can't be estimated
   * @property {number | null} [resumedAt] rows a resumed open started with
   */

  /**
   * The status text of a streaming open's indexing, e.g. "Indexing… 42% · 420,000 packets".
   * @param {IndexProgress} p
   */
  function indexingLabel(p) {
    if (p.phase === "catching-up" && p.resumedAt) {
      return `Resuming… re-reading packets 1–${p.resumedAt.toLocaleString()} (already shown)`;
    }
    const packets = `${p.frames.toLocaleString()} packets`;
    return typeof p.fraction === "number"
      ? `Indexing… ${Math.round(clampFraction(p.fraction) * 100)}% · ${packets}`
      : `Indexing… ${packets}`;
  }

  /** @param {number} f */
  function clampFraction(f) {
    return Math.min(1, Math.max(0, f));
  }

  /**
   * What the progress bar shows: the most important work running. Each kind is
   * a fraction (0–1), null (running, amount unknown: indeterminate) or undefined
   * (not running). Indexing comes first, then a streaming filter, an export,
   * coloring and any other request that reported progress.
   * @param {{
   *   index?: IndexProgress | null,
   *   filter?: number | null,
   *   exporting?: number | null,
   *   coloring?: number | null,
   *   busy?: number | null,
   * }} work
   * @returns {{visible: boolean, fraction: number | null, secondary: boolean, label: string}}
   */
  function progressView(work) {
    if (work.index) {
      const resuming = work.index.phase === "catching-up";
      return {
        visible: true,
        fraction:
          typeof work.index.fraction === "number" ? clampFraction(work.index.fraction) : null,
        // While re-reading rows already shown: a quieter bar.
        secondary: resuming,
        label: resuming ? "Resuming indexing" : "Indexing packets",
      };
    }
    /** @type {[keyof typeof work, string][]} */
    const kinds = [
      ["filter", "Filtering packets"],
      ["exporting", "Exporting"],
      ["coloring", "Coloring packets"],
      ["busy", "Working"],
    ];
    for (const [kind, label] of kinds) {
      const value = work[kind];
      if (value !== undefined && typeof value !== "object") {
        return { visible: true, fraction: clampFraction(value), secondary: false, label };
      }
      if (value === null) {
        return { visible: true, fraction: null, secondary: false, label };
      }
    }
    return { visible: false, fraction: null, secondary: false, label: "" };
  }

  // ------------------------------------------------------------------ commands menu (☰)

  /** The menu's headings in order (src/commandMenu.ts COMMAND_GROUPS). */
  const COMMAND_GROUP_ORDER = [
    "Filters",
    "Packets",
    "Statistics",
    "Export",
    "Capture",
    "Editing",
    "Dissectors",
    "AI",
    "Other",
  ];

  /**
   * @typedef {{id: string, title: string, category: string, group: string,
   *   keys?: {key: string, mac?: string}, requires?: string[]}} MenuCommand
   */

  /**
   * Commands under their headings, in COMMAND_GROUP_ORDER (a group the order
   * doesn't know goes under "Other"); each group keeps the commands' order.
   * Empty groups are left out.
   * @param {MenuCommand[]} commands
   * @returns {{group: string, commands: MenuCommand[]}[]}
   */
  function groupCommands(commands) {
    /** @type {Map<string, MenuCommand[]>} */
    const byGroup = new Map(COMMAND_GROUP_ORDER.map((g) => [g, []]));
    for (const c of commands) {
      byGroup.get(COMMAND_GROUP_ORDER.includes(c.group) ? c.group : "Other")?.push(c);
    }
    return [...byGroup]
      .filter(([, list]) => list.length)
      .map(([group, list]) => ({ group, commands: list }));
  }

  /**
   * The ☰ menu's rows: a heading per group, then the commands of the groups
   * that are open. While searching every group with a match is open and its
   * heading is only a label (`foldable: false`), so results show at once.
   * @param {{group: string, commands: MenuCommand[]}[]} groups
   * @param {ReadonlySet<string>} openGroups @param {boolean} searching
   */
  function commandMenuRows(groups, openGroups, searching) {
    /** @type {({kind: "group", group: string, count: number, open: boolean, foldable: boolean} | {kind: "command", group: string, command: MenuCommand})[]} */
    const rows = [];
    for (const g of groups) {
      const open = searching || openGroups.has(g.group);
      rows.push({
        kind: "group",
        group: g.group,
        count: g.commands.length,
        open,
        foldable: !searching,
      });
      if (open) {
        for (const command of g.commands) {
          rows.push({ kind: "command", group: g.group, command });
        }
      }
    }
    return rows;
  }

  /**
   * The commands matching typed text: every word must occur (case-insensitive)
   * in the title, the heading or the package.json category.
   * @param {MenuCommand[]} commands @param {string} text
   */
  function filterCommands(commands, text) {
    const words = text.toLowerCase().split(/\s+/).filter(Boolean);
    if (!words.length) {
      return commands;
    }
    return commands.filter((c) => {
      const hay = `${c.title} ${c.group} ${c.category}`.toLowerCase();
      return words.every((w) => hay.includes(w));
    });
  }

  const KEY_NAMES = {
    left: "Left",
    right: "Right",
    up: "Up",
    down: "Down",
    escape: "Esc",
    enter: "Enter",
  };
  const MAC_SYMBOLS = { cmd: "⌘", ctrl: "⌃", alt: "⌥", shift: "⇧", meta: "⌘" };
  const MAC_KEYS = { left: "←", right: "→", up: "↑", down: "↓", escape: "⎋", enter: "↩" };
  const PC_MODIFIERS = {
    ctrl: "Ctrl",
    alt: "Alt",
    shift: "Shift",
    cmd: "Win",
    meta: "Win",
    win: "Win",
  };

  /**
   * A package.json key binding as the platform shows it: "Ctrl+Shift+N" or,
   * on macOS (its `mac` binding when there is one), "⌘⇧N". "" without one.
   * @param {{key: string, mac?: string} | undefined} keys @param {boolean} mac
   */
  function formatKeybinding(keys, mac) {
    if (!keys) {
      return "";
    }
    const binding = mac ? keys.mac || keys.key : keys.key;
    return binding
      .split(" ") // (chords: "ctrl+k ctrl+s")
      .map((chord) =>
        chord
          .split("+")
          .map((part) => {
            const p = part.toLowerCase();
            if (mac) {
              return MAC_SYMBOLS[p] ?? MAC_KEYS[p] ?? (p.length === 1 ? p.toUpperCase() : part);
            }
            return PC_MODIFIERS[p] ?? KEY_NAMES[p] ?? (p.length === 1 ? p.toUpperCase() : part);
          })
          .join(mac ? "" : "+"),
      )
      .join(" ");
  }

  /** Why a requirement isn't met (lib.commandUnavailable). */
  const REQUIREMENT_REASONS = {
    ai: "AI help isn't available (it needs GitHub Copilot, and pcapViewer.ai.enabled)",
    selection: "Select a packet first",
    marks: "No packets are marked",
    filter: "No display filter is applied",
    capturing: "No capture is running",
  };

  /**
   * Why a command can't run now (its first requirement that isn't met), or
   * null when it can. The menu shows such entries disabled with the reason.
   * @param {MenuCommand} command
   * @param {{selected: boolean, marks: number, filter: boolean, capturing: boolean, ai: boolean}} ctx
   * @returns {string | null}
   */
  function commandUnavailable(command, ctx) {
    for (const need of command.requires ?? []) {
      const met =
        need === "selection"
          ? ctx.selected
          : need === "marks"
            ? ctx.marks > 0
            : need === "filter"
              ? ctx.filter
              : need === "capturing"
                ? ctx.capturing
                : need === "ai"
                  ? ctx.ai
                  : true;
      if (!met) {
        return REQUIREMENT_REASONS[need] ?? "Not available now";
      }
    }
    return null;
  }

  // ------------------------------------------------------------------ VoIP

  /**
   * A call's sequence diagram: the endpoints (columns, in order of first
   * appearance) and one row per SIP message and per RTP stream of the call
   * (at the stream's start), in time order. A row's `from`/`to` are column
   * indexes; RTP rows carry `stream` (index into `streams`) instead of a frame.
   * @param {{messages: [number, number, string, string, string][], streams: number[]}} call
   * @param {{src: string, dst: string, start: number, payload: string, packets: number, lost: number}[]} streams
   * @returns {{nodes: string[], rows: {time: number, from: number, to: number, label: string, frame?: number, stream?: number}[]}}
   */
  function callFlow(call, streams) {
    /** @type {string[]} */
    const nodes = [];
    const node = (/** @type {string} */ addr) => {
      let i = nodes.indexOf(addr);
      if (i < 0) {
        i = nodes.push(addr) - 1;
      }
      return i;
    };
    /** @type {{time: number, from: number, to: number, label: string, frame?: number, stream?: number}[]} */
    const rows = call.messages.map(([frame, time, src, dst, label]) => ({
      time,
      from: node(src),
      to: node(dst),
      label,
      frame,
    }));
    for (const i of call.streams) {
      const s = streams[i];
      if (s) {
        rows.push({
          time: s.start,
          from: node(s.src),
          to: node(s.dst),
          label: `RTP ${rtpStreamLabel(s)}`,
          stream: i,
        });
      }
    }
    rows.sort((a, b) => a.time - b.time);
    return { nodes, rows };
  }

  /**
   * "g711U · 49 packets · 1 lost (2.0%)".
   * @param {{payload: string, packets: number, lost: number, lostPercent?: number}} s
   */
  function rtpStreamLabel(s) {
    const lost =
      s.lost > 0
        ? ` · ${s.lost.toLocaleString()} lost (${(s.lostPercent ?? 0).toFixed(1)}%)`
        : s.lost < 0
          ? ` · ${(-s.lost).toLocaleString()} duplicated`
          : "";
    return `${s.payload} · ${s.packets.toLocaleString()} packets${lost}`;
  }

  /** rtp_stream point fields (voip.POINT_FIELDS). */
  const RP = {
    frame: 0,
    time: 1,
    seq: 2,
    delta: 3,
    jitter: 4,
    skew: 5,
    marker: 6,
    status: 7,
    gap: 8,
  };

  /**
   * The packets of an analysed RTP stream that are worth a look: sequence
   * gaps, late or duplicated packets and payload type changes.
   * @param {any[][]} points
   * @returns {{frame: number, text: string}[]}
   */
  function rtpProblems(points) {
    /** @type {{frame: number, text: string}[]} */
    const out = [];
    for (const p of points) {
      const frame = p[RP.frame];
      const seq = p[RP.seq];
      switch (p[RP.status]) {
        case 1: {
          const n = p[RP.gap];
          out.push({ frame, text: `${n} packet${n === 1 ? "" : "s"} lost before seq ${seq}` });
          break;
        }
        case 2:
          out.push({ frame, text: `Seq ${seq} out of order or duplicated` });
          break;
        case 3:
          out.push({ frame, text: `Payload type changed at seq ${seq}` });
          break;
      }
    }
    return out;
  }

  const api = {
    COMMAND_GROUP_ORDER,
    groupCommands,
    commandMenuRows,
    filterCommands,
    formatKeybinding,
    commandUnavailable,
    callFlow,
    rtpStreamLabel,
    rtpProblems,
    RP,
    indexingLabel,
    progressView,
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
    filterButtonTitle,
    sortRows,
    tableToCsv,
    rowsToText,
    niceTicks,
    hexToBytes,
    asciiChar,
    formatOffset,
    formatRelativeTime,
    formatBytes,
    formatDuration,
    rowColors,
    protocolFilterName,
    cellFilter,
    cellAddress,
    filterObjects,
    flowArrow,
    niceRange,
    tcpGraphSeries,
    truncate,
    layoutColumns,
    moveColumn,
    parseHexBytes,
    toBase64,
    formatBytesAs,
  };

  if (typeof module === "object" && module.exports) {
    module.exports = api;
  } else {
    root.PcapLib = api;
  }
})(typeof window !== "undefined" ? window : globalThis);
