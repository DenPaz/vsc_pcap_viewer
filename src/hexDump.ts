/**
 * Import from Hex Dump: guessing how a dump is laid out, and the options the
 * backend's import_hexdump (text2pcap) takes. Pure (no `vscode` import).
 */

export type OffsetBase = "hex" | "dec" | "oct" | "none";

const BYTE = /^[0-9a-fA-F]{2}$/;
const OFFSET = /^[0-9a-fA-F]{3,}:?$/;
/** hexdump -C's ASCII column: `|...|` at the end of a line. */
const PIPE_COLUMN = /\|[^|]{1,16}\|\s*$/;

interface DumpLine {
  offset: string;
  bytes: number;
}

/** A line as offset + bytes (bytes stop at the first token that isn't one). */
function dumpLine(line: string): DumpLine | undefined {
  const tokens = line.replace(PIPE_COLUMN, "").trim().split(/\s+/);
  if (tokens.length < 2 || !OFFSET.test(tokens[0])) {
    return undefined;
  }
  let bytes = 0;
  for (const t of tokens.slice(1)) {
    if (!BYTE.test(t)) {
      break;
    }
    bytes++;
  }
  return bytes ? { offset: tokens[0].replace(/:$/, ""), bytes } : undefined;
}

/**
 * How the dump's offsets are written: `none` when its lines are only hex
 * bytes; otherwise the base in which consecutive offsets advance by the
 * previous line's byte count (od -Ad / -Ao dumps are decimal / octal), `hex`
 * when nothing decides it. Looks at the first 500 lines.
 */
export function guessOffsets(text: string): OffsetBase {
  const lines = text
    .split("\n")
    .slice(0, 500)
    .map((l) => l.trimEnd())
    .filter(Boolean);
  const bytesOnly = lines.filter((l) =>
    l
      .trim()
      .split(/\s+/)
      .every((t) => BYTE.test(t)),
  );
  const parsed = lines.map(dumpLine);
  if (bytesOnly.length && bytesOnly.length >= parsed.filter(Boolean).length) {
    return "none";
  }
  const score = { hex: 0, dec: 0, oct: 0 };
  const radix = { hex: 16, dec: 10, oct: 8 } as const;
  for (let i = 1; i < parsed.length; i++) {
    const prev = parsed[i - 1];
    const cur = parsed[i];
    if (!prev || !cur) {
      continue;
    }
    for (const base of ["hex", "dec", "oct"] as const) {
      const a = parseInt(prev.offset, radix[base]);
      const b = parseInt(cur.offset, radix[base]);
      if (!Number.isNaN(a) && !Number.isNaN(b) && b - a === prev.bytes) {
        score[base]++;
      }
    }
  }
  // Ties (e.g. offsets 0000 and 0010 of a 10-byte line) go to hex.
  if (score.dec > score.hex && score.dec >= score.oct) {
    return "dec";
  }
  if (score.oct > score.hex && score.oct > score.dec) {
    return "oct";
  }
  return "hex";
}

/** Whether lines end in hexdump -C's `|ASCII|` column (text2pcap's -a skips it). */
export function hasAsciiColumn(text: string): boolean {
  const lines = text
    .split("\n")
    .slice(0, 50)
    .filter((l) => l.trim());
  return lines.length > 0 && lines.filter((l) => PIPE_COLUMN.test(l)).length * 2 >= lines.length;
}

/** `"5060,5061"` / `"5060 5061"` / `"5060"` (both) -> ports, or an error message. */
export function parsePorts(text: string): { srcPort: number; dstPort: number } | string {
  const parts = text
    .trim()
    .split(/[\s,]+/)
    .filter(Boolean);
  if (parts.length < 1 || parts.length > 2 || !parts.every((p) => /^\d{1,5}$/.test(p))) {
    return "Enter a source and a destination port, e.g. 5060,5060";
  }
  const [src, dst = src] = parts.map(Number);
  if (src > 65535 || dst > 65535) {
    return "Ports go up to 65535";
  }
  return { srcPort: src, dstPort: dst };
}

/** The new capture's name: after the dump's file, else `hexdump_<date>`. */
export function importFileName(source: string | undefined, date: Date): string {
  const stem = source
    ?.split(/[\\/]/)
    .pop()
    ?.replace(/\.[^.]*$/, "")
    .replace(/[^\w.-]+/g, "_")
    .slice(0, 100);
  if (stem) {
    return `${stem}.pcapng`;
  }
  const pad = (n: number) => String(n).padStart(2, "0");
  return (
    `hexdump_${date.getFullYear()}-${pad(date.getMonth() + 1)}-${pad(date.getDate())}_` +
    `${pad(date.getHours())}-${pad(date.getMinutes())}-${pad(date.getSeconds())}.pcapng`
  );
}
