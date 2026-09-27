/**
 * Pure helpers for live capture and capture editing: file names, stop
 * conditions, and the time offsets and date-times typed in the editing
 * dialogs. Times are handled as nanoseconds (bigint) so offsets reach editcap
 * exactly, however large.
 */
import { safeFileName } from "./settingsModel";

/** Stop conditions of a live capture (0 or absent: none). */
export interface CaptureLimits {
  packets?: number;
  seconds?: number;
  bytes?: number;
}

/** `pcapViewer.capture.stopAfter*` settings as capture_start's `limits`. */
export function captureLimits(
  packets: unknown,
  seconds: unknown,
  megabytes: unknown,
): CaptureLimits {
  const positive = (v: unknown) =>
    typeof v === "number" && Number.isFinite(v) && v > 0 ? v : undefined;
  const limits: CaptureLimits = {};
  const p = positive(packets);
  const s = positive(seconds);
  const mb = positive(megabytes);
  if (p) {
    limits.packets = Math.round(p);
  }
  if (s) {
    limits.seconds = s;
  }
  if (mb) {
    limits.bytes = Math.round(mb * 1_000_000);
  }
  return limits;
}

const pad = (n: number, width = 2) => String(n).padStart(width, "0");

/**
 * The file name of a new capture: "capture_eth0_2026-09-27_13-14-05.pcapng"
 * (interface labels made safe for any file system, at most three of them).
 */
export function captureFileName(labels: string[], date: Date): string {
  const names = labels
    .slice(0, 3)
    .map((l) => safeFileName(l).replace(/[\s{}]+/g, "_"))
    .filter(Boolean);
  const more = labels.length > 3 ? "more" : "";
  const stamp =
    `${date.getFullYear()}-${pad(date.getMonth() + 1)}-${pad(date.getDate())}_` +
    `${pad(date.getHours())}-${pad(date.getMinutes())}-${pad(date.getSeconds())}`;
  return `capture_${[...names, more].filter(Boolean).join("+")}_${stamp}.pcapng`.slice(0, 200);
}

const NS = 1_000_000_000n;
const UNIT_NS: Record<string, bigint> = {
  d: 86_400n * NS,
  h: 3_600n * NS,
  m: 60n * NS,
  s: NS,
  ms: 1_000_000n,
};

/** "12.5" → 12_500_000_000n (at most 9 decimals); undefined if it isn't a decimal. */
function decimalNs(text: string, unit: bigint = NS): bigint | undefined {
  const m = /^(\d*)(?:\.(\d*))?$/.exec(text);
  if (!m || (!m[1] && !m[2])) {
    return undefined;
  }
  const whole = BigInt(m[1] || "0") * unit;
  const digits = (m[2] ?? "").slice(0, 18);
  const frac = digits ? (BigInt(digits) * unit) / 10n ** BigInt(digits.length) : 0n;
  return whole + frac;
}

/**
 * A duration typed by the user, in nanoseconds: seconds ("-3600", "0.5"),
 * a clock ("1:30:00", "-0:00:01.5") or units ("1h 30m", "-2d", "1.5s",
 * "250ms"). Undefined if it can't be read.
 */
export function parseDuration(text: string): bigint | undefined {
  const t = text.trim().toLowerCase();
  const m = /^([+-]?)\s*(.+)$/.exec(t);
  if (!m) {
    return undefined;
  }
  const sign = m[1] === "-" ? -1n : 1n;
  const body = m[2].trim();
  let ns: bigint | undefined;
  if (/^[\d.]+$/.test(body)) {
    ns = decimalNs(body);
  } else if (/^\d+(:\d{1,2}){1,2}(\.\d*)?$/.test(body)) {
    const parts = body.split(":");
    const secs = decimalNs(parts.pop() ?? "0") ?? 0n;
    const [h, mm] = parts.length === 2 ? parts : ["0", parts[0]];
    ns = BigInt(h) * UNIT_NS.h + BigInt(mm) * UNIT_NS.m + secs;
  } else {
    const compact = body.replace(/\s+/g, "");
    const terms = [...compact.matchAll(/(\d+(?:\.\d*)?|\.\d+)(ms|d|h|m|s)/g)];
    if (!terms.length || terms.map((x) => x[0]).join("") !== compact) {
      return undefined;
    }
    ns = 0n;
    for (const [, value, unit] of terms) {
      const part = decimalNs(value, UNIT_NS[unit]);
      if (part === undefined) {
        return undefined;
      }
      ns += part;
    }
  }
  return ns === undefined ? undefined : sign * ns;
}

/** Nanoseconds as editcap's decimal seconds: "-3600.25", "0.000000001". */
export function nsToSeconds(ns: bigint): string {
  const negative = ns < 0n;
  const abs = negative ? -ns : ns;
  const whole = abs / NS;
  const frac = (abs % NS).toString().padStart(9, "0").replace(/0+$/, "");
  const text = frac ? `${whole}.${frac}` : `${whole}`;
  return negative && text !== "0" ? `-${text}` : text;
}

/** Epoch seconds (capinfos' float) as nanoseconds, to the microsecond it carries. */
export function epochNs(seconds: number): bigint {
  return BigInt(Math.round(seconds * 1_000_000)) * 1_000n;
}

/**
 * A date-time typed by the user, as epoch nanoseconds: "2026-09-27 13:14:05",
 * with "T" or a space, optional fractional seconds and zone ("Z", "+02:00");
 * without a zone it is local time. Undefined if it can't be read.
 */
export function parseDateTime(text: string): bigint | undefined {
  const m =
    /^(\d{4})-(\d{2})-(\d{2})[T ](\d{2}):(\d{2})(?::(\d{2})(?:\.(\d{1,9}))?)?\s*(Z|[+-]\d{2}:?\d{2})?$/i.exec(
      text.trim(),
    );
  if (!m) {
    return undefined;
  }
  const [, y, mo, d, h, mi, s = "0", frac = "", zone] = m;
  const parts = [y, mo, d, h, mi, s].map(Number);
  let ms: number;
  if (zone) {
    ms = Date.UTC(parts[0], parts[1] - 1, parts[2], parts[3], parts[4], parts[5]);
    if (zone.toUpperCase() !== "Z") {
      const sign = zone.startsWith("-") ? -1 : 1;
      const digits = zone.slice(1).replace(":", "");
      ms -= sign * (Number(digits.slice(0, 2)) * 60 + Number(digits.slice(2))) * 60_000;
    }
  } else {
    ms = new Date(parts[0], parts[1] - 1, parts[2], parts[3], parts[4], parts[5]).getTime();
  }
  const check = new Date(Date.UTC(parts[0], parts[1] - 1, parts[2]));
  if (
    Number.isNaN(ms) ||
    check.getUTCMonth() !== parts[1] - 1 ||
    check.getUTCDate() !== parts[2] ||
    parts[3] > 23 ||
    parts[4] > 59 ||
    parts[5] > 59
  ) {
    return undefined;
  }
  return BigInt(ms) * 1_000_000n + BigInt(frac.padEnd(9, "0") || "0");
}

/** Epoch nanoseconds as a local date-time the user can edit: "2026-09-27 13:14:05.123456". */
export function formatDateTime(ns: bigint): string {
  const ms = Number(ns / 1_000_000n);
  const d = new Date(ms);
  const micros = ((ns % NS) + NS) % NS;
  const frac = micros.toString().padStart(9, "0").slice(0, 6).replace(/0+$/, "");
  return (
    `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())} ` +
    `${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}` +
    (frac ? `.${frac}` : "")
  );
}

/**
 * A point in time for "keep packets between": a date-time, or an offset from
 * the first packet ("+10s", "90", "1:00"). Epoch nanoseconds, or undefined.
 */
export function parseCaptureTime(text: string, firstPacketNs: bigint): bigint | undefined {
  const absolute = parseDateTime(text);
  if (absolute !== undefined) {
    return absolute;
  }
  const offset = parseDuration(text);
  return offset === undefined ? undefined : firstPacketNs + offset;
}
