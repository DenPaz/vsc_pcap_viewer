/**
 * Captures written in pieces, recognised by name so they can be merged back
 * into one capture:
 *
 * - `tcpdump -C` / `-W`: `trace.pcap`, `trace.pcap1`, `trace.pcap2`, … (with
 *   `-W` the first piece is numbered too: `trace.pcap0`, or `trace.pcap00`).
 * - dumpcap / Wireshark ring buffers and `editcap -c` splits:
 *   `name_00001_20260927041500.pcapng` (piece number, then a timestamp).
 *
 * No vscode import: unit-tested.
 */
import * as fs from "node:fs/promises";
import * as path from "node:path";
import { captureStem } from "./settingsModel";

const TCPDUMP = /^(.*\.pcap(?:ng)?)(\d*)$/i;
const RING = /^(.*)_(\d{5})_(\d{14})(\.pcapng|\.pcap)(\.gz|\.zst|\.lz4)?$/i;

interface Piece {
  /** Pieces of the same capture share it. */
  key: string;
  /** Position in the capture (-1: tcpdump's unnumbered first piece). */
  index: number;
  /** Base name for the merged file. */
  stem: string;
}

export function rotationPiece(name: string): Piece | undefined {
  const ring = RING.exec(name);
  if (ring) {
    return {
      key: `ring:${ring[1]}:${ring[4]}${ring[5] ?? ""}`,
      index: Number(ring[2]),
      stem: ring[1],
    };
  }
  const tcpdump = TCPDUMP.exec(name);
  if (tcpdump) {
    return {
      key: `tcpdump:${tcpdump[1]}`,
      index: tcpdump[2] ? Number(tcpdump[2]) : -1,
      stem: captureStem(tcpdump[1]),
    };
  }
  return undefined;
}

/**
 * The pieces of the rotated capture `name` belongs to, among the file names
 * `names` of its folder, in capture order; [] unless there are at least two.
 */
export function rotatedSet(name: string, names: readonly string[]): string[] {
  const piece = rotationPiece(name);
  if (!piece) {
    return [];
  }
  const pieces = names
    .map((n) => ({ name: n, piece: rotationPiece(n) }))
    .filter((p): p is { name: string; piece: Piece } => p.piece?.key === piece.key);
  if (pieces.length < 2 || !pieces.some((p) => p.name === name)) {
    return [];
  }
  return pieces
    .sort((a, b) => a.piece.index - b.piece.index || a.name.localeCompare(b.name))
    .map((p) => p.name);
}

/** Suggested name for the merged capture: `trace.pcap3` → `trace-merged.pcapng`. */
export function mergedFileName(name: string): string {
  return `${rotationPiece(name)?.stem ?? captureStem(name)}-merged.pcapng`;
}

/** The pieces of the rotated capture `file` belongs to (full paths, in capture order); [] if none. */
export async function rotatedSiblings(file: string): Promise<string[]> {
  const dir = path.dirname(file);
  const names = await fs.readdir(dir).catch(() => [] as string[]);
  return rotatedSet(path.basename(file), names).map((n) => path.join(dir, n));
}
