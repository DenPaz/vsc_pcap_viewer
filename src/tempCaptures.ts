import * as crypto from "node:crypto";
import * as fs from "node:fs";
import * as path from "node:path";
import type * as vscode from "vscode";

/**
 * Unsaved captures (live captures and the results of capture editing) are
 * files in the extension's storage, one folder each so the editor tab shows
 * a meaningful name. Their editors are always "dirty": saving asks where to
 * keep the capture, and closing without saving discards it.
 */
export function temporaryCapturesDir(context: vscode.ExtensionContext): string {
  return path.join(context.globalStorageUri.fsPath, "captures");
}

/** Whether `uri` is an unsaved capture (it lives in temporaryCapturesDir). */
export function isTemporaryCapture(context: vscode.ExtensionContext, uri: vscode.Uri): boolean {
  if (uri.scheme !== "file") {
    return false;
  }
  const rel = path.relative(temporaryCapturesDir(context), uri.fsPath);
  return !!rel && !rel.startsWith("..") && !path.isAbsolute(rel);
}

/** A new, empty unsaved capture file named `fileName`. */
export async function newTemporaryCapture(
  context: vscode.ExtensionContext,
  fileName: string,
): Promise<string> {
  const folder = path.join(temporaryCapturesDir(context), crypto.randomBytes(6).toString("hex"));
  await fs.promises.mkdir(folder, { recursive: true });
  const file = path.join(folder, fileName);
  await fs.promises.writeFile(file, new Uint8Array());
  return file;
}

/**
 * Delete an unsaved capture's folder, a little later: when VS Code is shutting
 * down (hot exit keeps the unsaved editor), the extension host is gone by then
 * and the capture survives for the restored editor. Windows refuses while a
 * tshark still reads it: tried again, then left to `pruneTemporaryCaptures`.
 */
export function discardTemporaryCapture(
  context: vscode.ExtensionContext,
  file: string,
  delayMs = 5000,
): void {
  const folder = path.dirname(file);
  if (path.dirname(folder) !== temporaryCapturesDir(context)) {
    return; // (never anything else)
  }
  const attempt = (left: number) =>
    setTimeout(() => {
      fs.promises.rm(folder, { recursive: true, force: true }).catch(() => {
        if (left > 0) {
          attempt(left - 1);
        }
      });
    }, delayMs);
  attempt(2);
}

/** Remove unsaved captures older than `maxAgeDays` (left behind by a crash or a restore). */
export async function pruneTemporaryCaptures(
  context: vscode.ExtensionContext,
  keep: Set<string>,
  maxAgeDays = 7,
): Promise<void> {
  const root = temporaryCapturesDir(context);
  let entries: fs.Dirent[];
  try {
    entries = await fs.promises.readdir(root, { withFileTypes: true });
  } catch {
    return;
  }
  const cutoff = Date.now() - maxAgeDays * 86_400_000;
  for (const entry of entries.filter((e) => e.isDirectory())) {
    const folder = path.join(root, entry.name);
    try {
      const stat = await fs.promises.stat(folder);
      const open = [...keep].some((f) => path.dirname(f) === folder);
      if (!open && stat.mtimeMs < cutoff) {
        await fs.promises.rm(folder, { recursive: true, force: true });
      }
    } catch {
      // (in use, or gone meanwhile)
    }
  }
}
