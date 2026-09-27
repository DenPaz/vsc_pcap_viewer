import * as fs from "node:fs/promises";
import * as path from "node:path";
import * as vscode from "vscode";
import { indexCacheDir } from "../pcapEditor";

async function folderBytes(dir: string): Promise<number> {
  let total = 0;
  for (const entry of await fs.readdir(dir, { withFileTypes: true }).catch(() => [])) {
    const full = path.join(dir, entry.name);
    total += entry.isDirectory()
      ? await folderBytes(full)
      : await fs.stat(full).then(
          (s) => s.size,
          () => 0,
        );
  }
  return total;
}

/** "PCAP: Clear Index Cache": delete every saved packet-list index. Open captures keep working (they use their own copy). */
export async function clearIndexCache(context: vscode.ExtensionContext): Promise<void> {
  const dir = indexCacheDir(context);
  const entries = (await fs.readdir(dir, { withFileTypes: true }).catch(() => [])).filter(
    (e) => e.isDirectory() && !e.name.startsWith("."),
  );
  const bytes = await folderBytes(dir);
  await fs.rm(dir, { recursive: true, force: true });
  const n = entries.length;
  void vscode.window.showInformationMessage(
    n
      ? `PCAP Viewer: cleared ${n} saved index${n === 1 ? "" : "es"} (${(bytes / 1e6).toFixed(1)} MB).`
      : "PCAP Viewer: no saved indexes to clear.",
  );
}

export function registerIndexCacheCommands(context: vscode.ExtensionContext): void {
  context.subscriptions.push(
    vscode.commands.registerCommand("pcapViewer.clearIndexCache", () => clearIndexCache(context)),
  );
}
