import * as vscode from "vscode";
import type { PcapEditorProvider, PcapEditorSession } from "../pcapEditor";

export function requireSession(provider: PcapEditorProvider): PcapEditorSession | undefined {
  const session = provider.activeSession;
  if (!session) {
    void vscode.window.showInformationMessage(
      "Open a .pcap or .pcapng file in the PCAP Viewer first.",
    );
  }
  return session;
}

export function registerFilterCommands(
  context: vscode.ExtensionContext,
  provider: PcapEditorProvider,
): void {
  context.subscriptions.push(
    vscode.commands.registerCommand("pcapViewer.applyFilter", async (expr?: unknown) => {
      const session = requireSession(provider);
      if (!session) {
        return;
      }
      if (typeof expr === "string") {
        session.applyFilter(expr);
        return;
      }
      const value = await vscode.window.showInputBox({
        title: "Apply Display Filter",
        prompt: "Wireshark display filter, e.g. tcp.port == 443 && ip.addr == 10.0.0.1",
        value: session.currentFilter,
        validateInput: async (text) =>
          text.trim() ? await session.validateFilter(text) : undefined,
      });
      if (value !== undefined) {
        session.applyFilter(value);
      }
    }),
    vscode.commands.registerCommand("pcapViewer.clearFilter", () =>
      requireSession(provider)?.applyFilter(""),
    ),
    vscode.commands.registerCommand("pcapViewer.goToPacket", async (frame?: unknown) => {
      const session = requireSession(provider);
      if (!session) {
        return;
      }
      if (typeof frame === "number") {
        session.goTo(frame);
        return;
      }
      const total = session.openInfo?.frames ?? 0;
      const value = await vscode.window.showInputBox({
        title: "Go to Packet",
        prompt: total ? `Frame number (1–${total.toLocaleString()})` : "Frame number",
        validateInput: (text) => {
          const n = Number(text);
          return Number.isInteger(n) && n >= 1 && (!total || n <= total)
            ? undefined
            : "Enter a valid frame number";
        },
      });
      if (value) {
        session.goTo(Number(value));
      }
    }),
    vscode.commands.registerCommand("pcapViewer.reload", () =>
      requireSession(provider)?.load("Reload"),
    ),
  );
}
