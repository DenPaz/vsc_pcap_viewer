import * as path from "node:path";
import * as vscode from "vscode";
import { aiEnabled } from "../ai";
import type { PcapEditorProvider } from "../pcapEditor";
import { requireSession } from "./filter";

/** "PCAP: Suggest Display Filter…": describe the packets, pick a validated filter, it lands in the filter bar. */
export async function suggestDisplayFilter(provider: PcapEditorProvider): Promise<string | undefined> {
  const session = requireSession(provider);
  if (!session) {
    return undefined;
  }
  if (!aiEnabled()) {
    void vscode.window.showInformationMessage("AI help is turned off (pcapViewer.ai.enabled).");
    return undefined;
  }
  const request = await vscode.window.showInputBox({
    title: "Suggest Display Filter",
    prompt: "Describe the packets you want to see. Only this text, the current filter and protocol/field names are sent to the language model.",
    placeHolder: "e.g. DNS queries for example.com that got no answer",
  });
  if (!request?.trim()) {
    return undefined;
  }
  const outcome = await vscode.window.withProgress(
    { location: vscode.ProgressLocation.Notification, title: "Asking the language model for display filters…", cancellable: true },
    (_progress, token) => session.suggestFilters(request, token),
  );
  if (!outcome.suggestions.length) {
    if (outcome.message && outcome.message !== "Cancelled.") {
      void vscode.window.showInformationMessage(`PCAP Viewer: ${outcome.message}`);
    }
    return undefined;
  }
  const pick = await vscode.window.showQuickPick(
    outcome.suggestions.map((s) => ({ label: s.filter, detail: s.explanation })),
    { title: "Suggested display filters (checked with tshark)", placeHolder: "Pick one to put it in the filter bar (Enter there applies it)", matchOnDetail: true },
  );
  if (!pick) {
    return undefined;
  }
  session.reveal();
  session.prepareFilter(pick.label);
  return pick.label;
}

/**
 * "@pcap <request>" in the chat view: validated display filters for the active
 * capture, each with a button that applies it. Skipped if the chat API isn't there.
 */
function registerChatParticipant(context: vscode.ExtensionContext, provider: PcapEditorProvider, log: vscode.LogOutputChannel): void {
  if (typeof vscode.chat?.createChatParticipant !== "function") {
    log.info("chat API not available: @pcap chat participant not registered");
    return;
  }
  const participant = vscode.chat.createChatParticipant("pcapViewer.pcap", async (request, _context, stream, token) => {
    const session = provider.activeSession;
    if (!session?.openInfo) {
      stream.markdown("Open a capture in the PCAP Viewer first, then ask me for a display filter, e.g. *@pcap DNS queries that got no answer*.");
      return;
    }
    if (!request.prompt.trim()) {
      stream.markdown("Describe the packets you want to see, e.g. *@pcap TCP retransmissions to port 443*.");
      return;
    }
    stream.progress("Asking for display filters and checking them with tshark…");
    const outcome = await session.suggestFilters(request.prompt, token);
    if (!outcome.suggestions.length) {
      stream.markdown(outcome.message ?? "I couldn't find a valid display filter for that.");
      return;
    }
    stream.markdown(new vscode.MarkdownString().appendText(`Display filters for ${path.basename(session.uri.fsPath)} (each checked with tshark):`));
    for (const s of outcome.suggestions) {
      stream.markdown(new vscode.MarkdownString().appendCodeblock(s.filter, "").appendText(s.explanation));
      stream.button({ command: "pcapViewer.applyFilter", title: `Apply: ${s.filter.length > 40 ? `${s.filter.slice(0, 39)}…` : s.filter}`, arguments: [s.filter] });
    }
  });
  participant.iconPath = new vscode.ThemeIcon("filter");
  context.subscriptions.push(participant);
}

export function registerAiCommands(context: vscode.ExtensionContext, provider: PcapEditorProvider, log: vscode.LogOutputChannel): void {
  context.subscriptions.push(vscode.commands.registerCommand("pcapViewer.suggestFilter", () => suggestDisplayFilter(provider)));
  registerChatParticipant(context, provider, log);
}
