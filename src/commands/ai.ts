import * as path from "node:path";
import * as vscode from "vscode";
import { ExplainOutcome, ExplainSink, aiEnabled } from "../ai";
import { EXPLAIN_LIMITS, PACKET_DATA_CONSENT, explainQuery, parseExplainArgs } from "../aiExplain";
import { SECTION } from "../config";
import type { PcapEditorProvider, PcapEditorSession } from "../pcapEditor";
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

// ---------------------------------------------------------------------- explaining packets

function aiSetting(key: "allowPacketData" | "allowPacketBytes"): boolean {
  // Application-scoped: a workspace can't turn these on for the user.
  return vscode.workspace.getConfiguration(SECTION).get<boolean>(`ai.${key}`, false);
}

/** The user's consent to send packet data: the setting, else a one-time modal prompt that saves it. */
export async function packetDataConsent(): Promise<{ allowed: boolean; includeBytes: boolean }> {
  if (!aiSetting("allowPacketData")) {
    const allow = "Allow";
    const choice = await vscode.window.showWarningMessage("Send packet data to the language model?", { modal: true, detail: PACKET_DATA_CONSENT }, allow);
    if (choice !== allow) {
      return { allowed: false, includeBytes: false };
    }
    await vscode.workspace.getConfiguration(SECTION).update("ai.allowPacketData", true, vscode.ConfigurationTarget.Global);
  }
  return { allowed: true, includeBytes: aiSetting("allowPacketBytes") };
}

/** The frames to explain: those named, else the packets selected in the list. */
function framesToExplain(session: PcapEditorSession, named: number[]): number[] {
  if (named.length) {
    return named;
  }
  if (session.selectedFrames.length) {
    return [...session.selectedFrames].sort((a, b) => a - b);
  }
  return session.selectedFrame !== null ? [session.selectedFrame] : [];
}

const shorten = (s: string, max = 40) => (s.length > max ? `${s.slice(0, max - 1)}…` : s);

/** `@pcap /explain <frames> [question]`: stream the explanation with Go to packet / Apply filter buttons. */
async function explainInChat(provider: PcapEditorProvider, prompt: string, stream: vscode.ChatResponseStream, token: vscode.CancellationToken): Promise<void> {
  const session = provider.activeSession;
  if (!session?.openInfo) {
    stream.markdown("Open a capture in the PCAP Viewer first, then ask about packets, e.g. *@pcap /explain 12*.");
    return;
  }
  const args = parseExplainArgs(prompt);
  const frames = framesToExplain(session, args.frames);
  if (!frames.length) {
    stream.markdown("Which packets? Name them (*@pcap /explain 12 15-17*) or select them in the packet list first.");
    return;
  }
  const consent = await packetDataConsent();
  if (!consent.allowed) {
    stream.markdown("Explaining packets sends their contents to the language model, so it needs your permission first.");
    stream.button({ command: "workbench.action.openSettings", title: "Open Setting", arguments: [`${SECTION}.ai.allowPacketData`] });
    return;
  }
  const sink: ExplainSink = { progress: (m) => stream.progress(m), markdown: (t) => stream.markdown(t) };
  const outcome = await session.explainPackets(frames, args.question, consent.includeBytes, sink, token);
  explainButtons(outcome, (command, title, arg) => stream.button({ command, title, arguments: [arg] }));
  if (outcome.message && outcome.message !== "Cancelled.") {
    stream.markdown(`\n\n*${outcome.message}*`);
  }
}

function explainButtons(outcome: ExplainOutcome, add: (command: string, title: string, arg: number | string) => void): void {
  for (const frame of outcome.frames) {
    add("pcapViewer.goToPacket", `Go to packet ${frame}`, frame);
  }
  for (const filter of outcome.filters) {
    add("pcapViewer.applyFilter", `Apply filter: ${shorten(filter)}`, filter);
  }
}

/** Open the chat view with `query` sent. False when VS Code can't (no chat, or the command refuses). */
async function openChatWith(query: string, log: vscode.LogOutputChannel): Promise<boolean> {
  if (typeof vscode.chat?.createChatParticipant !== "function") {
    return false; // no @pcap participant to answer
  }
  if (!(await vscode.commands.getCommands(true)).includes("workbench.action.chat.open")) {
    return false;
  }
  try {
    await vscode.commands.executeCommand("workbench.action.chat.open", { query });
    return true;
  } catch (err) {
    log.info(`workbench.action.chat.open failed (${(err as Error)?.message ?? err}); asking the language model directly`);
    return false;
  }
}

/**
 * Without the chat view: ask the language model directly and stream the answer
 * into an untitled Markdown document, then offer the same buttons.
 */
async function explainInEditor(session: PcapEditorSession, frames: number[]): Promise<void> {
  const consent = await packetDataConsent();
  if (!consent.allowed) {
    return;
  }
  const doc = await vscode.workspace.openTextDocument({ language: "markdown", content: `# Packets ${frames.slice(0, EXPLAIN_LIMITS.maxPackets).join(", ")}\n\n` });
  const editor = await vscode.window.showTextDocument(doc, { viewColumn: vscode.ViewColumn.Beside, preview: false });
  let pending = "";
  let writing = Promise.resolve();
  const flush = () => {
    const text = pending;
    pending = "";
    writing = writing.then(async () => {
      if (text) {
        await editor.edit((e) => e.insert(doc.lineAt(doc.lineCount - 1).range.end, text));
      }
    });
    return writing;
  };
  const outcome = await vscode.window.withProgress(
    { location: vscode.ProgressLocation.Notification, title: "Explaining packets…", cancellable: true },
    async (progress, token) => {
      const timer = setInterval(() => void flush(), 150);
      try {
        const sink: ExplainSink = { progress: (m) => progress.report({ message: m }), markdown: (t) => (pending += t) };
        return await session.explainPackets(frames, "", consent.includeBytes, sink, token);
      } finally {
        clearInterval(timer);
        await flush();
      }
    },
  );
  if (!outcome.frames.length) {
    if (outcome.message && outcome.message !== "Cancelled.") {
      void vscode.window.showInformationMessage(`PCAP Viewer: ${outcome.message}`);
    }
    return;
  }
  const actions: { title: string; run: () => void }[] = [];
  explainButtons(outcome, (command, title, arg) => actions.push({ title, run: () => void vscode.commands.executeCommand(command, arg) }));
  const shown = actions.slice(0, 3); // a notification shows a few buttons
  const pick = await vscode.window.showInformationMessage(outcome.message ?? "Explanation ready.", ...shown.map((a) => a.title));
  shown.find((a) => a.title === pick)?.run();
}

/** "Ask Copilot About This Packet…": @pcap /explain in the chat view, else a direct request. */
export async function askAboutPackets(provider: PcapEditorProvider, log: vscode.LogOutputChannel, frames?: unknown): Promise<void> {
  const session = requireSession(provider);
  if (!session) {
    return;
  }
  if (!aiEnabled()) {
    void vscode.window.showInformationMessage("AI help is turned off (pcapViewer.ai.enabled).");
    return;
  }
  const named = Array.isArray(frames) ? frames.filter((n): n is number => Number.isInteger(n) && n >= 1) : [];
  const picked = framesToExplain(session, named);
  if (!picked.length) {
    void vscode.window.showInformationMessage("Select the packets to ask about first.");
    return;
  }
  if (!(await openChatWith(explainQuery(picked), log))) {
    await explainInEditor(session, picked);
  }
}

// ---------------------------------------------------------------------- chat participant

/**
 * "@pcap <request>" in the chat view: validated display filters for the active
 * capture, each with a button that applies it. "@pcap /explain <frames>" explains
 * packets (with consent: it sends packet data). Skipped if the chat API isn't there.
 */
function registerChatParticipant(context: vscode.ExtensionContext, provider: PcapEditorProvider, log: vscode.LogOutputChannel): void {
  if (typeof vscode.chat?.createChatParticipant !== "function") {
    log.info("chat API not available: @pcap chat participant not registered");
    return;
  }
  const participant = vscode.chat.createChatParticipant("pcapViewer.pcap", async (request, _context, stream, token) => {
    if (request.command === "explain") {
      await explainInChat(provider, request.prompt, stream, token);
      return;
    }
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
  context.subscriptions.push(
    vscode.commands.registerCommand("pcapViewer.suggestFilter", () => suggestDisplayFilter(provider)),
    vscode.commands.registerCommand("pcapViewer.askAboutPackets", (frames?: unknown) => askAboutPackets(provider, log, frames)),
  );
  registerChatParticipant(context, provider, log);
}
