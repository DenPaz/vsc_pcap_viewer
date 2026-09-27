import * as path from "node:path";
import * as vscode from "vscode";
import { ExplainOutcome, ExplainSink, aiEnabled } from "../ai";
import {
  AnomalyTarget,
  ExpertRow,
  anomalyQuery,
  defaultExpertQuestion,
  parseAnomalyArgs,
} from "../aiAnomaly";
import { STATISTICS_CONSENT } from "../aiConsent";
import { EXPLAIN_LIMITS, PACKET_DATA_CONSENT, explainQuery, parseExplainArgs } from "../aiExplain";
import { summaryQuery } from "../aiSummary";
import { PCAP_TOOLS, ToolConsent, runTool } from "../aiTools";
import { SECTION } from "../config";
import { toolsRuntime } from "../lmTools";
import type { PcapEditorProvider, PcapEditorSession } from "../pcapEditor";
import { requireSession } from "./filter";

/** "PCAP: Suggest Display Filter…": describe the packets, pick a validated filter, it lands in the filter bar. */
export async function suggestDisplayFilter(
  provider: PcapEditorProvider,
): Promise<string | undefined> {
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
    prompt:
      "Describe the packets you want to see. Only this text, the current filter and protocol/field names are sent to the language model.",
    placeHolder: "e.g. DNS queries for example.com that got no answer",
  });
  if (!request?.trim()) {
    return undefined;
  }
  const outcome = await vscode.window.withProgress(
    {
      location: vscode.ProgressLocation.Notification,
      title: "Asking the language model for display filters…",
      cancellable: true,
    },
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
    {
      title: "Suggested display filters (checked with tshark)",
      placeHolder: "Pick one to put it in the filter bar (Enter there applies it)",
      matchOnDetail: true,
    },
  );
  if (!pick) {
    return undefined;
  }
  session.reveal();
  session.prepareFilter(pick.label);
  return pick.label;
}

// ---------------------------------------------------------------------- explaining packets

function aiSetting(
  key: "allowPacketData" | "allowPacketBytes" | "allowCaptureStatistics",
): boolean {
  // Application-scoped: a workspace can't turn these on for the user.
  return vscode.workspace.getConfiguration(SECTION).get<boolean>(`ai.${key}`, false);
}

/** The user's consent to send packet data: the setting, else a one-time modal prompt that saves it. */
export async function packetDataConsent(): Promise<{ allowed: boolean; includeBytes: boolean }> {
  if (!aiSetting("allowPacketData")) {
    const allow = "Allow";
    const choice = await vscode.window.showWarningMessage(
      "Send packet data to the language model?",
      { modal: true, detail: PACKET_DATA_CONSENT },
      allow,
    );
    if (choice !== allow) {
      return { allowed: false, includeBytes: false };
    }
    await vscode.workspace
      .getConfiguration(SECTION)
      .update("ai.allowPacketData", true, vscode.ConfigurationTarget.Global);
  }
  return { allowed: true, includeBytes: aiSetting("allowPacketBytes") };
}

/** What the tools may return, from the settings (allowing packet data implies statistics). */
export function toolConsent(): ToolConsent {
  const packetData = aiSetting("allowPacketData");
  return { statistics: packetData || aiSetting("allowCaptureStatistics"), packetData };
}

/**
 * The user's consent to send statistics computed from the capture (summary,
 * anomalies, tools): the setting (or allowPacketData), else a one-time modal
 * prompt that saves it.
 */
export async function statisticsConsent(): Promise<boolean> {
  if (toolConsent().statistics) {
    return true;
  }
  const allow = "Allow";
  const choice = await vscode.window.showWarningMessage(
    "Send statistics computed from the capture to the language model?",
    { modal: true, detail: STATISTICS_CONSENT },
    allow,
  );
  if (choice !== allow) {
    return false;
  }
  await vscode.workspace
    .getConfiguration(SECTION)
    .update("ai.allowCaptureStatistics", true, vscode.ConfigurationTarget.Global);
  return true;
}

function statisticsRefused(stream: vscode.ChatResponseStream, what: string): void {
  stream.markdown(
    `${what} sends statistics computed from the capture (addresses, host names, counts) to the language model, so it needs your permission first.`,
  );
  stream.button({
    command: "workbench.action.openSettings",
    title: "Open Setting",
    arguments: [`${SECTION}.ai.allowCaptureStatistics`],
  });
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
async function explainInChat(
  provider: PcapEditorProvider,
  prompt: string,
  stream: vscode.ChatResponseStream,
  token: vscode.CancellationToken,
): Promise<void> {
  const session = provider.activeSession;
  if (!session?.openInfo) {
    stream.markdown(
      "Open a capture in the PCAP Viewer first, then ask about packets, e.g. *@pcap /explain 12*.",
    );
    return;
  }
  const args = parseExplainArgs(prompt);
  const frames = framesToExplain(session, args.frames);
  if (!frames.length) {
    stream.markdown(
      "Which packets? Name them (*@pcap /explain 12 15-17*) or select them in the packet list first.",
    );
    return;
  }
  const consent = await packetDataConsent();
  if (!consent.allowed) {
    stream.markdown(
      "Explaining packets sends their contents to the language model, so it needs your permission first.",
    );
    stream.button({
      command: "workbench.action.openSettings",
      title: "Open Setting",
      arguments: [`${SECTION}.ai.allowPacketData`],
    });
    return;
  }
  const sink: ExplainSink = {
    progress: (m) => stream.progress(m),
    markdown: (t) => stream.markdown(t),
  };
  const outcome = await session.explainPackets(
    frames,
    args.question,
    consent.includeBytes,
    sink,
    token,
  );
  explainButtons(outcome, (command, title, arg) =>
    stream.button({ command, title, arguments: [arg] }),
  );
  if (outcome.message && outcome.message !== "Cancelled.") {
    stream.markdown(`\n\n*${outcome.message}*`);
  }
}

function explainButtons(
  outcome: ExplainOutcome,
  add: (command: string, title: string, arg: number | string) => void,
): void {
  for (const frame of outcome.frames) {
    add("pcapViewer.goToPacket", `Go to packet ${frame}`, frame);
  }
  for (const filter of outcome.filters) {
    add("pcapViewer.applyFilter", `Apply filter: ${shorten(filter)}`, filter);
  }
}

/** An outcome's buttons (and note) at the end of a chat answer. */
function finishInChat(stream: vscode.ChatResponseStream, outcome: ExplainOutcome): void {
  explainButtons(outcome, (command, title, arg) =>
    stream.button({ command, title, arguments: [arg] }),
  );
  for (const need of outcome.refused ?? []) {
    const setting = need === "packetData" ? "allowPacketData" : "allowCaptureStatistics";
    stream.button({
      command: "workbench.action.openSettings",
      title: `Allow: ${setting}`,
      arguments: [`${SECTION}.ai.${setting}`],
    });
  }
  if (outcome.message && outcome.message !== "Cancelled.") {
    stream.markdown(`\n\n*${outcome.message}*`);
  }
}

const chatSink = (stream: vscode.ChatResponseStream): ExplainSink => ({
  progress: (m) => stream.progress(m),
  markdown: (t) => stream.markdown(t),
});

/** `@pcap /summary [question]`: a summary of the capture from its statistics. */
async function summaryInChat(
  provider: PcapEditorProvider,
  prompt: string,
  stream: vscode.ChatResponseStream,
  token: vscode.CancellationToken,
): Promise<void> {
  const session = provider.activeSession;
  if (!session?.openInfo) {
    stream.markdown(
      "Open a capture in the PCAP Viewer first, then ask for a summary with *@pcap /summary*.",
    );
    return;
  }
  if (!(await statisticsConsent())) {
    statisticsRefused(stream, "Summarizing a capture");
    return;
  }
  finishInChat(stream, await session.summarize(prompt.trim(), chatSink(stream), token));
}

/** Expert rows sent by the Expert Information panel, by reference (`@pcap /anomaly expert #N`). */
const expertSelections = new Map<number, ExpertRow[]>();
let nextSelection = 1;
const MAX_SELECTIONS = 20;

function keepSelection(rows: ExpertRow[]): number {
  const ref = nextSelection++;
  expertSelections.set(ref, rows);
  for (const old of expertSelections.keys()) {
    if (expertSelections.size <= MAX_SELECTIONS) {
      break;
    }
    expertSelections.delete(old);
  }
  return ref;
}

/** `@pcap /anomaly stream N | expert [#ref] [question]`: explain expert information or a TCP stream. */
async function anomalyInChat(
  provider: PcapEditorProvider,
  prompt: string,
  stream: vscode.ChatResponseStream,
  token: vscode.CancellationToken,
): Promise<void> {
  const session = provider.activeSession;
  if (!session?.openInfo) {
    stream.markdown(
      "Open a capture in the PCAP Viewer first, then ask about its expert information (*@pcap /anomaly*) or a TCP stream (*@pcap /anomaly stream 3*).",
    );
    return;
  }
  const { target, question } = parseAnomalyArgs(prompt);
  let rows: ExpertRow[] | undefined;
  if (target.kind === "expert" && target.ref !== undefined) {
    rows = expertSelections.get(target.ref);
    if (!rows) {
      stream.markdown(
        "*That selection is no longer available: explaining the capture's errors and warnings instead.*\n\n",
      );
    }
  }
  if (!(await statisticsConsent())) {
    statisticsRefused(stream, "Explaining expert information or a TCP stream");
    return;
  }
  finishInChat(
    stream,
    await session.explainAnomaly({ target, rows, question }, chatSink(stream), token),
  );
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
    log.info(
      `workbench.action.chat.open failed (${(err as Error)?.message ?? err}); asking the language model directly`,
    );
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
  await answerInEditor(
    `Packets ${frames.slice(0, EXPLAIN_LIMITS.maxPackets).join(", ")}`,
    "Explaining packets…",
    (sink, token) => session.explainPackets(frames, "", consent.includeBytes, sink, token),
  );
}

/** Stream an answer into a new untitled Markdown editor beside the capture, then offer its buttons. */
async function answerInEditor(
  heading: string,
  progressTitle: string,
  run: (sink: ExplainSink, token: vscode.CancellationToken) => Promise<ExplainOutcome>,
): Promise<void> {
  const doc = await vscode.workspace.openTextDocument({
    language: "markdown",
    content: `# ${heading}\n\n`,
  });
  const editor = await vscode.window.showTextDocument(doc, {
    viewColumn: vscode.ViewColumn.Beside,
    preview: false,
  });
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
    {
      location: vscode.ProgressLocation.Notification,
      title: progressTitle,
      cancellable: true,
    },
    async (progress, token) => {
      const timer = setInterval(() => void flush(), 150);
      try {
        const sink: ExplainSink = {
          progress: (m) => progress.report({ message: m }),
          markdown: (t) => (pending += t),
        };
        return await run(sink, token);
      } finally {
        clearInterval(timer);
        await flush();
      }
    },
  );
  if (!outcome.frames.length && !outcome.filters.length) {
    if (outcome.message && outcome.message !== "Cancelled.") {
      void vscode.window.showInformationMessage(`PCAP Viewer: ${outcome.message}`);
    }
    return;
  }
  const actions: { title: string; run: () => void }[] = [];
  explainButtons(outcome, (command, title, arg) =>
    actions.push({ title, run: () => void vscode.commands.executeCommand(command, arg) }),
  );
  const shown = actions.slice(0, 3); // a notification shows a few buttons
  const pick = await vscode.window.showInformationMessage(
    outcome.message ?? "Explanation ready.",
    ...shown.map((a) => a.title),
  );
  shown.find((a) => a.title === pick)?.run();
}

/** "PCAP: Summarize Capture with Copilot": @pcap /summary in the chat view, else a direct request. */
export async function summarizeCapture(
  provider: PcapEditorProvider,
  log: vscode.LogOutputChannel,
): Promise<void> {
  const session = requireSession(provider);
  if (!session) {
    return;
  }
  if (!aiEnabled()) {
    void vscode.window.showInformationMessage("AI help is turned off (pcapViewer.ai.enabled).");
    return;
  }
  if (await openChatWith(summaryQuery(), log)) {
    return;
  }
  if (await statisticsConsent()) {
    await answerInEditor(
      `Summary of ${path.basename(session.uri.fsPath)}`,
      "Summarizing the capture…",
      (sink, token) => session.summarize("", sink, token),
    );
  }
}

/** What the Expert Information and TCP Stream Graph panels ask about (their "Ask Copilot…" buttons). */
export type AnomalyAsk =
  | { kind: "expert"; rows: ExpertRow[]; question?: string; sessionId?: number }
  | { kind: "stream"; stream: number; question?: string; sessionId?: number };

/** "Ask Copilot…" from a panel: @pcap /anomaly in the chat view, else a direct request. */
export async function askAboutAnomaly(
  provider: PcapEditorProvider,
  log: vscode.LogOutputChannel,
  ask: AnomalyAsk,
): Promise<void> {
  const session =
    provider.allSessions.find((s) => s.id === ask.sessionId) ?? requireSession(provider);
  if (!session) {
    return;
  }
  if (!aiEnabled()) {
    void vscode.window.showInformationMessage("AI help is turned off (pcapViewer.ai.enabled).");
    return;
  }
  session.activate(); // @pcap answers about the active capture
  let target: AnomalyTarget;
  let rows: ExpertRow[] | undefined;
  let question = ask.question ?? "";
  if (ask.kind === "stream") {
    target = { kind: "stream", stream: ask.stream };
    question ||= "Explain this stream: is anything wrong, and why?";
  } else {
    rows = ask.rows.length ? ask.rows : undefined;
    target = { kind: "expert", ref: rows ? keepSelection(rows) : undefined };
    question ||= rows ? defaultExpertQuestion(rows) : "";
  }
  if (await openChatWith(anomalyQuery(target, question), log)) {
    return;
  }
  if (await statisticsConsent()) {
    const heading = ask.kind === "stream" ? `TCP stream ${ask.stream}` : "Expert information";
    await answerInEditor(heading, "Asking the language model…", (sink, token) =>
      session.explainAnomaly({ target, rows, question }, sink, token),
    );
  }
}

/** "Ask Copilot About This Packet…": @pcap /explain in the chat view, else a direct request. */
export async function askAboutPackets(
  provider: PcapEditorProvider,
  log: vscode.LogOutputChannel,
  frames?: unknown,
): Promise<void> {
  const session = requireSession(provider);
  if (!session) {
    return;
  }
  if (!aiEnabled()) {
    void vscode.window.showInformationMessage("AI help is turned off (pcapViewer.ai.enabled).");
    return;
  }
  const named = Array.isArray(frames)
    ? frames.filter((n): n is number => Number.isInteger(n) && n >= 1)
    : [];
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
function registerChatParticipant(
  context: vscode.ExtensionContext,
  provider: PcapEditorProvider,
  log: vscode.LogOutputChannel,
): void {
  if (typeof vscode.chat?.createChatParticipant !== "function") {
    log.info("chat API not available: @pcap chat participant not registered");
    return;
  }
  const participant = vscode.chat.createChatParticipant(
    "pcapViewer.pcap",
    async (request, _context, stream, token) => {
      if (request.command === "explain") {
        await explainInChat(provider, request.prompt, stream, token);
        return;
      }
      if (request.command === "summary") {
        await summaryInChat(provider, request.prompt, stream, token);
        return;
      }
      if (request.command === "anomaly") {
        await anomalyInChat(provider, request.prompt, stream, token);
        return;
      }
      const session = provider.activeSession;
      if (!session?.openInfo) {
        stream.markdown(
          "Open a capture in the PCAP Viewer first, then ask me for a display filter, e.g. *@pcap DNS queries that got no answer*.",
        );
        return;
      }
      if (!request.prompt.trim()) {
        stream.markdown(
          "Describe the packets you want to see, e.g. *@pcap TCP retransmissions to port 443*.",
        );
        return;
      }
      // With language model tools: answer from computed results (counts, statistics).
      if (session.toolsAvailable && (await statisticsConsent())) {
        finishInChat(
          stream,
          await session.answerWithTools(request.prompt, toolConsent(), chatSink(stream), token),
        );
        return;
      }
      stream.progress("Asking for display filters and checking them with tshark…");
      const outcome = await session.suggestFilters(request.prompt, token);
      if (!outcome.suggestions.length) {
        stream.markdown(outcome.message ?? "I couldn't find a valid display filter for that.");
        return;
      }
      stream.markdown(
        new vscode.MarkdownString().appendText(
          `Display filters for ${path.basename(session.uri.fsPath)} (each checked with tshark):`,
        ),
      );
      for (const s of outcome.suggestions) {
        stream.markdown(
          new vscode.MarkdownString().appendCodeblock(s.filter, "").appendText(s.explanation),
        );
        stream.button({
          command: "pcapViewer.applyFilter",
          title: `Apply: ${s.filter.length > 40 ? `${s.filter.slice(0, 39)}…` : s.filter}`,
          arguments: [s.filter],
        });
      }
    },
  );
  participant.iconPath = new vscode.ThemeIcon("filter");
  context.subscriptions.push(participant);
}

export function registerAiCommands(
  context: vscode.ExtensionContext,
  provider: PcapEditorProvider,
  log: vscode.LogOutputChannel,
): void {
  context.subscriptions.push(
    vscode.commands.registerCommand("pcapViewer.suggestFilter", () =>
      suggestDisplayFilter(provider),
    ),
    vscode.commands.registerCommand("pcapViewer.askAboutPackets", (frames?: unknown) =>
      askAboutPackets(provider, log, frames),
    ),
  );
  context.subscriptions.push(
    vscode.commands.registerCommand("pcapViewer.summarizeCapture", () =>
      summarizeCapture(provider, log),
    ),
    vscode.commands.registerCommand("pcapViewer.askAboutAnomaly", (ask?: AnomalyAsk) =>
      ask
        ? askAboutAnomaly(provider, log, ask)
        : askAboutAnomaly(provider, log, { kind: "expert", rows: [] }),
    ),
  );
  registerChatParticipant(context, provider, log);
  registerLanguageModelTools(context, provider, log);
}

/**
 * The read-only tools (aiTools.ts) as VS Code language model tools, so any
 * chat that uses tools (Copilot's agent mode, other participants) can ask the
 * open capture too. @pcap runs the same tools itself. Skipped without the API.
 */
function registerLanguageModelTools(
  context: vscode.ExtensionContext,
  provider: PcapEditorProvider,
  log: vscode.LogOutputChannel,
): void {
  const runtime = toolsRuntime();
  if (!runtime) {
    log.info("language model tools API not available: PCAP tools not registered");
    return;
  }
  for (const spec of PCAP_TOOLS) {
    try {
      context.subscriptions.push(
        runtime.registerTool(spec.name, {
          invoke: async (options) => {
            const session = provider.activeSession;
            const backend = session?.backend;
            if (!session?.openInfo || !backend?.running) {
              return runtime.result("No capture is open in PCAP Viewer.");
            }
            const result = await runTool(spec.name, options.input, backend, toolConsent());
            return runtime.result(result.text);
          },
        }),
      );
    } catch (err) {
      log.warn(`could not register the ${spec.name} tool: ${(err as Error)?.message ?? err}`);
    }
  }
}
