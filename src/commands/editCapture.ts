import * as os from "node:os";
import * as path from "node:path";
import * as vscode from "vscode";
import { RpcError } from "../backendClient";
import {
  epochNs,
  formatDateTime,
  nsToSeconds,
  parseCaptureTime,
  parseDateTime,
  parseDuration,
} from "../captureModel";
import { readSettings } from "../config";
import { PcapEditorProvider, PcapEditorSession, describeError } from "../pcapEditor";
import { exportFileName } from "../settingsModel";
import { discardTemporaryCapture, newTemporaryCapture } from "../tempCaptures";
import { requireSession } from "./filter";

/** The operations of the backend's edit_capture (editing.py). */
export type EditOperation = "timeShift" | "dedup" | "keep" | "truncate" | "injectSecrets" | "split";

const OPERATIONS: { op: EditOperation; label: string; detail: string; suffix: string }[] = [
  {
    op: "timeShift",
    label: "Time Shift…",
    detail: "Move every packet's timestamp by an offset, or so the first packet has a given time",
    suffix: "shifted",
  },
  {
    op: "dedup",
    label: "Remove Duplicate Packets…",
    detail: "Drop packets identical to a recent one (e.g. captured on two interfaces)",
    suffix: "dedup",
  },
  {
    op: "keep",
    label: "Keep Packets in a Range…",
    detail: "Keep packets by number (1-100, 250) or between two times",
    suffix: "range",
  },
  {
    op: "truncate",
    label: "Truncate Packets…",
    detail: "Keep only the first bytes of each packet (headers), e.g. to share a capture",
    suffix: "truncated",
  },
  {
    op: "split",
    label: "Split Capture…",
    detail: "Write the capture as several files of N packets or N seconds each",
    suffix: "",
  },
  {
    op: "injectSecrets",
    label: "Embed TLS Keys in Capture…",
    detail: "Store a TLS key log in the capture, so it decrypts without the key log file",
    suffix: "with-keys",
  },
];

type Params = Record<string, unknown>;

async function ask(options: vscode.InputBoxOptions): Promise<string | undefined> {
  const value = await vscode.window.showInputBox({ ignoreFocusOut: true, ...options });
  return value === undefined ? undefined : value.trim();
}

async function choose<T extends vscode.QuickPickItem>(
  items: T[],
  title: string,
): Promise<T | undefined> {
  return vscode.window.showQuickPick(items, { title, ignoreFocusOut: true });
}

async function timeShiftParams(session: PcapEditorSession): Promise<Params | undefined> {
  const start = session.openInfo?.startTime;
  const how = await choose(
    [
      { label: "Shift by an Offset…", detail: "e.g. -3600, 1h 30m, -0:00:01.5", byOffset: true },
      ...(typeof start === "number"
        ? [
            {
              label: "Set the First Packet's Time…",
              detail: `now ${formatDateTime(epochNs(start))} (the others keep their spacing)`,
              byOffset: false,
            },
          ]
        : []),
    ],
    "Time Shift",
  );
  if (!how) {
    return undefined;
  }
  if (how.byOffset || typeof start !== "number") {
    const text = await ask({
      title: "Time Shift: offset",
      prompt: "Seconds (may be negative), a clock (1:30:00) or units (1d 2h 3m 4.5s, 250ms)",
      placeHolder: "-3600",
      validateInput: (t) => (parseDuration(t) === undefined ? "Not an offset" : undefined),
    });
    const ns = text === undefined ? undefined : parseDuration(text);
    return ns === undefined ? undefined : { offset: nsToSeconds(ns) };
  }
  const first = epochNs(start);
  const text = await ask({
    title: "Time Shift: time of the first packet",
    prompt: "Local time, or with a zone (Z, +02:00)",
    value: formatDateTime(first),
    validateInput: (t) =>
      parseDateTime(t) === undefined ? "Use YYYY-MM-DD HH:MM:SS[.ffffff]" : undefined,
  });
  const target = text === undefined ? undefined : parseDateTime(text);
  return target === undefined ? undefined : { offset: nsToSeconds(target - first) };
}

async function dedupParams(): Promise<Params | undefined> {
  const how = await choose(
    [
      { label: "Among the Previous 5 Packets", detail: "editcap's default", mode: "default" },
      { label: "Among the Previous N Packets…", mode: "window" },
      {
        label: "Within a Time Window…",
        detail: "identical packets less than N seconds apart",
        mode: "time",
      },
    ],
    "Remove Duplicate Packets",
  );
  if (!how) {
    return undefined;
  }
  if (how.mode === "default") {
    return { window: 5 };
  }
  if (how.mode === "window") {
    const text = await ask({
      title: "Remove Duplicate Packets: window",
      prompt: "How many previous packets to compare each packet with (1 to 1,000,000)",
      value: "100",
      validateInput: (t) =>
        /^\d+$/.test(t) && Number(t) >= 1 && Number(t) <= 1_000_000 ? undefined : "1 to 1,000,000",
    });
    return text === undefined ? undefined : { window: Number(text) };
  }
  const text = await ask({
    title: "Remove Duplicate Packets: time window",
    prompt: "Seconds, e.g. 0.000001 for packets captured twice at the same moment",
    value: "0.001",
    validateInput: (t) => {
      const ns = parseDuration(t);
      return ns !== undefined && ns > 0n ? undefined : "A positive number of seconds";
    },
  });
  const ns = text === undefined ? undefined : parseDuration(text);
  return ns === undefined ? undefined : { seconds: nsToSeconds(ns) };
}

async function keepParams(session: PcapEditorSession): Promise<Params | undefined> {
  const info = session.openInfo;
  const how = await choose(
    [
      { label: "By Packet Number…", detail: "e.g. 1-100, 250, 300-", byTime: false },
      ...(typeof info?.startTime === "number"
        ? [
            {
              label: "Between Two Times…",
              detail: "date-times or offsets from the first packet",
              byTime: true,
            },
          ]
        : []),
    ],
    "Keep Packets in a Range",
  );
  if (!how) {
    return undefined;
  }
  if (!how.byTime) {
    const text = await ask({
      title: "Keep Packets: packet numbers",
      prompt: `Packets to keep, of 1-${(info?.frames ?? 0).toLocaleString()} (the others are dropped)`,
      placeHolder: "1-100, 250, 300-",
      validateInput: (t) =>
        /^\s*\d+(-\d*)?(\s*[,\s]\s*\d+(-\d*)?)*\s*$/.test(t) ? undefined : "e.g. 1-100, 250, 300-",
    });
    return text === undefined ? undefined : { frames: text };
  }
  const first = epochNs(info?.startTime ?? 0);
  const last = typeof info?.endTime === "number" ? epochNs(info.endTime) : first;
  const read = (t: string) => parseCaptureTime(t, first);
  const invalid = (t: string) =>
    read(t) === undefined
      ? "A date-time (YYYY-MM-DD HH:MM:SS) or an offset (+10s, 1:00)"
      : undefined;
  const from = await ask({
    title: "Keep Packets: from (inclusive)",
    prompt: "A date-time, or an offset from the first packet (10, +1m 30s)",
    value: formatDateTime(first),
    validateInput: invalid,
  });
  if (from === undefined) {
    return undefined;
  }
  const to = await ask({
    title: "Keep Packets: until (exclusive)",
    prompt: "A date-time, or an offset from the first packet",
    value: formatDateTime(last + 1_000n),
    validateInput: (t) => {
      const problem = invalid(t);
      const a = read(from);
      const b = read(t);
      return (
        problem ??
        (a !== undefined && b !== undefined && b <= a ? "Must be after the start" : undefined)
      );
    },
  });
  const a = read(from);
  const b = to === undefined ? undefined : read(to);
  return a === undefined || b === undefined
    ? undefined
    : { from: nsToSeconds(a), to: nsToSeconds(b) };
}

async function truncateParams(): Promise<Params | undefined> {
  const text = await ask({
    title: "Truncate Packets",
    prompt: "Bytes to keep of each packet (the headers of most protocols fit in 128)",
    value: "128",
    validateInput: (t) =>
      /^\d+$/.test(t) && Number(t) >= 1 && Number(t) <= 262_144 ? undefined : "1 to 262,144 bytes",
  });
  return text === undefined ? undefined : { snaplen: Number(text) };
}

async function secretsParams(session: PcapEditorSession): Promise<Params | undefined> {
  const configured = readSettings(session.uri).tlsKeyLogFile;
  let keyLog = configured;
  if (configured) {
    const pick = await choose(
      [
        { label: `Use ${path.basename(configured)}`, detail: configured, file: configured },
        { label: "Choose a Key Log File…", file: "" },
      ],
      "Embed TLS Keys",
    );
    if (!pick) {
      return undefined;
    }
    keyLog = pick.file;
  }
  if (!keyLog) {
    const chosen = await vscode.window.showOpenDialog({
      title: "Embed TLS Keys: choose the key log (SSLKEYLOGFILE)",
      canSelectMany: false,
      filters: { "Key log": ["log", "txt", "keys"], "All files": ["*"] },
    });
    keyLog = chosen?.[0]?.fsPath ?? "";
  }
  return keyLog ? { keyLog } : undefined;
}

async function splitParams(
  session: PcapEditorSession,
  temporary: boolean,
): Promise<Params | undefined> {
  const how = await choose(
    [
      { label: "Every N Packets…", bySeconds: false },
      { label: "Every N Seconds…", bySeconds: true },
    ],
    "Split Capture",
  );
  if (!how) {
    return undefined;
  }
  const text = await ask({
    title: `Split Capture: ${how.bySeconds ? "seconds" : "packets"} per file`,
    value: how.bySeconds ? "60" : "100000",
    validateInput: (t) =>
      how.bySeconds
        ? parseDuration(t) !== undefined && parseDuration(t)! > 0n
          ? undefined
          : "A positive duration (60, 5m)"
        : /^\d+$/.test(t) && Number(t) >= 1
          ? undefined
          : "A whole number of packets",
  });
  if (text === undefined) {
    return undefined;
  }
  const near = temporary
    ? (vscode.workspace.workspaceFolders?.[0]?.uri.fsPath ?? os.homedir())
    : path.dirname(session.uri.fsPath);
  const folder = await vscode.window.showOpenDialog({
    title: "Split Capture: folder for the pieces",
    canSelectFiles: false,
    canSelectFolders: true,
    defaultUri: vscode.Uri.file(near),
    openLabel: "Split Here",
  });
  if (!folder?.[0]) {
    return undefined;
  }
  const amount = how.bySeconds
    ? { seconds: nsToSeconds(parseDuration(text)!) }
    : { packets: Number(text) };
  return { ...amount, dir: folder[0].fsPath };
}

/**
 * "PCAP: Edit Capture…" and its operations: an edited copy of the whole
 * capture file (editcap), opened as a new unsaved capture (split writes its
 * pieces into a folder instead). The capture itself is never changed.
 */
export async function editCapture(
  provider: PcapEditorProvider,
  context: vscode.ExtensionContext,
  log: vscode.LogOutputChannel,
  op?: EditOperation,
): Promise<string[] | undefined> {
  const session = requireSession(provider);
  const client = session?.backend;
  if (!session || !client?.running || !session.openInfo) {
    return undefined;
  }
  if (session.capturing || session.openInfo.indexing) {
    void vscode.window.showInformationMessage(
      session.capturing
        ? "Stop the capture before editing it."
        : "Wait until the capture is loaded before editing it.",
    );
    return undefined;
  }
  const entry = op ? OPERATIONS.find((o) => o.op === op) : await choose(OPERATIONS, "Edit Capture");
  if (!entry) {
    return undefined;
  }
  const temporary = session.document.temporary;
  const params = await (async () => {
    switch (entry.op) {
      case "timeShift":
        return timeShiftParams(session);
      case "dedup":
        return dedupParams();
      case "keep":
        return keepParams(session);
      case "truncate":
        return truncateParams();
      case "injectSecrets":
        return secretsParams(session);
      case "split":
        return splitParams(session, temporary);
    }
  })();
  if (!params) {
    return undefined;
  }
  let dest: string | undefined;
  if (entry.op !== "split") {
    const name = path.basename(exportFileName(session.uri.fsPath, entry.suffix, "pcapng"));
    dest = await newTemporaryCapture(context, name);
  }
  let result: { path?: string; files?: string[]; packets: number; removed?: number };
  try {
    result = await vscode.window.withProgress(
      {
        location: vscode.ProgressLocation.Notification,
        title: `${entry.label.replace(/…$/, "")}: ${path.basename(session.uri.fsPath)}`,
        cancellable: true,
      },
      (_progress, token) => {
        const pending = client.send<typeof result>(
          "edit_capture",
          { operation: entry.op, ...params, ...(dest ? { dest } : {}) },
          { timeoutMs: 0 },
        );
        token.onCancellationRequested(() => client.cancel(pending.id));
        return pending.promise;
      },
    );
  } catch (err) {
    if (dest) {
      discardTemporaryCapture(context, dest, 0);
    }
    if (!(err instanceof RpcError && err.cancelled)) {
      log.error(`edit capture (${entry.op}): ${describeError(err)}`);
      void vscode.window.showErrorMessage(`PCAP Viewer: ${describeError(err)}`);
    }
    return undefined;
  }
  if (result.files) {
    const files = result.files;
    void vscode.window
      .showInformationMessage(
        `Split into ${files.length} files in ${path.dirname(files[0] ?? "")}.`,
        "Open the First",
      )
      .then((choice) => {
        if (choice) {
          void vscode.commands.executeCommand(
            "vscode.openWith",
            vscode.Uri.file(files[0]),
            PcapEditorProvider.viewType,
          );
        }
      });
    return files;
  }
  const out = result.path ?? dest!;
  await vscode.commands.executeCommand(
    "vscode.openWith",
    vscode.Uri.file(out),
    PcapEditorProvider.viewType,
  );
  const packets = `${result.packets.toLocaleString()} packet${result.packets === 1 ? "" : "s"}`;
  const message =
    entry.op === "dedup"
      ? `Removed ${(result.removed ?? 0).toLocaleString()} duplicate packets (${packets} left). Save the new capture to keep it.`
      : `${entry.label.replace(/…$/, "")}: ${packets} in the new capture. Save it to keep it.`;
  vscode.window.setStatusBarMessage(message, 8000);
  if (entry.op === "dedup") {
    void vscode.window.showInformationMessage(message);
  }
  return [out];
}

export function registerEditCaptureCommands(
  context: vscode.ExtensionContext,
  provider: PcapEditorProvider,
  log: vscode.LogOutputChannel,
): void {
  const commands: [string, EditOperation | undefined][] = [
    ["pcapViewer.editCapture", undefined],
    ["pcapViewer.timeShift", "timeShift"],
    ["pcapViewer.removeDuplicates", "dedup"],
    ["pcapViewer.keepPackets", "keep"],
    ["pcapViewer.truncatePackets", "truncate"],
    ["pcapViewer.splitCapture", "split"],
    ["pcapViewer.embedTlsKeys", "injectSecrets"],
  ];
  for (const [id, op] of commands) {
    context.subscriptions.push(
      vscode.commands.registerCommand(id, () => editCapture(provider, context, log, op)),
    );
  }
}
