import * as fs from "node:fs";
import * as path from "node:path";
import * as vscode from "vscode";
import { RpcError } from "../backendClient";
import { guessOffsets, hasAsciiColumn, importFileName, OffsetBase, parsePorts } from "../hexDump";
import { PcapEditorProvider, describeError } from "../pcapEditor";
import { discardTemporaryCapture, newTemporaryCapture } from "../tempCaptures";
import { withBackend } from "./withBackend";

/** What the backend's import_hexdump takes besides the dump and `dest` (hexdump.py). */
export type HexDumpOptions = Record<string, string | number | boolean>;

/** Arguments of pcapViewer.importHexDump (tests and other callers skip the questions). */
export interface ImportHexDumpArgs {
  text?: string;
  input?: string;
  options?: HexDumpOptions;
}

type Pick<T> = vscode.QuickPickItem & { value: T };

const TITLE = "Import from Hex Dump";
/** How much of a file is read to guess its layout. */
const SNIFF_BYTES = 64 * 1024;

async function choose<T>(
  items: Pick<T>[],
  placeHolder: string,
  step: number,
): Promise<T | undefined> {
  const pick = await vscode.window.showQuickPick(items, {
    title: `${TITLE} (${step}/4)`,
    placeHolder,
    ignoreFocusOut: true,
  });
  return pick?.value;
}

/** Where the dump comes from: the active editor, the clipboard or a file. */
async function chooseSource(): Promise<{ text?: string; input?: string } | undefined> {
  const editor = vscode.window.activeTextEditor;
  const clipboard = await vscode.env.clipboard.readText();
  type Source = "editor" | "clipboard" | "file";
  const items: Pick<Source>[] = [];
  if (editor) {
    const selected = !editor.selection.isEmpty;
    items.push({
      label: selected ? "$(selection) Selection in the Editor" : "$(file-text) Active Editor",
      description: path.basename(editor.document.fileName),
      value: "editor",
    });
  }
  if (clipboard.trim()) {
    items.push({
      label: "$(clippy) Clipboard",
      description: clipboard.trim().split("\n")[0].slice(0, 60),
      value: "clipboard",
    });
  }
  items.push({ label: "$(folder-opened) Text File…", value: "file" });
  const source = await choose(items, "Where is the hex dump?", 1);
  switch (source) {
    case "editor": {
      const e = editor!;
      return { text: e.document.getText(e.selection.isEmpty ? undefined : e.selection) };
    }
    case "clipboard":
      return { text: clipboard };
    case "file": {
      const files = await vscode.window.showOpenDialog({
        title: TITLE,
        canSelectMany: false,
        openLabel: "Import",
        filters: { "Hex dumps": ["txt", "hex", "dump", "log"], "All files": ["*"] },
      });
      return files?.[0] ? { input: files[0].fsPath } : undefined;
    }
    default:
      return undefined;
  }
}

async function sample(source: { text?: string; input?: string }): Promise<string> {
  if (source.text !== undefined) {
    return source.text;
  }
  const handle = await fs.promises.open(source.input!, "r");
  try {
    const buf = Buffer.alloc(SNIFF_BYTES);
    const { bytesRead } = await handle.read(buf, 0, SNIFF_BYTES, 0);
    return buf.subarray(0, bytesRead).toString("utf8");
  } finally {
    await handle.close();
  }
}

const OFFSET_LABELS: Record<OffsetBase, string> = {
  hex: "Hexadecimal offsets (0000, 0010, …)",
  dec: "Decimal offsets (0000, 0016, …)",
  oct: "Octal offsets (0000, 0020, …)",
  none: "No offsets (only hex bytes)",
};

async function chooseOffsets(guess: OffsetBase): Promise<OffsetBase | undefined> {
  const order: OffsetBase[] = [
    guess,
    ...(["hex", "dec", "oct", "none"] as const).filter((b) => b !== guess),
  ];
  return choose(
    order.map((value) => ({
      label: OFFSET_LABELS[value],
      description: value === guess ? "detected" : undefined,
      value,
    })),
    "How does each line of the dump start?",
    2,
  );
}

async function askPorts(proto: string): Promise<{ srcPort: number; dstPort: number } | undefined> {
  const text = await vscode.window.showInputBox({
    title: TITLE,
    prompt: `${proto} source and destination ports of the dummy header`,
    value: "1234,1234",
    ignoreFocusOut: true,
    validateInput: (t) => {
      const r = parsePorts(t);
      return typeof r === "string" ? r : undefined;
    },
  });
  const r = text === undefined ? undefined : parsePorts(text);
  return typeof r === "object" ? r : undefined;
}

type Encapsulation = "ethernet" | "rawip" | "udp" | "tcp" | "sctp" | "linkType" | "exportPdu";

/** What the bytes are: whole frames, IP packets, or payloads behind a dummy header. */
async function chooseEncapsulation(): Promise<HexDumpOptions | undefined> {
  const kind = await choose<Encapsulation>(
    [
      {
        label: "Ethernet frames",
        description: "whole frames, as Wireshark copies them",
        value: "ethernet",
      },
      { label: "IP packets", description: "IPv4 or IPv6, no link layer", value: "rawip" },
      {
        label: "UDP payloads…",
        description: "adds dummy Ethernet, IPv4 and UDP headers",
        value: "udp",
      },
      {
        label: "TCP payloads…",
        description: "adds dummy Ethernet, IPv4 and TCP headers",
        value: "tcp",
      },
      {
        label: "SCTP payloads…",
        description: "adds dummy Ethernet, IPv4 and SCTP headers",
        value: "sctp",
      },
      { label: "Another link-layer type…", description: "a LINKTYPE number", value: "linkType" },
      {
        label: "Payloads for one dissector…",
        description: "an Exported PDU header, e.g. sip",
        value: "exportPdu",
      },
    ],
    "What do the bytes hold?",
    3,
  );
  switch (kind) {
    case "ethernet":
      return {};
    case "rawip":
      return { linkType: 101 };
    case "udp":
    case "tcp":
    case "sctp": {
      const ports = await askPorts(kind.toUpperCase());
      return ports && { header: kind, ...ports };
    }
    case "linkType": {
      const text = await vscode.window.showInputBox({
        title: TITLE,
        prompt: "LINKTYPE number (see tcpdump.org/linktypes.html), e.g. 105 for 802.11",
        ignoreFocusOut: true,
        validateInput: (t) =>
          /^\d{1,5}$/.test(t.trim()) && Number(t) <= 65535
            ? undefined
            : "Enter a number from 0 to 65535",
      });
      return text === undefined ? undefined : { linkType: Number(text.trim()) };
    }
    case "exportPdu": {
      const name = await vscode.window.showInputBox({
        title: TITLE,
        prompt: "Dissector name, e.g. sip, http or dns",
        ignoreFocusOut: true,
        validateInput: (t) =>
          /^[A-Za-z0-9][A-Za-z0-9_.-]*$/.test(t.trim()) ? undefined : "Enter a dissector name",
      });
      return name === undefined ? undefined : { header: "exportPdu", dissector: name.trim() };
    }
    default:
      return undefined;
  }
}

/** Whether each packet is preceded by a time (text2pcap's -t). */
async function chooseTimestamps(): Promise<HexDumpOptions | undefined> {
  const kind = await choose<"none" | "iso" | "custom">(
    [
      { label: "No times", description: "packets 1 µs apart", value: "none" },
      {
        label: "ISO 8601 time before each packet",
        description: "2024-05-01T10:15:14.25Z",
        value: "iso",
      },
      { label: "Another time format…", description: "strptime, e.g. %H:%M:%S.%f", value: "custom" },
    ],
    "Is there a time before each packet?",
    4,
  );
  if (kind === "none") {
    return {};
  }
  if (kind === "iso") {
    return { timestamp: "ISO" };
  }
  if (kind === "custom") {
    const format = await vscode.window.showInputBox({
      title: TITLE,
      prompt: "strptime format of the time before each packet (%f: fractions of a second)",
      value: "%H:%M:%S.%f",
      ignoreFocusOut: true,
      validateInput: (t) => (t.trim() ? undefined : "Enter a format"),
    });
    return format === undefined ? undefined : { timestamp: format.trim() };
  }
  return undefined;
}

/**
 * PCAP: Import from Hex Dump…: text2pcap turns a hex dump (from the editor,
 * the clipboard or a file) into a new unsaved capture, which opens. Needs no
 * open capture. Returns the new capture's path.
 */
export async function importHexDump(
  provider: PcapEditorProvider,
  context: vscode.ExtensionContext,
  log: vscode.LogOutputChannel,
  args?: ImportHexDumpArgs,
): Promise<string | undefined> {
  let source: { text?: string; input?: string } | undefined =
    args && (args.text !== undefined || args.input)
      ? { text: args.text, input: args.input }
      : undefined;
  let options = args?.options;
  if (!options) {
    source = source ?? (await chooseSource());
    if (!source) {
      return undefined;
    }
    const text = await sample(source);
    const offsets = await chooseOffsets(guessOffsets(text));
    const encapsulation = offsets && (await chooseEncapsulation());
    const timestamps = encapsulation && (await chooseTimestamps());
    if (!offsets || !encapsulation || !timestamps) {
      return undefined;
    }
    options = { offsets, ...encapsulation, ...timestamps };
    if (hasAsciiColumn(text)) {
      options.asciiDump = true;
    }
  }
  if (!source) {
    return undefined;
  }
  const dest = await newTemporaryCapture(context, importFileName(source.input, new Date()));
  let result: { path: string; packets: number };
  try {
    result = await vscode.window.withProgress(
      { location: vscode.ProgressLocation.Notification, title: TITLE, cancellable: true },
      (_progress, token) =>
        withBackend(provider, context, log, (client) => {
          const pending = client.send<{ path: string; packets: number }>(
            "import_hexdump",
            { ...source, ...options, dest },
            { timeoutMs: 0 },
          );
          token.onCancellationRequested(() => client.cancel(pending.id));
          return pending.promise;
        }),
    );
  } catch (err) {
    discardTemporaryCapture(context, dest, 0);
    if (!(err instanceof RpcError && err.cancelled)) {
      log.error(`import hex dump: ${describeError(err)}`);
      void vscode.window.showErrorMessage(`PCAP Viewer: ${describeError(err)}`);
    }
    return undefined;
  }
  await vscode.commands.executeCommand(
    "vscode.openWith",
    vscode.Uri.file(result.path),
    PcapEditorProvider.viewType,
  );
  const packets = `${result.packets.toLocaleString()} packet${result.packets === 1 ? "" : "s"}`;
  vscode.window.setStatusBarMessage(
    `Imported ${packets} from the hex dump. Save the new capture to keep it.`,
    8000,
  );
  return result.path;
}

export function registerImportHexDumpCommand(
  context: vscode.ExtensionContext,
  provider: PcapEditorProvider,
  log: vscode.LogOutputChannel,
): void {
  context.subscriptions.push(
    vscode.commands.registerCommand("pcapViewer.importHexDump", (args?: ImportHexDumpArgs) =>
      importHexDump(provider, context, log, args),
    ),
  );
}
