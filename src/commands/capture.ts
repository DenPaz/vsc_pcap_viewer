import * as vscode from "vscode";
import type { BackendClient } from "../backendClient";
import { captureFileName, captureLimits } from "../captureModel";
import { getSetting } from "../config";
import { PcapEditorProvider, describeError } from "../pcapEditor";
import { newTemporaryCapture } from "../tempCaptures";
import { requireSession } from "./filter";
import { withBackend } from "./withBackend";

const LAST_INTERFACES = "pcapViewer.capture.lastInterfaces";
const LAST_FILTER = "pcapViewer.capture.lastFilter";

interface CaptureInterface {
  name: string;
  description: string;
  addresses: string[];
  loopback: boolean;
}

interface CaptureChoice {
  interfaces: string[];
  labels: string[];
  filter: string;
}

/** An interface's name for people: its friendly name ("Ethernet 2"), else its name. */
function label(i: CaptureInterface): string {
  return i.description || i.name;
}

async function pickInterfaces(
  context: vscode.ExtensionContext,
  interfaces: CaptureInterface[],
): Promise<CaptureInterface[] | undefined> {
  const last = new Set(context.globalState.get<string[]>(LAST_INTERFACES, []));
  const items = interfaces.map((i) => ({
    label: label(i),
    description: i.description && i.description !== i.name ? i.name : undefined,
    detail: [i.loopback ? "loopback" : "", ...i.addresses].filter(Boolean).join(" · ") || undefined,
    picked: last.has(i.name),
    iface: i,
  }));
  const picked = await vscode.window.showQuickPick(items, {
    title: "Start Capture: choose the interfaces",
    placeHolder: "Interfaces to capture on (several can be checked)",
    canPickMany: true,
    matchOnDescription: true,
    matchOnDetail: true,
  });
  return picked?.length ? picked.map((p) => p.iface) : undefined;
}

/** The capture filter, checked by dumpcap as it is typed (undefined: cancelled). */
async function askFilter(
  context: vscode.ExtensionContext,
  backend: BackendClient,
  iface: string,
): Promise<string | undefined> {
  let seq = 0;
  const filter = await vscode.window.showInputBox({
    title: "Start Capture: capture filter",
    prompt: "Only packets matching this capture (BPF) filter are captured. Empty: every packet.",
    placeHolder: "e.g. tcp port 443, host 10.0.0.1, not arp",
    value: context.globalState.get<string>(LAST_FILTER, ""),
    validateInput: async (text) => {
      const mine = ++seq;
      await new Promise((resolve) => setTimeout(resolve, 250));
      if (mine !== seq || !text.trim()) {
        return undefined;
      }
      try {
        const res = await backend.request<{
          valid: boolean;
          checked: boolean;
          error?: string;
          message?: string;
        }>("validate_capture_filter", { filter: text, interface: iface });
        if (mine !== seq) {
          return undefined;
        }
        if (!res.valid) {
          return `Invalid capture filter: ${res.error ?? ""}`;
        }
        if (!res.checked && res.message) {
          return {
            message: `Couldn't check the filter: ${res.message.split("\n")[0]}`,
            severity: vscode.InputBoxValidationSeverity.Warning,
          };
        }
      } catch {
        // (checked again when capturing)
      }
      return undefined;
    },
  });
  return filter === undefined ? undefined : filter.trim();
}

/**
 * "PCAP: Start Capture…": choose interfaces and a capture filter, then a new
 * (unsaved) capture opens and fills as packets arrive. `options` skips the
 * questions (tests, keybindings with arguments).
 */
export async function startCapture(
  provider: PcapEditorProvider,
  context: vscode.ExtensionContext,
  log: vscode.LogOutputChannel,
  options?: { interfaces?: unknown; filter?: unknown },
): Promise<vscode.Uri | undefined> {
  let choice: CaptureChoice | undefined;
  try {
    choice = await withBackend(provider, context, log, async (backend) => {
      const given = Array.isArray(options?.interfaces)
        ? options.interfaces.filter((i): i is string => typeof i === "string" && !!i)
        : [];
      if (given.length) {
        return {
          interfaces: given,
          labels: given,
          filter: typeof options?.filter === "string" ? options.filter.trim() : "",
        };
      }
      const res = await backend.request<{ interfaces: CaptureInterface[] }>(
        "list_interfaces",
        {},
        { timeoutMs: 30_000 },
      );
      if (!res.interfaces.length) {
        throw new Error(
          "dumpcap lists no interfaces to capture on. It may lack the permission to see them " +
            "(see the PCAP Viewer README: Live capture).",
        );
      }
      const picked = await pickInterfaces(context, res.interfaces);
      if (!picked) {
        return undefined;
      }
      const filter = await askFilter(context, backend, picked[0].name);
      if (filter === undefined) {
        return undefined;
      }
      return { interfaces: picked.map((i) => i.name), labels: picked.map(label), filter };
    });
  } catch (err) {
    log.error(`capture: ${describeError(err)}`);
    void vscode.window
      .showErrorMessage(`PCAP Viewer: ${describeError(err)}`, "Show Log")
      .then((c) => c && log.show());
    return undefined;
  }
  if (!choice) {
    return undefined;
  }
  await context.globalState.update(LAST_INTERFACES, choice.interfaces);
  await context.globalState.update(LAST_FILTER, choice.filter);
  const file = await newTemporaryCapture(context, captureFileName(choice.labels, new Date()));
  const uri = vscode.Uri.file(file);
  provider.queueCapture(uri, {
    interfaces: choice.interfaces,
    labels: choice.labels,
    filter: choice.filter,
    limits: captureLimits(
      getSetting<unknown>("capture.stopAfterPackets", 0),
      getSetting<unknown>("capture.stopAfterSeconds", 0),
      getSetting<unknown>("capture.stopAfterMegabytes", 0),
    ),
    promiscuous: getSetting<boolean>("capture.promiscuous", true) !== false,
  });
  await vscode.commands.executeCommand("vscode.openWith", uri, PcapEditorProvider.viewType);
  return uri;
}

export function registerCaptureCommands(
  context: vscode.ExtensionContext,
  provider: PcapEditorProvider,
  log: vscode.LogOutputChannel,
): void {
  context.subscriptions.push(
    vscode.commands.registerCommand("pcapViewer.startCapture", (options?: unknown) =>
      startCapture(
        provider,
        context,
        log,
        options && typeof options === "object" ? (options as Record<string, unknown>) : undefined,
      ),
    ),
    vscode.commands.registerCommand("pcapViewer.stopCapture", async () => {
      const session = requireSession(provider);
      if (session && !session.capturing) {
        void vscode.window.showInformationMessage("This capture is not running.");
        return;
      }
      await session?.stopCapture();
    }),
  );
}
