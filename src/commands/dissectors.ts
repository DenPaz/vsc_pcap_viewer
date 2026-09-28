import * as fs from "node:fs";
import * as path from "node:path";
import * as vscode from "vscode";
import { revealFile } from "./reveal";
import { SECTION, getSetting, readSettings, updateSetting } from "../config";
import { setLuaChoice } from "../luaChoice";
import { luaDissectorTemplate, validatePort, validateProtocolName } from "../luaTemplate";
import type { PcapEditorProvider, PcapEditorSession } from "../pcapEditor";
import {
  DecodeAsRule,
  parseDecodeAsRule,
  resolveDissectorsFolder,
  upsertDecodeAsRule,
} from "../settingsModel";
import { requireSession } from "./filter";

interface Choice {
  name: string;
  desc: string;
}

interface DissectorCheck {
  scripts: string[];
  errors: { message: string; script?: string }[];
  warnings: string[];
}

/** Layers people usually want, offered before the full list. */
const COMMON_LAYERS: Choice[] = [
  { name: "tcp.port", desc: "TCP port" },
  { name: "udp.port", desc: "UDP port" },
  { name: "sctp.port", desc: "SCTP port" },
  { name: "tls.port", desc: "TLS port" },
  { name: "ethertype", desc: "Ethertype" },
  { name: "ip.proto", desc: "IPv4 protocol" },
];

function workspaceDir(): string | undefined {
  return vscode.workspace.workspaceFolders?.[0]?.uri.fsPath;
}

function dissectorsFolder(): string | undefined {
  return resolveDissectorsFolder(
    vscode.workspace.getConfiguration(SECTION).get<string>("dissectorsFolder", ""),
    workspaceDir(),
  );
}

// ---------------------------------------------------------------------- reload

/**
 * "PCAP: Reload Dissectors": check the Lua scripts (fast, no packets read) so
 * errors show up immediately, then re-index every open capture with them.
 */
export async function reloadDissectors(
  provider: PcapEditorProvider,
  log: vscode.LogOutputChannel,
): Promise<void> {
  const sessions = provider.allSessions;
  if (!sessions.length) {
    void vscode.window.showInformationMessage("Open a capture to load the dissectors into.");
    return;
  }
  // Each capture resolves its own settings (multi-root folders can differ);
  // check every distinct script set once, with a backend that will load it.
  const checked = new Set<string>();
  const scripts = new Set<string>();
  for (const s of sessions) {
    const lua = readSettings(s.uri).luaScripts;
    lua.forEach((f) => scripts.add(f));
    const key = JSON.stringify(lua);
    if (!lua.length || checked.has(key) || !s.backend?.running) {
      continue;
    }
    checked.add(key);
    try {
      const check = await s.backend.request<DissectorCheck>(
        "check_dissectors",
        { lua },
        { timeoutMs: 60_000 },
      );
      reportDissectorCheck(check, log);
    } catch (err) {
      log.warn(`dissector check failed: ${(err as Error).message}`);
    }
  }
  await Promise.all(sessions.map((s) => s.load()));
  const n = scripts.size;
  vscode.window.setStatusBarMessage(
    `Reloaded ${sessions.length} capture(s) with ${n} Lua dissector${n === 1 ? "" : "s"}`,
    4000,
  );
}

// ---------------------------------------------------------------------- per-capture choice

/** Arguments of pcapViewer.chooseLuaDissectors (tests skip the picker): scripts by path or name. */
export interface LuaChoiceArgs {
  scripts?: string[];
}

/**
 * PCAP: Lua Dissectors…: check which of the configured scripts this capture
 * loads (none checked: no Lua; all checked: back to every configured script,
 * including ones added later). The choice is remembered per capture file and
 * the capture reloads with it; switching back to an earlier choice reopens
 * from its saved index.
 */
async function chooseLuaDissectors(provider: PcapEditorProvider, args?: LuaChoiceArgs) {
  const session = requireSession(provider);
  if (!session) {
    return;
  }
  const settings = readSettings(session.uri);
  const available = settings.luaAvailable;
  if (!available.length) {
    const pick = await vscode.window.showInformationMessage(
      "No Lua dissectors are configured. Put .lua files in the dissectors folder, or list them in pcapViewer.luaScripts.",
      "Open Dissectors Folder",
      "Open Settings",
    );
    if (pick === "Open Dissectors Folder") {
      await vscode.commands.executeCommand("pcapViewer.openDissectorsFolder");
    } else if (pick === "Open Settings") {
      await vscode.commands.executeCommand("workbench.action.openSettings", "pcapViewer.lua");
    }
    return;
  }
  let chosen: string[] | undefined;
  if (args?.scripts) {
    const wanted = new Set(args.scripts.map((f) => path.normalize(f)));
    chosen = available.filter((f) => wanted.has(path.normalize(f)) || wanted.has(path.basename(f)));
  } else {
    const active = new Set(settings.luaScripts.map((f) => path.normalize(f)));
    const items = available.map((f) => ({
      label: path.basename(f),
      description: vscode.workspace.asRelativePath(path.dirname(f)),
      picked: active.has(path.normalize(f)),
      script: f,
    }));
    const picked = await vscode.window.showQuickPick(items, {
      canPickMany: true,
      ignoreFocusOut: true,
      title: `Lua Dissectors for ${path.basename(session.uri.fsPath)}`,
      placeHolder: "Check the scripts this capture loads (none checked: no Lua dissectors)",
    });
    if (!picked) {
      return;
    }
    chosen = picked.map((i) => i.script);
  }
  // Every script checked means "all configured", so scripts added later load too.
  const next = chosen.length === available.length ? undefined : chosen;
  const current = settings.luaChosen ? settings.luaScripts : undefined;
  const same =
    current === undefined
      ? next === undefined
      : next !== undefined && next.join("\n") === current.join("\n");
  if (same) {
    return;
  }
  await setLuaChoice(session.uri, next);
  const file = path.normalize(session.uri.fsPath);
  const sessions = provider.allSessions.filter((s) => path.normalize(s.uri.fsPath) === file);
  await Promise.all(sessions.map((s) => s.load()));
  const n = next?.length ?? available.length;
  vscode.window.setStatusBarMessage(
    next?.length === 0
      ? `${path.basename(file)}: no Lua dissectors`
      : `${path.basename(file)}: ${n} Lua dissector${n === 1 ? "" : "s"}`,
    4000,
  );
}

function reportDissectorCheck(check: DissectorCheck, log: vscode.LogOutputChannel): void {
  for (const w of check.warnings) {
    log.warn(w);
  }
  for (const e of check.errors) {
    log.error(`Lua dissector error${e.script ? ` in ${e.script}` : ""}:\n${e.message}`);
  }
  if (!check.errors.length) {
    log.info(`Lua dissectors loaded without errors: ${check.scripts.join(", ") || "(none)"}`);
    return;
  }
  const first = check.errors[0];
  const where = first.script ? ` in ${path.basename(first.script)}` : "";
  const more = check.errors.length > 1 ? ` (+${check.errors.length - 1} more)` : "";
  const actions = first.script ? ["Open Script", "Show Log"] : ["Show Log"];
  void vscode.window
    .showErrorMessage(
      `Lua dissector error${where}: ${first.message.split("\n")[0].replace(/^Lua: /, "")}${more}`,
      ...actions,
    )
    .then((choice) => {
      if (choice === "Open Script" && first.script) {
        const line = /:(\d+):/.exec(first.message)?.[1];
        const selection = line
          ? new vscode.Range(Number(line) - 1, 0, Number(line) - 1, 0)
          : undefined;
        void vscode.window.showTextDocument(vscode.Uri.file(first.script), { selection });
      } else if (choice === "Show Log") {
        log.show();
      }
    });
}

// ---------------------------------------------------------------------- new / open

async function chooseDissectorsFolder(): Promise<string | undefined> {
  const ws = workspaceDir();
  type Item = vscode.QuickPickItem & { action: "workspace" | "browse" };
  const items: Item[] = [
    ...(ws
      ? [
          {
            label: "$(new-folder) Use a 'dissectors' folder in this workspace",
            description: path.join(ws, "dissectors"),
            action: "workspace" as const,
          },
        ]
      : []),
    { label: "$(folder-opened) Choose a folder…", action: "browse" },
  ];
  const pick = await vscode.window.showQuickPick(items, {
    title: "Where should Lua dissectors live?",
    placeHolder: "Every *.lua file in this folder is loaded (pcapViewer.dissectorsFolder)",
  });
  if (!pick) {
    return undefined;
  }
  if (pick.action === "workspace" && ws) {
    fs.mkdirSync(path.join(ws, "dissectors"), { recursive: true });
    await updateSetting("dissectorsFolder", "dissectors");
    return path.join(ws, "dissectors");
  }
  const chosen = await vscode.window.showOpenDialog({
    canSelectFolders: true,
    canSelectFiles: false,
    openLabel: "Use for Lua dissectors",
  });
  if (!chosen?.[0]) {
    return undefined;
  }
  const dir = chosen[0].fsPath;
  // Store workspace-relative when possible so the setting is portable.
  const rel = ws && !path.relative(ws, dir).startsWith("..") ? path.relative(ws, dir) || "." : dir;
  await updateSetting("dissectorsFolder", rel);
  return dir;
}

/** "PCAP: New Lua Dissector": scaffold a dissector in the dissectors folder and open it. */
export async function newLuaDissector(): Promise<vscode.Uri | undefined> {
  const folder = dissectorsFolder() ?? (await chooseDissectorsFolder());
  if (!folder) {
    return undefined;
  }
  const name = await vscode.window.showInputBox({
    title: "New Lua Dissector (1/4)",
    prompt: "Protocol short name (used as the display-filter prefix)",
    placeHolder: "myproto",
    validateInput: (v) =>
      validateProtocolName(v.trim()) ??
      (fs.existsSync(path.join(folder, `${v.trim()}.lua`))
        ? `${v.trim()}.lua already exists`
        : undefined),
  });
  if (!name) {
    return undefined;
  }
  const description = await vscode.window.showInputBox({
    title: "New Lua Dissector (2/4)",
    prompt: "Protocol name shown in the tree",
    value: `${name.toUpperCase()} Protocol`,
  });
  if (description === undefined) {
    return undefined;
  }
  const transport = await vscode.window.showQuickPick(
    [
      { label: "UDP", value: "udp" as const },
      { label: "TCP", value: "tcp" as const },
    ],
    { title: "New Lua Dissector (3/4)", placeHolder: "Transport the protocol runs over" },
  );
  if (!transport) {
    return undefined;
  }
  const port = await vscode.window.showInputBox({
    title: "New Lua Dissector (4/4)",
    prompt: `${transport.label} port to register on`,
    validateInput: validatePort,
  });
  if (!port) {
    return undefined;
  }
  fs.mkdirSync(folder, { recursive: true });
  const file = path.join(folder, `${name.trim()}.lua`);
  fs.writeFileSync(
    file,
    luaDissectorTemplate({
      name: name.trim(),
      description: description.trim() || name,
      transport: transport.value,
      port: Number(port),
    }),
    { flag: "wx" },
  );
  const uri = vscode.Uri.file(file);
  await vscode.window.showTextDocument(uri);
  void vscode.window
    .showInformationMessage(
      `Created ${path.basename(file)}. It is used after "PCAP: Reload Dissectors".`,
      "Reload Dissectors",
    )
    .then((choice) => choice && vscode.commands.executeCommand("pcapViewer.reloadDissectors"));
  return uri;
}

/** "PCAP: Open Dissectors Folder": reveal it (creating/configuring it if needed). */
export async function openDissectorsFolder(): Promise<void> {
  let folder = dissectorsFolder();
  if (!folder) {
    folder = await chooseDissectorsFolder();
    if (!folder) {
      return;
    }
  }
  if (!fs.existsSync(folder)) {
    const create = await vscode.window.showInformationMessage(
      `${folder} does not exist. Create it?`,
      "Create",
    );
    if (!create) {
      return;
    }
    fs.mkdirSync(folder, { recursive: true });
  }
  await revealFile(folder, true);
}

// ---------------------------------------------------------------------- Decode As

/** Ports of the selected packet, offered as ready-made Decode As targets. */
async function packetSuggestions(
  session: PcapEditorSession,
  frame: number | null,
): Promise<{ layer: string; value: string; detail: string }[]> {
  const backend = session.backend;
  if (frame === null || !backend?.running) {
    return [];
  }
  type Node = { name?: string; show?: string; children?: Node[] };
  let tree: Node[];
  try {
    tree = (
      await backend.request<{ tree: Node[] }>("packet_detail", { number: frame }, { timeoutMs: 0 })
    ).tree;
  } catch {
    return [];
  }
  const found = new Map<string, string>();
  const walk = (nodes: Node[]) => {
    for (const n of nodes) {
      if (
        n.name &&
        n.show &&
        /^(tcp|udp|sctp)\.(srcport|dstport)$/.test(n.name) &&
        !found.has(n.name)
      ) {
        found.set(n.name, n.show);
      }
      walk(n.children ?? []);
    }
  };
  walk(tree);
  const out: { layer: string; value: string; detail: string }[] = [];
  const seen = new Set<string>();
  for (const [name, value] of found) {
    const [proto, which] = name.split(".");
    const key = `${proto}.port==${value}`;
    if (!seen.has(key)) {
      seen.add(key);
      out.push({
        layer: `${proto}.port`,
        value,
        detail: `${which === "srcport" ? "source" : "destination"} port of packet ${frame}`,
      });
    }
  }
  return out;
}

/** "PCAP: Decode As…": pick layer + value (suggested from the packet), then a protocol; stored in settings. */
export async function decodeAs(
  provider: PcapEditorProvider,
  frame?: number,
): Promise<DecodeAsRule | undefined> {
  const session = requireSession(provider);
  const backend = session?.backend;
  if (!session || !backend?.running) {
    return undefined;
  }
  type LayerItem = vscode.QuickPickItem & { layer?: string; value?: string; other?: boolean };
  const suggestions = await packetSuggestions(
    session,
    typeof frame === "number" ? frame : session.selectedFrame,
  );
  const items: LayerItem[] = [
    ...suggestions.map((s) => ({
      label: `${s.layer} == ${s.value}`,
      description: s.detail,
      layer: s.layer,
      value: s.value,
    })),
    ...(suggestions.length ? [{ label: "", kind: vscode.QuickPickItemKind.Separator }] : []),
    ...COMMON_LAYERS.map((l) => ({ label: l.name, description: l.desc, layer: l.name })),
    { label: "$(list-unordered) Other layer type…", other: true },
  ];
  const pick = await vscode.window.showQuickPick(items, {
    title: "Decode As (1/2)",
    placeHolder: "What should be decoded differently?",
    matchOnDescription: true,
  });
  if (!pick) {
    return undefined;
  }
  let layer = pick.layer;
  if (pick.other) {
    const all = await backend.request<{ choices: Choice[] }>(
      "decode_as_options",
      {},
      { timeoutMs: 60_000 },
    );
    const chosen = await vscode.window.showQuickPick(
      all.choices.map((c) => ({ label: c.name, description: c.desc })),
      { title: "Decode As: layer type", matchOnDescription: true },
    );
    layer = chosen?.label;
  }
  if (!layer) {
    return undefined;
  }
  let value = pick.value;
  if (value === undefined) {
    value = (
      await vscode.window.showInputBox({
        title: `Decode As: ${layer}`,
        prompt: `Value of ${layer} to match (e.g. 8080, or a range such as 8000-8100)`,
        validateInput: (v) =>
          /^[^,\s]+$/.test(v.trim()) ? undefined : "Enter a value without spaces or commas",
      })
    )?.trim();
    if (!value) {
      return undefined;
    }
  }
  const protocols = await backend.request<{ choices: Choice[] }>(
    "decode_as_options",
    { layer },
    { timeoutMs: 60_000 },
  );
  const proto = await vscode.window.showQuickPick(
    protocols.choices.map((c) => ({ label: c.name, description: c.desc })),
    {
      title: `Decode As (2/2): ${layer} == ${value} as…`,
      placeHolder: "Protocol to decode it as",
      matchOnDescription: true,
    },
  );
  if (!proto) {
    return undefined;
  }
  const rule: DecodeAsRule = { layer, value, protocol: proto.label };
  // Read and write for the capture's own folder (multi-root: rules can differ per folder).
  const current = getSetting<string[]>("decodeAs", [], session.uri);
  await updateSetting("decodeAs", upsertDecodeAsRule(current, rule), session.uri);
  return rule;
}

const DELETE_BUTTON: vscode.QuickInputButton = {
  iconPath: new vscode.ThemeIcon("trash"),
  tooltip: "Remove rule",
};

/** "PCAP: Manage Decode As Rules": list rules, remove with the trash button, or add one. */
export async function manageDecodeAs(provider: PcapEditorProvider): Promise<void> {
  type Item = vscode.QuickPickItem & { rule?: string; add?: boolean };
  // Rules as seen by the active capture (its workspace folder), if any.
  const scope = provider.activeSession?.uri;
  const qp = vscode.window.createQuickPick<Item>();
  qp.title = "Decode As Rules";
  const build = () => {
    const rules = getSetting<string[]>("decodeAs", [], scope);
    qp.items = [
      ...rules.map((r) => {
        const parsed = parseDecodeAsRule(r);
        return {
          label: parsed ? `${parsed.layer} == ${parsed.value}` : r,
          description: parsed ? `→ ${parsed.protocol}` : "invalid rule",
          rule: r,
          buttons: [DELETE_BUTTON],
        };
      }),
      { label: "$(add) Add rule…", add: true },
    ];
    qp.placeholder = rules.length
      ? "Rules are applied to every tshark call"
      : "No Decode As rules yet";
  };
  build();
  qp.onDidTriggerItemButton(async ({ item }) => {
    const rules = getSetting<string[]>("decodeAs", [], scope);
    await updateSetting(
      "decodeAs",
      rules.filter((r) => r !== item.rule),
      scope,
    );
    build();
  });
  qp.onDidAccept(() => {
    const item = qp.selectedItems[0];
    qp.hide();
    if (item?.add) {
      void decodeAs(provider);
    }
  });
  qp.onDidHide(() => qp.dispose());
  qp.show();
}

export function registerDissectorCommands(
  context: vscode.ExtensionContext,
  provider: PcapEditorProvider,
  log: vscode.LogOutputChannel,
): void {
  context.subscriptions.push(
    vscode.commands.registerCommand("pcapViewer.reloadDissectors", () =>
      reloadDissectors(provider, log),
    ),
    vscode.commands.registerCommand("pcapViewer.chooseLuaDissectors", (args?: LuaChoiceArgs) =>
      chooseLuaDissectors(provider, args),
    ),
    vscode.commands.registerCommand("pcapViewer.newLuaDissector", () => newLuaDissector()),
    vscode.commands.registerCommand("pcapViewer.openDissectorsFolder", () =>
      openDissectorsFolder(),
    ),
    vscode.commands.registerCommand("pcapViewer.decodeAs", (frame?: number) =>
      decodeAs(provider, frame),
    ),
    vscode.commands.registerCommand("pcapViewer.manageDecodeAs", () => manageDecodeAs(provider)),
    // Offer a reload when a loaded Lua dissector is saved.
    vscode.workspace.onDidSaveTextDocument((doc) => {
      if (!provider.allSessions.length || !doc.fileName.toLowerCase().endsWith(".lua")) {
        return;
      }
      const saved = path.normalize(doc.fileName);
      const loaded = provider.allSessions.some((s) =>
        readSettings(s.uri).luaScripts.some((f) => path.normalize(f) === saved),
      );
      if (loaded) {
        void vscode.window
          .showInformationMessage(`${path.basename(doc.fileName)} saved.`, "Reload Dissectors")
          .then(
            (choice) => choice && vscode.commands.executeCommand("pcapViewer.reloadDissectors"),
          );
      }
    }),
  );
}
