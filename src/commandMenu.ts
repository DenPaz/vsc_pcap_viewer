/**
 * The viewer's ☰ menu: every contributed PCAP Viewer command, built from
 * package.json (`contributes.commands` plus `contributes.keybindings`) so a new
 * command shows up without touching this file. Pure (no `vscode` import), so
 * it is unit-tested against the real package.json.
 */

/** Menu headings, in their order (lib.js groupCommands sorts by it too). */
export const COMMAND_GROUPS = [
  "Filters",
  "Packets",
  "Statistics",
  "Export",
  "Capture",
  "Editing",
  "Dissectors",
  "AI",
  "Other",
] as const;
export type CommandGroup = (typeof COMMAND_GROUPS)[number];

/**
 * What a command needs to be useful right now; the webview greys the entry
 * out with the reason when it's missing (lib.commandUnavailable).
 */
export type Requirement = "selection" | "marks" | "filter" | "capturing" | "ai";

export interface MenuCommand {
  id: string;
  title: string;
  /** package.json category, e.g. "PCAP Statistics". */
  category: string;
  group: CommandGroup;
  /** Key binding from package.json (`key` for Windows/Linux, `mac` for macOS). */
  keys?: { key: string; mac?: string };
  requires?: Requirement[];
}

/**
 * Contributed commands the menu leaves out, and why. Commands that are
 * registered but not contributed (e.g. pcapViewer.openCopy, which needs a
 * document URI) never appear, since the list comes from `contributes.commands`.
 */
export const EXCLUDED_COMMANDS: Readonly<Record<string, string>> = {
  "pcapViewer.savedFilters":
    "the ★ button at the other end of the same filter bar opens the saved and recent filters in place",
};

/** Which heading each command goes under (see COMMAND_GROUPS). */
const GROUP_OF: Readonly<Record<string, CommandGroup>> = {
  "pcapViewer.applyFilter": "Filters",
  "pcapViewer.clearFilter": "Filters",
  "pcapViewer.saveFilter": "Filters",
  "pcapViewer.addFilterButton": "Filters",
  "pcapViewer.manageFilterButtons": "Filters",
  "pcapViewer.goToPacket": "Packets",
  "pcapViewer.find": "Packets",
  "pcapViewer.findNext": "Packets",
  "pcapViewer.findPrevious": "Packets",
  "pcapViewer.goBack": "Packets",
  "pcapViewer.goForward": "Packets",
  "pcapViewer.nextInConversation": "Packets",
  "pcapViewer.previousInConversation": "Packets",
  "pcapViewer.firstPacket": "Packets",
  "pcapViewer.lastPacket": "Packets",
  "pcapViewer.selectAll": "Packets",
  "pcapViewer.toggleMark": "Packets",
  "pcapViewer.nextMark": "Packets",
  "pcapViewer.previousMark": "Packets",
  "pcapViewer.unmarkAll": "Packets",
  "pcapViewer.toggleTimeReference": "Packets",
  "pcapViewer.editPacketComment": "Packets",
  "pcapViewer.deletePacketComment": "Packets",
  "pcapViewer.deleteAllPacketComments": "Packets",
  "pcapViewer.followStream": "Statistics",
  "pcapViewer.followTcpStream": "Statistics",
  "pcapViewer.followUdpStream": "Statistics",
  "pcapViewer.followTlsStream": "Statistics",
  "pcapViewer.followHttpStream": "Statistics",
  "pcapViewer.exportFiltered": "Export",
  "pcapViewer.exportMarked": "Export",
  "pcapViewer.exportSelected": "Export",
  "pcapViewer.exportPacketList": "Export",
  "pcapViewer.exportDissections": "Export",
  "pcapViewer.exportPacketBytes": "Export",
  "pcapViewer.exportObjects": "Export",
  "pcapViewer.startCapture": "Capture",
  "pcapViewer.stopCapture": "Capture",
  "pcapViewer.mergeCaptures": "Capture",
  "pcapViewer.importHexDump": "Capture",
  "pcapViewer.reload": "Capture",
  "pcapViewer.editCapture": "Editing",
  "pcapViewer.timeShift": "Editing",
  "pcapViewer.removeDuplicates": "Editing",
  "pcapViewer.keepPackets": "Editing",
  "pcapViewer.truncatePackets": "Editing",
  "pcapViewer.splitCapture": "Editing",
  "pcapViewer.embedTlsKeys": "Editing",
  "pcapViewer.reloadDissectors": "Dissectors",
  "pcapViewer.newLuaDissector": "Dissectors",
  "pcapViewer.openDissectorsFolder": "Dissectors",
  "pcapViewer.decodeAs": "Dissectors",
  "pcapViewer.manageDecodeAs": "Dissectors",
  "pcapViewer.setTlsKeyLogFile": "Dissectors",
  "pcapViewer.suggestFilter": "AI",
  "pcapViewer.askAboutPackets": "AI",
  "pcapViewer.summarizeCapture": "AI",
  "pcapViewer.askAboutAnomaly": "AI",
  "pcapViewer.timeFormat": "Other",
  "pcapViewer.nameResolution": "Other",
  "pcapViewer.manageColumns": "Other",
  "pcapViewer.colorizeWithFilter": "Other",
  "pcapViewer.toggleColoring": "Other",
  "pcapViewer.manageColoringRules": "Other",
  "pcapViewer.clearIndexCache": "Other",
  "pcapViewer.showLog": "Other",
  "pcapViewer.checkEnvironment": "Other",
  "pcapViewer.openSample": "Other",
  "pcapViewer.openWalkthrough": "Other",
};

/** What each command needs (commands not listed always apply). */
const REQUIRES: Readonly<Record<string, Requirement[]>> = {
  "pcapViewer.clearFilter": ["filter"],
  "pcapViewer.nextInConversation": ["selection"],
  "pcapViewer.previousInConversation": ["selection"],
  "pcapViewer.toggleMark": ["selection"],
  "pcapViewer.nextMark": ["marks"],
  "pcapViewer.previousMark": ["marks"],
  "pcapViewer.unmarkAll": ["marks"],
  "pcapViewer.toggleTimeReference": ["selection"],
  "pcapViewer.editPacketComment": ["selection"],
  "pcapViewer.deletePacketComment": ["selection"],
  "pcapViewer.followStream": ["selection"],
  "pcapViewer.followTcpStream": ["selection"],
  "pcapViewer.followUdpStream": ["selection"],
  "pcapViewer.followTlsStream": ["selection"],
  "pcapViewer.followHttpStream": ["selection"],
  "pcapViewer.statistics.tcpStreamGraph": ["selection"],
  "pcapViewer.exportMarked": ["marks"],
  "pcapViewer.exportSelected": ["selection"],
  "pcapViewer.exportPacketBytes": ["selection"],
  "pcapViewer.stopCapture": ["capturing"],
  "pcapViewer.suggestFilter": ["ai"],
  "pcapViewer.askAboutPackets": ["ai", "selection"],
  "pcapViewer.summarizeCapture": ["ai"],
  "pcapViewer.askAboutAnomaly": ["ai"],
};

/** The heading of a command: its explicit group, else by category, else Other. */
export function commandGroup(id: string, category: string | undefined): CommandGroup {
  return GROUP_OF[id] ?? (category === "PCAP Statistics" ? "Statistics" : "Other");
}

/** Whether a command has an explicit group (a unit test keeps them all explicit). */
export function hasExplicitGroup(id: string): boolean {
  return id in GROUP_OF;
}

interface PackageJson {
  contributes?: {
    commands?: { command: string; title: string; category?: string }[];
    keybindings?: { command: string; key?: string; mac?: string }[];
  };
}

/**
 * The menu's commands in package.json order (the webview groups them): every
 * contributed `pcapViewer.*` command except EXCLUDED_COMMANDS, with its first
 * key binding and its requirements.
 */
export function buildCommandMenu(pkg: PackageJson): MenuCommand[] {
  const keys = new Map<string, { key: string; mac?: string }>();
  for (const k of pkg.contributes?.keybindings ?? []) {
    if (k.key && !keys.has(k.command)) {
      keys.set(k.command, k.mac ? { key: k.key, mac: k.mac } : { key: k.key });
    }
  }
  return (pkg.contributes?.commands ?? [])
    .filter((c) => c.command.startsWith("pcapViewer.") && !(c.command in EXCLUDED_COMMANDS))
    .map((c) => {
      const item: MenuCommand = {
        id: c.command,
        title: c.title,
        category: c.category ?? "PCAP",
        group: commandGroup(c.command, c.category),
      };
      const binding = keys.get(c.command);
      if (binding) {
        item.keys = binding;
      }
      const requires = REQUIRES[c.command];
      if (requires) {
        item.requires = [...requires];
      }
      return item;
    });
}
