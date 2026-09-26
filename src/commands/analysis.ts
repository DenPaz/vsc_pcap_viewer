import * as vscode from "vscode";
import { FOLLOW_LABELS, FollowPanel, FollowProto } from "../panels/followPanel";
import { StatsKind, StatsPanel } from "../panels/statsPanel";
import type { PcapEditorProvider } from "../pcapEditor";
import { requireSession } from "./filter";

const STATS_COMMANDS: Record<string, StatsKind> = {
  "pcapViewer.statistics.conversations": "conversations",
  "pcapViewer.statistics.endpoints": "endpoints",
  "pcapViewer.statistics.protocolHierarchy": "phs",
  "pcapViewer.statistics.ioGraph": "io",
  "pcapViewer.statistics.expertInfo": "expert",
  "pcapViewer.statistics.captureProperties": "properties",
};

/** Follow-stream and statistics commands (brief 4.5 and 4.6). */
export function registerAnalysisCommands(context: vscode.ExtensionContext, provider: PcapEditorProvider): void {
  const follow = async (proto?: FollowProto, frame?: number) => {
    const session = requireSession(provider);
    if (!session) {
      return;
    }
    const target = typeof frame === "number" ? frame : session.selectedFrame;
    if (target === null || target === undefined) {
      void vscode.window.showInformationMessage("Select a packet in the stream to follow first.");
      return;
    }
    let chosen = proto;
    if (!chosen) {
      const pick = await vscode.window.showQuickPick(
        (Object.keys(FOLLOW_LABELS) as FollowProto[]).map((p) => ({ label: `${FOLLOW_LABELS[p]} Stream`, proto: p })),
        { title: `Follow Stream (packet ${target})` },
      );
      chosen = pick?.proto;
    }
    if (chosen) {
      FollowPanel.show(context, session, chosen, target);
    }
  };
  context.subscriptions.push(
    vscode.commands.registerCommand("pcapViewer.followStream", (frame?: number) => follow(undefined, frame)),
    ...(Object.keys(FOLLOW_LABELS) as FollowProto[]).map((proto) =>
      vscode.commands.registerCommand(`pcapViewer.follow${FOLLOW_LABELS[proto][0]}${FOLLOW_LABELS[proto].slice(1).toLowerCase()}Stream`, (frame?: number) =>
        follow(proto, frame),
      ),
    ),
    ...Object.entries(STATS_COMMANDS).map(([command, kind]) =>
      vscode.commands.registerCommand(command, () => {
        const session = requireSession(provider);
        return session ? StatsPanel.show(context, session, kind) : undefined;
      }),
    ),
  );
}

