/**
 * The consent for the AI features that send statistics computed from the
 * capture (never packet contents): the capture summary, anomaly explanations
 * and @pcap's tools. One setting, `pcapViewer.ai.allowCaptureStatistics`
 * (application-scoped), asked once with this text; allowing packet data
 * (`pcapViewer.ai.allowPacketData`) implies it. No `vscode` import: the text
 * is unit-tested against the limits it states.
 */
import { ANOMALY_LIMITS } from "./aiAnomaly";
import { SUMMARY_LIMITS } from "./aiSummary";
import { TOOL_LIMITS } from "./aiTools";

/** Exactly what the statistics-based AI features send: shown in the consent prompt (and README). */
export const STATISTICS_CONSENT =
  "Summarizing a capture, explaining expert information or a TCP stream, and answering @pcap questions with tools " +
  "send statistics computed from the capture by tshark to the language model (GitHub Copilot), never packet contents " +
  "or bytes: the capture's properties (packets, duration, size, link type); its protocol hierarchy; its top " +
  `${SUMMARY_LIMITS.maxRows} conversations and endpoints by bytes (IP addresses, ports, host names when name ` +
  "resolution is on, packet and byte counts); expert information counts and messages; packet and byte counts over " +
  `time in ${SUMMARY_LIMITS.ioBuckets} buckets; for an explanation, the selected expert entries (with up to ` +
  `${ANOMALY_LIMITS.maxFramesPerRow} packet numbers each) and their conversation, or up to ` +
  `${ANOMALY_LIMITS.maxPoints} packets of a TCP stream as sequence numbers, lengths, windows, round-trip times and ` +
  "retransmission flags; and the results of @pcap's tools (packet counts for display filters, the same statistics " +
  `with up to ${TOOL_LIMITS.maxStatsRows} rows). Listing packets (their summary lines) also needs ` +
  "pcapViewer.ai.allowPacketData. Addresses and host names can be private. Your choice is saved in the " +
  "pcapViewer.ai.allowCaptureStatistics setting (user settings only).";
