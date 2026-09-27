import * as assert from "node:assert/strict";
import { STATISTICS_CONSENT } from "../../../src/aiConsent";
import { ANOMALY_LIMITS } from "../../../src/aiAnomaly";
import {
  SUMMARY_LIMITS,
  StatsTable,
  SummaryInput,
  buildSummaryPrompt,
  expertCounts,
  formatBytes,
  formatSeconds,
  ioOutline,
  protocolLines,
  summaryQuery,
  topRows,
} from "../../../src/aiSummary";
import { TOOL_LIMITS } from "../../../src/aiTools";

const col = (id: string, label: string, numeric = false) => ({ id, label, numeric });

// Shapes as the backend's stats method returns them (http.pcap / mixed.pcapng).
const PHS: StatsTable = {
  title: "Protocol Hierarchy",
  columns: [
    col("protocol", "Protocol"),
    col("percent_packets", "Percent Packets", true),
    col("packets", "Packets", true),
    col("percent_bytes", "Percent Bytes", true),
    col("bytes", "Bytes", true),
  ],
  rows: [
    { cells: ["eth", 100, 26, 100, 3000], depth: 0 },
    { cells: ["ip", 90, 24, 95, 2900], depth: 1 },
    { cells: ["udp", 30, 8, 20, 600], depth: 2 },
    { cells: ["dns", 23, 6, 15, 450], depth: 3 },
  ],
};

function conversations(n: number): StatsTable {
  return {
    title: "TCP Conversations",
    columns: [
      col("a", "Address A"),
      col("b", "Address B"),
      col("packets", "Packets", true),
      col("bytes", "Bytes", true),
    ],
    rows: Array.from({ length: n }, (_, i) => ({
      cells: [`10.0.0.${i}:${4000 + i}`, "93.184.216.34:443", i + 1, (i + 1) * 100],
      filter: `ip.addr == 10.0.0.${i}`,
    })),
  };
}

const EXPERT: StatsTable = {
  title: "Expert Information",
  columns: [
    col("severity", "Severity"),
    col("summary", "Summary"),
    col("group", "Group"),
    col("protocol", "Protocol"),
    col("count", "Count", true),
  ],
  rows: [
    { cells: ["Note", "Duplicate ACK (#1)", "Sequence", "TCP", 4], frames: [10] },
    { cells: ["Warning", "Previous segment not captured", "Sequence", "TCP", 2], frames: [7, 9] },
    { cells: ["Chat", "Connection establish request (SYN)", "Sequence", "TCP", 3], frames: [1] },
    { cells: ["Error", "Malformed Packet", "Malformed", "DNS", 1], frames: [12] },
  ],
};

function io(n: number): StatsTable {
  return {
    title: "I/O Graph",
    interval: 1,
    columns: [
      col("start", "Start (s)", true),
      col("end", "End (s)", true),
      col("packets", "Packets", true),
      col("bytes", "Bytes", true),
    ],
    rows: Array.from({ length: n }, (_, i) => ({ cells: [i, i + 1, i === 5 ? 100 : 1, 60] })),
  };
}

const INPUT: SummaryInput = {
  question: "",
  currentFilter: "tcp",
  info: {
    frames: 26,
    startTime: 1700000000,
    endTime: 1700000000.05,
    size: 4096,
    linkType: "ether",
    fileType: "pcapng",
  },
  protocols: PHS,
  conversations: [conversations(3)],
  endpoints: [],
  expert: EXPERT,
  io: io(24),
};

suite("AI capture summary", () => {
  test("top rows by bytes, and what was left out", () => {
    const { rows, omitted } = topRows(conversations(20), 5);
    assert.deepEqual(
      rows.map((r) => r.cells[3]),
      [2000, 1900, 1800, 1700, 1600],
    );
    assert.equal(omitted, 15);
  });

  test("protocol hierarchy lines keep the tree", () => {
    const lines = protocolLines(PHS, 3, 80);
    assert.equal(lines[0], "eth, 26 packets, 100% of packets, 3.0 kB");
    assert.match(lines[2], /^ {4}udp, 8 packets/);
    assert.equal(lines[3], "[1 more protocol rows not included]");
  });

  test("expert counts: severities in order, groups, most severe messages first", () => {
    const c = expertCounts(EXPERT, 2);
    assert.deepEqual(c.bySeverity, [
      ["Error", 1],
      ["Warning", 2],
      ["Note", 4],
      ["Chat", 3],
    ]);
    assert.deepEqual(c.byGroup[0], ["Note / Sequence", 4]);
    assert.deepEqual(
      c.top.map((e) => e.summary),
      ["Malformed Packet", "Previous segment not captured"],
    );
    assert.equal(c.omitted, 2);
  });

  test("traffic over time is merged into a few buckets", () => {
    const outline = ioOutline(io(24), 12);
    assert.equal(outline.length, 12);
    assert.deepEqual(outline[0], { start: 0, end: 2, packets: 2, bytes: 120 });
    assert.equal(outline[2].packets, 101, "the busy second is kept in its bucket");
    assert.deepEqual(ioOutline(io(0), 12), []);
  });

  test("the prompt: statistics only, untrusted, answer only from them", () => {
    const prompt = buildSummaryPrompt(INPUT);
    assert.match(prompt, /only from these statistics/i);
    assert.match(prompt, /can't be determined/);
    assert.match(prompt, /untrusted/);
    assert.match(prompt, /```filter/);
    assert.match(prompt, /Question: Summarize this capture\./);
    assert.match(prompt, /Current display filter in the viewer: tcp/);
    assert.match(prompt, /Packets: 26\nDuration: 50 ms\nFile size: 4\.1 kB\nLink type: ether/);
    assert.match(
      prompt,
      /## TCP Conversations \(top 3 by bytes\)\nAddress A \| Address B \| Packets \| Bytes/,
    );
    assert.match(prompt, /By severity: Error 1, Warning 2, Note 4, Chat 3/);
    assert.match(prompt, /## Traffic over time \(12 buckets\)/);
    assert.match(prompt, /Busiest: 4–6 s with 101 packets/);
    assert.ok(prompt.length <= SUMMARY_LIMITS.maxPromptChars);
  });

  test("the prompt stays within its limits with huge tables", () => {
    const big: SummaryInput = {
      ...INPUT,
      protocols: { ...PHS, rows: Array.from({ length: 500 }, () => PHS.rows[3]) },
      conversations: [conversations(2000), conversations(2000)],
      endpoints: [conversations(2000)],
      missing: ["endpoints"],
    };
    const prompt = buildSummaryPrompt(big);
    assert.ok(prompt.length <= SUMMARY_LIMITS.maxPromptChars, `${prompt.length}`);
    const shown = prompt.match(/^10\.0\.0\.\d+:\d+ \|/gm) ?? [];
    assert.ok(shown.length <= SUMMARY_LIMITS.maxRows * 3);
    assert.match(prompt, /\[1985 more rows not included\]|more rows not included/);
    const tiny = buildSummaryPrompt(big, { ...SUMMARY_LIMITS, maxPromptChars: 3000 });
    assert.ok(tiny.length <= 3000, `${tiny.length}`);
    assert.match(buildSummaryPrompt(big), /Not available \(could not be computed\): endpoints\./);
  });

  test("formatting helpers and the chat query", () => {
    assert.equal(formatBytes(999), "999 B");
    assert.equal(formatBytes(1_500_000), "1.5 MB");
    assert.equal(formatSeconds(0.25), "250 ms");
    assert.equal(formatSeconds(4.56), "4.6 s");
    assert.equal(formatSeconds(7322), "2 h 2 min");
    assert.equal(summaryQuery(), "@pcap /summary");
    assert.equal(summaryQuery(" what\nhappened? "), "@pcap /summary what happened?");
  });

  test("the consent text states exactly what is sent, with its limits", () => {
    assert.match(STATISTICS_CONSENT, /never packet contents or bytes/);
    assert.match(
      STATISTICS_CONSENT,
      new RegExp(`top ${SUMMARY_LIMITS.maxRows} conversations and endpoints`),
    );
    assert.match(STATISTICS_CONSENT, new RegExp(`in ${SUMMARY_LIMITS.ioBuckets} buckets`));
    assert.match(
      STATISTICS_CONSENT,
      new RegExp(`up to ${ANOMALY_LIMITS.maxFramesPerRow} packet numbers each`),
    );
    assert.match(
      STATISTICS_CONSENT,
      new RegExp(`up to ${ANOMALY_LIMITS.maxPoints} packets of a TCP stream`),
    );
    assert.match(STATISTICS_CONSENT, new RegExp(`up to ${TOOL_LIMITS.maxStatsRows} rows`));
    assert.match(STATISTICS_CONSENT, /IP addresses, ports, host names/);
    assert.match(
      STATISTICS_CONSENT,
      /pcapViewer\.ai\.allowCaptureStatistics setting \(user settings only\)/,
    );
    assert.match(
      STATISTICS_CONSENT,
      /Listing packets .* also needs pcapViewer\.ai\.allowPacketData/,
    );
  });
});
