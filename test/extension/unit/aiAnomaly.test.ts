import * as assert from "node:assert/strict";
import {
  ANOMALY_LIMITS,
  ExpertRow,
  TcpPoint,
  anomalyQuery,
  buildExpertPrompt,
  buildTcpPrompt,
  defaultExpertQuestion,
  downsamplePoints,
  expertRowsFromTable,
  framesFilter,
  notableExpertRows,
  parseAnomalyArgs,
  tcpFacts,
} from "../../../src/aiAnomaly";

// [frame, time, dir, seq, len, ack, win, rtt, retrans, syn] as tcp_graph returns them.
const POINTS: TcpPoint[] = [
  [1, 0, 0, 0, 0, 0, 64240, null, 0, 1],
  [2, 0.01, 1, 0, 0, 1, 65535, 0.01, 0, 1],
  [3, 0.02, 0, 1, 100, 1, 64240, null, 0, 0],
  [4, 0.03, 1, 1, 0, 101, 0, 0.03, 0, 0], // zero window from B
  [5, 0.04, 0, 1, 100, 1, 64240, null, 1, 0], // retransmission
  [6, 0.05, 1, 1, 500, 101, 65535, 0.02, 0, 0],
];

const ROWS: ExpertRow[] = [
  {
    severity: "Warning",
    group: "Sequence",
    protocol: "TCP",
    summary: "This frame is a (suspected) retransmission",
    count: 12,
    frames: [5, 9, 14, 20, 31, 40, 41],
  },
  {
    severity: "Note",
    group: "Sequence",
    protocol: "TCP",
    summary: "Duplicate ACK (#1)",
    count: 3,
    frames: [8],
  },
];

suite("AI anomaly explanations", () => {
  test("arguments: a stream, expert rows by reference, or the overview", () => {
    assert.deepEqual(parseAnomalyArgs("stream 3 why so slow?"), {
      target: { kind: "stream", stream: 3 },
      question: "why so slow?",
    });
    assert.deepEqual(parseAnomalyArgs("tcp stream #12"), {
      target: { kind: "stream", stream: 12 },
      question: "",
    });
    assert.deepEqual(parseAnomalyArgs("expert #2 why these retransmissions?"), {
      target: { kind: "expert", ref: 2 },
      question: "why these retransmissions?",
    });
    assert.deepEqual(parseAnomalyArgs("expert"), {
      target: { kind: "expert", ref: undefined },
      question: "",
    });
    assert.deepEqual(parseAnomalyArgs("  anything wrong? "), {
      target: { kind: "expert" },
      question: "anything wrong?",
    });
    for (const target of [
      { kind: "stream" as const, stream: 7 },
      { kind: "expert" as const, ref: 4 },
      { kind: "expert" as const },
    ]) {
      assert.deepEqual(
        parseAnomalyArgs(anomalyQuery(target, "why?").replace("@pcap /anomaly ", "")),
        {
          target: target.kind === "expert" ? { kind: "expert", ref: target.ref } : target,
          question: "why?",
        },
      );
    }
    assert.equal(anomalyQuery({ kind: "stream", stream: 2 }), "@pcap /anomaly stream 2");
  });

  test("a question to start with", () => {
    assert.match(defaultExpertQuestion([ROWS[0]]), /^Why these retransmissions\?/);
    assert.match(defaultExpertQuestion([ROWS[1]]), /^Why these duplicate ACKs\?/);
    assert.match(defaultExpertQuestion(ROWS), /What do these expert information entries mean/);
  });

  test("expert rows from a stats table, and the notable ones", () => {
    const rows = expertRowsFromTable({
      columns: [
        { id: "severity", label: "Severity", numeric: false },
        { id: "summary", label: "Summary", numeric: false },
        { id: "group", label: "Group", numeric: false },
        { id: "protocol", label: "Protocol", numeric: false },
        { id: "count", label: "Count", numeric: true },
      ],
      rows: [
        { cells: ["Chat", "SYN", "Sequence", "TCP", 3], frame: 1, frames: [1, 4] },
        { cells: ["Error", "Malformed Packet", "Malformed", "DNS", 1], frame: 12 },
        { cells: ["Warning", "Retransmission", "Sequence", "TCP", 9] },
      ],
    });
    assert.deepEqual(rows[0], {
      severity: "Chat",
      group: "Sequence",
      protocol: "TCP",
      summary: "SYN",
      count: 3,
      frames: [1, 4],
    });
    assert.deepEqual(rows[1].frames, [12]);
    assert.deepEqual(
      notableExpertRows(rows, 5).map((r) => r.severity),
      ["Error", "Warning"],
    );
    assert.equal(notableExpertRows([rows[0]], 5).length, 1, "only chats: explain those");
    assert.equal(framesFilter(ROWS, 2), "frame.number in {5 8 9}");
    assert.equal(framesFilter([], 2), undefined);
  });

  test("TCP facts from every point", () => {
    const f = tcpFacts(POINTS, ["10.0.0.1:4000", "10.0.0.2:80"]);
    assert.equal(f.packets, 6);
    assert.equal(f.syns, 2);
    assert.ok(Math.abs(f.duration - 0.05) < 1e-9);
    const [a, b] = f.directions;
    assert.equal(a.label, "10.0.0.1:4000 → 10.0.0.2:80");
    assert.deepEqual([a.dataPackets, a.bytes, a.retransmissions], [2, 200, 1]);
    assert.equal(a.retransmissionRate, 0.5);
    assert.deepEqual([b.bytes, b.zeroWindows, b.minWindow, b.maxWindow], [500, 1, 65535, 65535]);
    assert.equal(f.rtt?.samples, 3);
    assert.ok(Math.abs((f.rtt?.median ?? 0) - 20) < 1e-9);
    assert.ok(Math.abs((f.rtt?.max ?? 0) - 30) < 1e-9);
    assert.equal(f.retransmissionRate, 1 / 3);
    assert.equal(tcpFacts([], []).rtt, null);
  });

  test("downsampling keeps notable points, both ends and capture order", () => {
    const many: TcpPoint[] = Array.from({ length: 1000 }, (_, i) => [
      i + 1,
      i / 100,
      i % 2,
      i * 10,
      10,
      i * 10,
      i === 500 ? 0 : 65535,
      null,
      i === 700 ? 1 : 0,
      i === 0 ? 1 : 0,
    ]);
    const sample = downsamplePoints(many, 50);
    assert.equal(sample.length, 50);
    const frames = sample.map((p) => p[0] as number);
    assert.deepEqual(
      frames,
      [...frames].sort((x, y) => x - y),
    );
    for (const must of [1, 501, 701, 1000]) {
      assert.ok(frames.includes(must), `frame ${must}`);
    }
    assert.equal(downsamplePoints(POINTS, 50).length, POINTS.length);
  });

  test("the TCP prompt: facts, a capped sample, no payloads, untrusted", () => {
    const many: TcpPoint[] = Array.from({ length: 5000 }, (_, i) => [
      i + 1,
      i / 10,
      i % 2,
      i * 100,
      100,
      i * 100,
      65535,
      0.02,
      0,
      0,
    ]);
    const prompt = buildTcpPrompt({
      question: "",
      stream: 3,
      endpoints: ["a:1", "b:2"],
      points: many,
    });
    assert.match(prompt, /TCP stream 3/);
    assert.match(prompt, /Question: Explain this stream\./);
    assert.match(prompt, /Retransmission rate/);
    assert.match(prompt, /No payloads are included/);
    assert.match(prompt, /untrusted/);
    assert.match(prompt, /only from the data given/);
    assert.match(prompt, new RegExp(`## Sample: ${ANOMALY_LIMITS.maxPoints} of 5000 packets`));
    assert.match(
      prompt,
      /frame,time,dir,seq,len,ack,win,rtt_ms,retrans,syn\n1,0,0,0,100,0,65535,20,0,0/,
    );
    assert.ok(prompt.length <= ANOMALY_LIMITS.maxPromptChars);
    const small = buildTcpPrompt(
      { question: "why?", stream: 3, endpoints: ["a:1", "b:2"], points: many },
      { ...ANOMALY_LIMITS, maxPromptChars: 4000 },
    );
    assert.ok(small.length <= 4000, `${small.length}`);
  });

  test("the expert prompt: capped rows and frames, the conversation, untrusted", () => {
    const rows = Array.from({ length: 30 }, (_, i) => ({ ...ROWS[0], summary: `message ${i}` }));
    const prompt = buildExpertPrompt({
      question: "why these retransmissions?",
      currentFilter: "",
      rows,
      conversations: {
        title: "TCP Conversations",
        columns: [
          { id: "a", label: "Address A", numeric: false },
          { id: "b", label: "Address B", numeric: false },
          { id: "bytes", label: "Bytes", numeric: true },
        ],
        rows: [{ cells: ["10.0.0.1:4000", "10.0.0.2:80", 123456] }],
      },
    });
    assert.match(prompt, /Question: why these retransmissions\?/);
    assert.equal(
      (prompt.match(/^Warning \| Sequence/gm) ?? []).length,
      ANOMALY_LIMITS.maxExpertRows,
    );
    assert.match(prompt, /\| 12 \| 5, 9, 14, 20, 31\n/, "at most 5 frames per row");
    assert.match(prompt, /\[20 more entries not included\]/);
    assert.match(prompt, /10\.0\.0\.1:4000 \| 10\.0\.0\.2:80 \| 123,456/);
    assert.match(prompt, /untrusted/);
    assert.match(
      buildExpertPrompt({ question: "", currentFilter: "", rows: ROWS, overview: true }),
      /its errors and warnings/,
    );
  });
});
