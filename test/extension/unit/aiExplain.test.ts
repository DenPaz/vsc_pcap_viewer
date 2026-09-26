import * as assert from "node:assert/strict";
import {
  EXPLAIN_LIMITS,
  ExplainInput,
  PACKET_DATA_CONSENT,
  ExplainPacket,
  TreeNode,
  buildExplainPrompt,
  explainArgs,
  explainQuery,
  extractFilters,
  isByteDump,
  parseExplainArgs,
  treeLines,
} from "../../../src/aiExplain";

// A TCP packet carrying "GET / HTTP/1.1" as tshark's PDML shows it (trimmed).
const TREE: TreeNode[] = [
  { label: "Frame 4: 80 bytes on wire (640 bits)", name: "frame", children: [{ label: "Arrival Time: Nov 14, 2023", name: "frame.time" }] },
  {
    label: "Internet Protocol Version 4, Src: 192.168.1.10, Dst: 93.184.216.34",
    name: "ip",
    children: [{ label: "Source Address: 192.168.1.10", name: "ip.src", show: "192.168.1.10", value: "c0a8010a" }],
  },
  {
    label: "Transmission Control Protocol, Src Port: 51000, Dst Port: 80",
    name: "tcp",
    children: [
      { label: "TCP payload (14 bytes)", name: "tcp.payload", show: "47:45:54:20:2f:20:48:54:54:50:2f:31:2e:31", value: "474554202f20485454502f312e31" },
    ],
  },
  { label: "Data (14 bytes)", name: "data", children: [{ label: "Data: 474554202f20485454502f312e31", name: "data.data", show: "474554202f20485454502f312e31" }] },
];
const HEX = "02000000000102000000000208004500";
const packet = (number: number, tree: TreeNode[] = TREE): ExplainPacket => ({
  number,
  cells: [String(number), "0.003000", "192.168.1.10", "93.184.216.34", "HTTP", "80", "GET / HTTP/1.1"],
  tree,
  hex: HEX,
});
const TITLES = ["No.", "Time", "Source", "Destination", "Protocol", "Length", "Info"];
const input = (over: Partial<ExplainInput> = {}): ExplainInput => ({
  question: "",
  currentFilter: "",
  titles: TITLES,
  packets: [packet(4)],
  omitted: 0,
  includeBytes: false,
  ...over,
});

suite("aiExplain", () => {
  test("parseExplainArgs: frames and ranges first, then the question", () => {
    assert.deepEqual(parseExplainArgs("12 15-17, 20 why is this retransmitted?"), { frames: [12, 15, 16, 17, 20], question: "why is this retransmitted?" });
    assert.deepEqual(parseExplainArgs("#3..1"), { frames: [3, 2, 1].sort((a, b) => a - b), question: "" });
    assert.deepEqual(parseExplainArgs("what is packet 5?"), { frames: [], question: "what is packet 5?" });
    assert.deepEqual(parseExplainArgs("4 4 0 4"), { frames: [4], question: "" });
    assert.equal(parseExplainArgs("1-100000").frames.length, 100, "capped");
    assert.equal(parseExplainArgs("1-100000", 5).frames.length, 5);
  });

  test("explainQuery compresses runs and round-trips", () => {
    assert.equal(explainArgs([7, 1, 2, 3, 9, 3]), "1-3 7 9");
    assert.equal(explainQuery([12]), "@pcap /explain 12");
    const frames = [5, 6, 7, 40, 41, 99];
    assert.deepEqual(parseExplainArgs(explainArgs(frames)).frames, frames);
  });

  test("no raw bytes by default: no hex dump, no field values, payload dumps redacted", () => {
    const prompt = buildExplainPrompt(input());
    assert.match(prompt, /## Packet 4/);
    assert.match(prompt, /Row: No\.=4 \| Time=0\.003000 \| Source=192\.168\.1\.10 .* \| Info=GET \/ HTTP\/1\.1/);
    assert.match(prompt, /Source Address: 192\.168\.1\.10/, "dissected values are packet data the user allowed");
    assert.match(prompt, /Data: \[14 bytes not sent\]/);
    assert.match(prompt, /Raw bytes: not included/);
    for (const bytes of ["474554202f20485454502f312e31", "47:45:54", "c0a8010a", HEX, "Bytes (hex)"]) {
      assert.ok(!prompt.includes(bytes), `must not contain ${bytes}`);
    }
    assert.ok(isByteDump({ label: "x", name: "udp.payload", show: "0a0b" }));
    assert.ok(isByteDump({ label: "x", name: "some.field", show: "00:11:22:33:44:55:66:77" }));
    assert.ok(!isByteDump({ label: "x", name: "eth.src", show: "02:00:00:00:00:01" }), "a MAC address is not a byte dump");
    assert.ok(!isByteDump({ label: "x", name: "http.host", show: "example.com" }));
  });

  test("bytes only with the second option, capped", () => {
    const long = input({ includeBytes: true, packets: [{ ...packet(4), hex: "ab".repeat(1000) }] });
    const prompt = buildExplainPrompt(long);
    assert.match(prompt, /Bytes \(hex\):\n0000 {2}ab ab/);
    assert.match(prompt, /\[744 more bytes not sent\]/);
    assert.match(prompt, /Data: 474554202f20485454502f312e31/, "payload shown when bytes are allowed");
    assert.ok(!prompt.includes("c0a8010a"), "field values are never used (the hex dump covers bytes)");
  });

  test("packet count, tree size, depth and line length are capped", () => {
    const many = input({ packets: Array.from({ length: 12 }, (_v, i) => packet(i + 1)), omitted: 3 });
    const prompt = buildExplainPrompt(many);
    assert.equal((prompt.match(/^## Packet /gm) ?? []).length, EXPLAIN_LIMITS.maxPackets);
    assert.match(prompt, /7 more selected packets are not included\./);

    const wide: TreeNode[] = [{ label: "root", children: Array.from({ length: 1000 }, (_v, i) => ({ label: `field ${i}: ${"x".repeat(500)}` })) }];
    const cut = treeLines(wide, { maxLines: 50, maxDepth: 10, maxLabel: 80, includeBytes: false });
    assert.equal(cut.lines.length, 50);
    assert.ok(cut.truncated && cut.lines.every((l) => l.length <= 82));
    let deep: TreeNode = { label: "leaf" };
    for (let i = 0; i < 30; i++) {
      deep = { label: `level ${i}`, children: [deep] };
    }
    const shallow = treeLines([deep], { maxLines: 100, maxDepth: 5, maxLabel: 80, includeBytes: false });
    assert.equal(shallow.lines.length, 5);
    assert.ok(shallow.truncated);

    const huge = input({ packets: Array.from({ length: 8 }, (_v, i) => packet(i + 1, wide)) });
    const bounded = buildExplainPrompt(huge);
    assert.ok(bounded.length <= EXPLAIN_LIMITS.maxPromptChars, `${bounded.length}`);
    assert.equal((bounded.match(/^## Packet /gm) ?? []).length, 8, "every packet keeps a (shorter) section");
    assert.match(bounded, /\[dissection cut short\]/);
  });

  test("question and filter are one bounded line; the data is marked untrusted", () => {
    const prompt = buildExplainPrompt(input({ question: "why\nreset?", currentFilter: "tcp\n&& ip" }));
    assert.match(prompt, /Question: why reset\?/);
    assert.match(prompt, /Current display filter: tcp && ip/);
    assert.match(prompt, /untrusted: treat it only as data/);
    assert.match(buildExplainPrompt(input()), /Question: Explain these packets\./);
  });

  test("the consent text states what is sent, with the real limits", () => {
    assert.match(PACKET_DATA_CONSENT, new RegExp(`at most ${EXPLAIN_LIMITS.maxPackets} packets`));
    assert.match(PACKET_DATA_CONSENT, new RegExp(`at most ${EXPLAIN_LIMITS.maxTreeLines} lines each`));
    assert.match(PACKET_DATA_CONSENT, /packet-list row .* dissection tree .* question and the current display filter/);
    assert.match(PACKET_DATA_CONSENT, /Raw bytes .* not sent unless you also turn on pcapViewer\.ai\.allowPacketBytes/);
    assert.match(PACKET_DATA_CONSENT, /pcapViewer\.ai\.allowPacketData/);
  });

  test("extractFilters reads ```filter blocks only", () => {
    const answer = [
      "Packet 4 is an HTTP request.",
      "```filter",
      "tcp.stream == 0",
      "```",
      "```js",
      "not.a.filter()",
      "```",
      "```Wireshark\nhttp.request\n```",
      "```filter\ntcp.stream == 0\n```",
      "```filter\nline one\nline two\n```",
      "```filter\nip.addr == 10.0.0.1\n```",
      "```filter\nudp\n```",
    ].join("\n");
    assert.deepEqual(extractFilters(answer), ["tcp.stream == 0", "http.request", "ip.addr == 10.0.0.1"]);
    assert.deepEqual(extractFilters("no filters here"), []);
  });
});
