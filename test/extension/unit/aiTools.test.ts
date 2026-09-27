import * as assert from "node:assert/strict";
import * as fs from "node:fs";
import * as path from "node:path";
import {
  LoopMessage,
  LoopModel,
  LoopPart,
  PCAP_TOOLS,
  TOOL_LIMITS,
  ToolBackend,
  ToolConsent,
  ToolResult,
  buildToolPrompt,
  notAllowed,
  runTool,
  runToolLoop,
} from "../../../src/aiTools";

const ALL: ToolConsent = { statistics: true, packetData: true };
const STATS_ONLY: ToolConsent = { statistics: true, packetData: false };
const NONE: ToolConsent = { statistics: false, packetData: false };

/** A backend answering like the real one for mixed.pcapng, recording what was asked. */
function fakeBackend(): ToolBackend & { calls: [string, Record<string, unknown>][] } {
  const calls: [string, Record<string, unknown>][] = [];
  return {
    calls,
    async request<T>(method: string, params: Record<string, unknown>): Promise<T> {
      calls.push([method, params]);
      const answer = (): unknown => {
        switch (method) {
          case "validate_filter":
            return String(params.expr).includes("==")
              ? { valid: false, error: '"==" was unexpected in this context.' }
              : { valid: true };
          case "count_matches":
            return {
              filter: params.filter,
              count: 6,
              total: 26,
              frames: [5, 6, 9].slice(0, Number(params.limit ?? 0)),
            };
          case "list_packets":
            return {
              rows: (params.frames as number[]).map((n) => ({
                number: n,
                cells: [
                  String(n),
                  "0.01",
                  "192.168.1.10",
                  "8.8.8.8",
                  "DNS",
                  "74",
                  "Standard query 0x1 A example.com",
                  "extra",
                ],
              })),
            };
          case "capture_info":
            return {
              frames: 26,
              startTime: 1700000000,
              endTime: 1700000000.05,
              size: 4096,
              linkType: "ether",
              fileType: "pcapng",
            };
          case "field_index":
            return {
              protocols: [{ name: "dns", desc: "Domain Name System" }],
              fields: [{ name: "dns.flags.rcode", desc: "Reply code", type: "FT_UINT16" }],
            };
          case "stats":
            return {
              title: "UDP Conversations",
              columns: [
                { id: "a", label: "Address A", numeric: false },
                { id: "b", label: "Address B", numeric: false },
                { id: "bytes", label: "Bytes", numeric: true },
              ],
              rows: Array.from({ length: 40 }, (_, i) => ({
                cells: [`10.0.0.${i}`, "8.8.8.8", i],
              })),
            };
          default:
            throw new Error(`unexpected ${method}`);
        }
      };
      return answer() as T;
    },
  };
}

/** A model that plays a script: each round, the parts it "streams". Records what it was sent. */
function scriptedModel(
  rounds: LoopPart[][],
): LoopModel & { sent: { messages: LoopMessage[]; tools: string[] }[] } {
  const sent: { messages: LoopMessage[]; tools: string[] }[] = [];
  return {
    sent,
    async *send(messages, tools) {
      sent.push({ messages: structuredClone([...messages]), tools: tools.map((t) => t.name) });
      for (const part of rounds[Math.min(sent.length - 1, rounds.length - 1)]) {
        yield part;
      }
    },
  };
}

const call = (callId: string, name: string, input: unknown): LoopPart => ({
  type: "call",
  callId,
  name,
  input,
});
const text = (t: string): LoopPart => ({ type: "text", text: t });

suite("AI tools", () => {
  test("package.json declares exactly these tools", () => {
    const pkg = JSON.parse(
      fs.readFileSync(path.resolve(__dirname, "../../../../package.json"), "utf8"),
    );
    const declared = pkg.contributes.languageModelTools as {
      name: string;
      modelDescription: string;
      inputSchema: unknown;
    }[];
    assert.deepEqual(
      declared.map((t) => t.name),
      PCAP_TOOLS.map((t) => t.name),
    );
    const setting =
      pkg.contributes.configuration.properties["pcapViewer.ai.allowCaptureStatistics"];
    assert.equal(setting.default, false);
    assert.equal(setting.scope, "application", "a workspace can't turn it on");
    for (const tool of PCAP_TOOLS) {
      const d = declared.find((t) => t.name === tool.name);
      assert.deepEqual(d?.inputSchema, tool.inputSchema, tool.name);
      assert.equal(d?.modelDescription, tool.description, tool.name);
    }
  });

  test("consent: statistics tools and listing packets are refused without it", async () => {
    const backend = fakeBackend();
    const refused = await runTool("pcap_count", { filter: "dns" }, backend, NONE);
    assert.equal(refused.refused, "statistics");
    assert.equal(refused.text, notAllowed("statistics"));
    assert.match(refused.text, /pcapViewer\.ai\.allowCaptureStatistics/);
    const listing = await runTool("pcap_list_packets", { filter: "dns" }, backend, STATS_ONLY);
    assert.equal(listing.refused, "packetData");
    assert.match(listing.text, /pcapViewer\.ai\.allowPacketData/);
    assert.deepEqual(backend.calls, [], "nothing was asked of the backend");
    // Field names aren't capture data; allowing packet data implies statistics.
    assert.match(
      (await runTool("pcap_field_search", { prefix: "dns" }, backend, NONE)).text,
      /dns\.flags\.rcode \(FT_UINT16\): Reply code/,
    );
    assert.equal(
      (await runTool("pcap_capture_info", {}, backend, { statistics: false, packetData: true }))
        .refused,
      undefined,
    );
  });

  test("every filter is validated first; counting doesn't touch the view", async () => {
    const backend = fakeBackend();
    const bad = await runTool("pcap_count", { filter: "dns.qry.name ==" }, backend, ALL);
    assert.match(bad.text, /^Invalid display filter `dns\.qry\.name ==`: "==" was unexpected/);
    assert.equal(bad.filter, undefined);
    assert.deepEqual(
      backend.calls.map(([m]) => m),
      ["validate_filter"],
    );
    const ok = await runTool("pcap_count", { filter: "dns.flags.rcode != 0" }, backend, ALL);
    assert.equal(ok.text, "`dns.flags.rcode != 0`: 6 of 26 packets match.");
    assert.equal(ok.filter, "dns.flags.rcode != 0");
    assert.ok(
      !backend.calls.some(([m]) => m === "set_filter"),
      "the view's filter is never replaced",
    );
  });

  test("listing packets: at most 20 rows, summary columns only", async () => {
    const backend = fakeBackend();
    const res = await runTool("pcap_list_packets", { filter: "dns", limit: 500 }, backend, ALL);
    const counted = backend.calls.find(([m]) => m === "count_matches");
    assert.equal(counted?.[1].limit, TOOL_LIMITS.maxPackets);
    const listed = backend.calls.find(([m]) => m === "list_packets");
    assert.deepEqual(listed?.[1], {
      frames: [5, 6, 9],
      inView: false,
      columns: [],
      timeFormat: "relative",
    });
    assert.match(res.text, /^6 packets match `dns`; the first 3:\nNo\. \| Time \| Source/);
    assert.match(
      res.text,
      /5 \| 0\.01 \| 192\.168\.1\.10 \| 8\.8\.8\.8 \| DNS \| 74 \| Standard query 0x1 A example\.com$/m,
    );
    assert.doesNotMatch(res.text, /extra/, "no custom columns");
  });

  test("statistics are capped and summarized", async () => {
    const backend = fakeBackend();
    const res = await runTool(
      "pcap_stats",
      { kind: "conv", type: "udp", filter: "udp" },
      backend,
      ALL,
    );
    assert.deepEqual(backend.calls.at(-1), [
      "stats",
      { kind: "conversations", type: "udp", filter: "udp" },
    ]);
    assert.match(res.text, new RegExp(`40 rows, top ${TOOL_LIMITS.maxStatsRows} by bytes`));
    assert.equal(res.text.split("\n").length, TOOL_LIMITS.maxStatsRows + 2);
    assert.match(
      (await runTool("pcap_stats", { kind: "flows" }, backend, ALL)).text,
      /kind must be one of/,
    );
    assert.match(
      (await runTool("pcap_capture_info", {}, backend, ALL)).text,
      /Packets: 26\nFirst packet: 2023-11-14T22:13:20\.000Z\nDuration: 50 ms/,
    );
    assert.match((await runTool("nope", {}, backend, ALL)).text, /Unknown tool/);
  });

  test("the loop runs the tools the model calls and sends their results back", async () => {
    const model = scriptedModel([
      [text("Let me count. "), call("c1", "pcap_count", { filter: "dns.flags.rcode != 0" })],
      [text("6 DNS responses failed."), text("\n```filter\ndns.flags.rcode == 3\n```")],
    ]);
    const shown: string[] = [];
    const ran: string[] = [];
    const out = await runToolLoop(model, buildToolPrompt("how many DNS queries failed?", ""), {
      cancelled: () => false,
      onText: (t) => shown.push(t),
      onToolCall: (name) => ran.push(name),
      runTool: async (name, input) => runTool(name, input, fakeBackend(), ALL),
    });
    assert.deepEqual(ran, ["pcap_count"]);
    assert.equal(model.sent.length, 2);
    assert.deepEqual(
      model.sent[0].tools,
      PCAP_TOOLS.map((t) => t.name),
    );
    const second = model.sent[1].messages;
    assert.deepEqual(second[1], {
      role: "assistant",
      parts: [text("Let me count. "), call("c1", "pcap_count", { filter: "dns.flags.rcode != 0" })],
    });
    assert.deepEqual(second[2], {
      role: "user",
      parts: [
        { type: "result", callId: "c1", text: "`dns.flags.rcode != 0`: 6 of 26 packets match." },
      ],
    });
    assert.match(out.answer, /6 DNS responses failed/);
    assert.equal(shown.join(""), out.answer);
    assert.deepEqual(out.filters, ["dns.flags.rcode != 0", "dns.flags.rcode == 3"]);
    assert.equal(out.stopped, undefined);
  });

  test("at most 8 tool calls, then the model must answer without tools", async () => {
    const three = [
      call("a", "pcap_count", { filter: "tcp" }),
      call("b", "pcap_count", { filter: "udp" }),
      call("c", "pcap_count", { filter: "arp" }),
    ];
    const model = scriptedModel([three, three, three, [text("Enough.")]]);
    let runs = 0;
    const out = await runToolLoop(model, "q", {
      cancelled: () => false,
      onText: () => undefined,
      runTool: async (): Promise<ToolResult> => {
        runs++;
        return { text: "ok" };
      },
    });
    assert.equal(runs, TOOL_LIMITS.maxCalls);
    assert.equal(out.calls.length, TOOL_LIMITS.maxCalls);
    assert.equal(out.stopped, "calls");
    const last = model.sent.at(-1)!;
    assert.deepEqual(last.tools, [], "no tools in the final round");
    assert.match(JSON.stringify(last.messages.at(-1)), /Tool call limit reached: answer now/);
    assert.match(
      JSON.stringify(last.messages.at(-2)),
      /Tool call limit reached: answer with what you have/,
    );
  });

  test("the time limit and cancellation stop the loop", async () => {
    let clock = 0;
    const model = scriptedModel([[call("a", "pcap_capture_info", {})], [text("done")]]);
    const out = await runToolLoop(model, "q", {
      now: () => clock,
      cancelled: () => false,
      onText: () => undefined,
      runTool: async () => {
        clock += TOOL_LIMITS.timeLimitMs; // this call took all the time
        return { text: "ok" };
      },
    });
    assert.equal(out.stopped, "time");
    assert.deepEqual(model.sent.at(-1)?.tools, []);
    assert.match(JSON.stringify(model.sent.at(-1)?.messages.at(-1)), /Time limit reached/);

    let cancelled = false;
    const model2 = scriptedModel([[text("a"), text("b")]]);
    const out2 = await runToolLoop(model2, "q", {
      cancelled: () => cancelled,
      onText: () => {
        cancelled = true;
      },
      runTool: async () => ({ text: "" }),
    });
    assert.equal(out2.answer, "a");
    const out3 = await runToolLoop(scriptedModel([[text("x")]]), "q", {
      cancelled: () => true,
      onText: () => undefined,
      runTool: async () => ({ text: "" }),
    });
    assert.equal(out3.stopped, "cancelled");
  });

  test("refused tools are reported once", async () => {
    const model = scriptedModel([
      [call("a", "pcap_count", { filter: "tcp" }), call("b", "pcap_stats", { kind: "phs" })],
      [text("I can't: statistics aren't allowed.")],
    ]);
    const out = await runToolLoop(model, "q", {
      cancelled: () => false,
      onText: () => undefined,
      runTool: (name, input) => runTool(name, input, fakeBackend(), NONE),
    });
    assert.deepEqual(out.refused, ["statistics"]);
    assert.deepEqual(out.filters, []);
  });

  test("the prompt: tools first, only from results, untrusted", () => {
    const prompt = buildToolPrompt("how many DNS\nqueries failed?", "dns");
    assert.match(prompt, /Base your answer only on tool results/);
    assert.match(prompt, /untrusted/);
    assert.match(prompt, /Current display filter in the viewer: dns/);
    assert.match(prompt, /Question: how many DNS queries failed\?$/);
  });
});
