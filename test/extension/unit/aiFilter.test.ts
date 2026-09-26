import * as assert from "node:assert/strict";
import {
  ChatTurn,
  FilterSuggestion,
  PromptInput,
  buildFilterPrompt,
  buildRetryPrompt,
  extractKeywords,
  parseSuggestions,
  suggestFilters,
  validateSuggestions,
} from "../../../src/aiFilter";

const INPUT: PromptInput = {
  request: "DNS queries for example.com\nthat got no answer",
  currentFilter: "udp",
  protocols: ["eth", "ip", "udp", "dns", "tcp", "http"],
  fields: [
    { name: "dns.qry.name", desc: "Name — Query Name", type: "FT_STRING" },
    { name: "dns.flags.response", desc: "Response\nflag", type: "FT_BOOLEAN" },
  ],
};

suite("aiFilter", () => {
  test("extractKeywords keeps protocol/field-like words", () => {
    assert.deepEqual(extractKeywords("Show me DNS queries for example.com that got no answer"), ["dns", "queries", "example.com", "got", "answer"]);
    assert.deepEqual(extractKeywords("tcp.port 443 or 10.0.0.1, http2!"), ["tcp.port", "http2"]);
    assert.deepEqual(extractKeywords("a b c the"), []);
    assert.equal(extractKeywords("one two three four five six seven eight nine ten", 3).length, 3);
  });

  test("the prompt carries the request, current filter, protocols and fields only", () => {
    const prompt = buildFilterPrompt(INPUT);
    assert.match(prompt, /Request: DNS queries for example\.com that got no answer$/m); // newlines collapsed
    assert.match(prompt, /^Current display filter: udp$/m);
    assert.match(prompt, /^Protocols in this capture: eth, ip, udp, dns, tcp, http$/m);
    assert.match(prompt, /^- dns\.qry\.name \(FT_STRING\): Name — Query Name$/m);
    assert.match(prompt, /^- dns\.flags\.response \(FT_BOOLEAN\): Response flag$/m);
    assert.match(prompt, /JSON only/);
    assert.equal(buildFilterPrompt({ ...INPUT, currentFilter: "", protocols: [], fields: [] }).includes("Current display filter: (none)"), true);
  });

  test("the prompt never includes packet data, even if a caller passes some", () => {
    const withPackets = { ...INPUT, packets: [{ info: "SECRET-PAYLOAD GET /private?token=abc" }], rows: ["10.1.2.3 → 10.9.9.9"] } as PromptInput;
    const prompt = buildFilterPrompt(withPackets);
    assert.ok(!prompt.includes("SECRET-PAYLOAD"));
    assert.ok(!prompt.includes("token=abc"));
    assert.ok(!prompt.includes("10.9.9.9"));
    assert.equal(prompt, buildFilterPrompt(INPUT));
  });

  test("the prompt is bounded", () => {
    const fields = Array.from({ length: 500 }, (_, i) => ({ name: `f${i}.x`, desc: "d".repeat(1000) }));
    const prompt = buildFilterPrompt({ ...INPUT, request: "x".repeat(10_000), fields });
    assert.ok(prompt.length < 20_000, `prompt is ${prompt.length} chars`);
    assert.ok(!prompt.includes("f60.x"));
  });

  test("parseSuggestions accepts the JSON array, fenced or with prose", () => {
    const good = '[{"filter": "dns.flags.response == 0", "explanation": "DNS queries"}, {"filter": "dns", "explanation": "All DNS"}]';
    const expected: FilterSuggestion[] = [
      { filter: "dns.flags.response == 0", explanation: "DNS queries" },
      { filter: "dns", explanation: "All DNS" },
    ];
    assert.deepEqual(parseSuggestions(good), expected);
    assert.deepEqual(parseSuggestions("```json\n" + good + "\n```"), expected);
    assert.deepEqual(parseSuggestions(`Here you go:\n${good}\nHope it helps!`), expected);
    assert.deepEqual(parseSuggestions(`{"suggestions": ${good}}`), expected);
    assert.deepEqual(parseSuggestions('{"filter": "tcp", "explanation": "TCP"}'), [{ filter: "tcp", explanation: "TCP" }]);
  });

  test("parseSuggestions drops bad entries, duplicates and extras", () => {
    const text = JSON.stringify([
      { filter: "  tcp  ", explanation: "  lots\n of   space " },
      { filter: "tcp", explanation: "duplicate" },
      { filter: "" },
      { filter: "a\nb" },
      { explanation: "no filter" },
      null,
      42,
      { filter: "udp" },
      { filter: "icmp", explanation: "third" },
      { filter: "arp", explanation: "fourth: over the limit" },
    ]);
    assert.deepEqual(parseSuggestions(text), [
      { filter: "tcp", explanation: "lots of space" },
      { filter: "udp", explanation: "" },
      { filter: "icmp", explanation: "third" },
    ]);
    assert.deepEqual(parseSuggestions("I cannot help with that."), []);
    assert.deepEqual(parseSuggestions("[not json]"), []);
    assert.deepEqual(parseSuggestions('"just a string"'), []);
  });

  test("validateSuggestions drops what tshark rejects", async () => {
    const validate = async (f: string) => (f.includes("bogus") ? `"${f}" is neither a field nor a protocol name.` : undefined);
    const res = await validateSuggestions(
      [
        { filter: "dns", explanation: "ok" },
        { filter: "bogus.field == 1", explanation: "bad" },
      ],
      validate,
    );
    assert.deepEqual(res.valid, [{ filter: "dns", explanation: "ok" }]);
    assert.deepEqual(res.rejected, [{ filter: "bogus.field == 1", error: '"bogus.field == 1" is neither a field nor a protocol name.' }]);
  });

  test("suggestFilters retries once with tshark's errors when nothing was valid", async () => {
    const seen: ChatTurn[][] = [];
    const answers = ['[{"filter": "dns.bogus == 1", "explanation": "x"}]', '[{"filter": "dns.flags.response == 0", "explanation": "fixed"}]'];
    const res = await suggestFilters(
      {
        ask: async (turns) => {
          seen.push(turns.map((t) => ({ ...t })));
          return answers[seen.length - 1];
        },
        validate: async (f) => (f.includes("bogus") ? "not a field" : undefined),
      },
      INPUT,
    );
    assert.deepEqual(res.suggestions, [{ filter: "dns.flags.response == 0", explanation: "fixed" }]);
    assert.deepEqual(res.rejected, [{ filter: "dns.bogus == 1", error: "not a field" }]);
    assert.equal(seen.length, 2);
    assert.deepEqual(
      seen[1].map((t) => t.role),
      ["user", "assistant", "user"],
    );
    assert.match(seen[1][2].content, /dns\.bogus == 1: not a field/);
  });

  test("suggestFilters does not retry when something was valid, or when retry is off", async () => {
    let calls = 0;
    const deps = {
      ask: async () => {
        calls++;
        return '[{"filter": "tcp", "explanation": "a"}, {"filter": "bogus", "explanation": "b"}]';
      },
      validate: async (f: string) => (f === "bogus" ? "bad" : undefined),
    };
    assert.deepEqual((await suggestFilters(deps, INPUT)).suggestions, [{ filter: "tcp", explanation: "a" }]);
    assert.equal(calls, 1);
    const none = await suggestFilters({ ask: async () => "no idea", validate: deps.validate }, INPUT, { retry: false });
    assert.deepEqual(none, { suggestions: [], rejected: [] });
  });

  test("buildRetryPrompt", () => {
    assert.match(buildRetryPrompt([]), /JSON only/);
    assert.match(buildRetryPrompt([{ filter: "x ==", error: "Unexpected end\nof filter" }]), /- x ==: Unexpected end of filter/);
  });
});
