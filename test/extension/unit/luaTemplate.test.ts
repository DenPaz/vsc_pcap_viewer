import * as assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { luaDissectorTemplate, validatePort, validateProtocolName } from "../../../src/luaTemplate";
import { formatDecodeAsRule, parseDecodeAsRule, resolveDissectorsFolder, upsertDecodeAsRule } from "../../../src/settingsModel";

const ROOT = path.resolve(__dirname, "../../../..");
const HAVE_TSHARK = spawnSync("tshark", ["--version"]).status === 0;
// tshark refuses to run Lua as root.
const CAN_RUN_LUA = HAVE_TSHARK && !(typeof process.getuid === "function" && process.getuid() === 0);

suite("Lua dissector template", () => {
  test("validation", () => {
    assert.equal(validateProtocolName("myproto"), undefined);
    assert.equal(validateProtocolName("my_proto2"), undefined);
    assert.ok(validateProtocolName("MyProto"));
    assert.ok(validateProtocolName("2proto"));
    assert.ok(validateProtocolName("a".repeat(33)));
    assert.equal(validatePort("9999"), undefined);
    assert.ok(validatePort("0"));
    assert.ok(validatePort("70000"));
    assert.ok(validatePort("80.5"));
  });

  test("fills in name, description, transport and port; escapes the description", () => {
    const lua = luaDissectorTemplate({ name: "acme", description: 'Acme "Wire" \\ Proto', transport: "tcp", port: 7000 });
    assert.match(lua, /local acme = Proto\("acme", "Acme \\"Wire\\" \\\\ Proto"\)/);
    assert.match(lua, /ProtoField\.uint8\("acme\.type"/);
    assert.match(lua, /DissectorTable\.get\("tcp\.port"\):add\(7000, acme\)/);
  });

  (CAN_RUN_LUA ? test : test.skip)("the generated dissector loads in tshark and decodes packets", () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "pcapviewer-lua-"));
    try {
      const script = path.join(dir, "genproto.lua");
      fs.writeFileSync(script, luaDissectorTemplate({ name: "genproto", description: "Generated", transport: "udp", port: 9999 }));
      const res = spawnSync(
        "tshark",
        ["-X", `lua_script:${script}`, "-r", path.join(ROOT, "test", "fixtures", "udp_custom.pcap"), "-Y", "genproto.type == 1", "-T", "fields", "-e", "_ws.col.protocol"],
        { encoding: "utf8" },
      );
      assert.equal(res.stderr.includes("Lua"), false, res.stderr);
      // The template's generic "type" is the first payload byte: 1 in all six fixture packets.
      assert.deepEqual(res.stdout.trim().split(/\r?\n/), Array(6).fill("GENPROTO"));
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });
});

suite("Decode As rules", () => {
  test("parse and format", () => {
    assert.deepEqual(parseDecodeAsRule("tcp.port==8080,http"), { layer: "tcp.port", value: "8080", protocol: "http" });
    assert.deepEqual(parseDecodeAsRule(" udp.port:9999,dns "), { layer: "udp.port", value: "9999", protocol: "dns" });
    assert.equal(parseDecodeAsRule("tcp.port==8080"), undefined);
    assert.equal(parseDecodeAsRule("-d,x"), undefined);
    assert.equal(formatDecodeAsRule({ layer: "tcp.port", value: "8000-8100", protocol: "http" }), "tcp.port==8000-8100,http");
  });

  test("upsert replaces the rule for the same layer and value", () => {
    const rules = ["tcp.port==8080,http", "udp.port==53,dns", "garbage"];
    assert.deepEqual(upsertDecodeAsRule(rules, { layer: "tcp.port", value: "8080", protocol: "http2" }), ["udp.port==53,dns", "garbage", "tcp.port==8080,http2"]);
    assert.deepEqual(upsertDecodeAsRule(rules, { layer: "tcp.port", value: "8443", protocol: "tls" }).length, 4);
  });

  test("resolveDissectorsFolder", () => {
    const base = path.resolve("/work");
    assert.equal(resolveDissectorsFolder("dissectors", base), path.join(base, "dissectors"));
    assert.equal(resolveDissectorsFolder(path.resolve("/abs/d"), base), path.resolve("/abs/d"));
    assert.equal(resolveDissectorsFolder("  ", base), undefined);
    assert.equal(resolveDissectorsFolder(undefined, base), undefined);
  });
});
