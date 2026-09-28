import * as assert from "node:assert/strict";
import * as fs from "node:fs";
import * as path from "node:path";
import { guessOffsets, hasAsciiColumn, importFileName, parsePorts } from "../../../src/hexDump";

const HEXDUMPS = path.resolve(__dirname, "../../../../test/fixtures/hexdump");

suite("hexDump", () => {
  test("guessOffsets: the fixtures (Wireshark's dumps, with and without the ASCII column)", () => {
    for (const name of ["frames.txt", "sip-payload.txt", "timed-ipv4.txt"]) {
      assert.equal(guessOffsets(fs.readFileSync(path.join(HEXDUMPS, name), "utf8")), "hex", name);
    }
  });

  test("guessOffsets: od's decimal and octal offsets, bytes without offsets", () => {
    const odDecimal = [
      "0000000 45 00 00 1c 00 01 00 00 40 11 7c cd 7f 00 00 01",
      "0000016 7f 00 00 01 04 d2 04 d2 00 08 f3 f9",
      "0000028",
    ].join("\n");
    assert.equal(guessOffsets(odDecimal), "dec");
    const odOctal = [
      "0000000 45 00 00 1c 00 01 00 00 40 11 7c cd 7f 00 00 01",
      "0000020 7f 00 00 01 04 d2 04 d2 00 08 f3 f9",
      "0000034",
    ].join("\n");
    assert.equal(guessOffsets(odOctal), "oct");
    const hex = ["000000 45 00 00 1c 00 01 00 00 40 11 7c cd 7f 00 00 01", "000010 7f 00"].join(
      "\n",
    );
    assert.equal(guessOffsets(hex), "hex");
    assert.equal(guessOffsets("45 00 00 1c 00 01\n7f 00 00 01\n\n45 00\n"), "none");
    assert.equal(guessOffsets(""), "hex");
    // xxd-style offsets with a colon count as offsets too.
    assert.equal(guessOffsets("00000000: 45 00 00 1c\n00000004: 7f 00\n"), "hex");
  });

  test("hasAsciiColumn: hexdump -C's |…| column", () => {
    const hd = [
      "00000000  45 00 00 1c 00 01 00 00  40 11 7c cd 7f 00 00 01  |E.......@.|.....|",
      "00000010  7f 00 00 01 04 d2 04 d2  00 08 f3 f9              |............|",
      "0000001c",
    ].join("\n");
    assert.equal(hasAsciiColumn(hd), true);
    assert.equal(guessOffsets(hd), "hex");
    assert.equal(hasAsciiColumn(fs.readFileSync(path.join(HEXDUMPS, "frames.txt"), "utf8")), false);
    assert.equal(hasAsciiColumn(""), false);
  });

  test("parsePorts", () => {
    assert.deepEqual(parsePorts("5060,5061"), { srcPort: 5060, dstPort: 5061 });
    assert.deepEqual(parsePorts(" 53 1053 "), { srcPort: 53, dstPort: 1053 });
    assert.deepEqual(parsePorts("5060"), { srcPort: 5060, dstPort: 5060 });
    assert.equal(typeof parsePorts("70000,1"), "string");
    assert.equal(typeof parsePorts("http"), "string");
    assert.equal(typeof parsePorts("1,2,3"), "string");
    assert.equal(typeof parsePorts(""), "string");
  });

  test("importFileName: after the dump's file, else dated", () => {
    const date = new Date(2026, 8, 28, 3, 4, 5);
    assert.equal(importFileName("/tmp/router log.txt", date), "router_log.pcapng");
    assert.equal(importFileName("C:\\dumps\\frames.hex", date), "frames.pcapng");
    assert.equal(importFileName(undefined, date), "hexdump_2026-09-28_03-04-05.pcapng");
  });
});
