import * as assert from "node:assert/strict";
import { mergedFileName, rotatedSet, rotationPiece } from "../../../src/rotation";

suite("rotated captures", () => {
  test("tcpdump -C pieces, in capture order", () => {
    const names = ["trace.pcap2", "notes.txt", "trace.pcap", "trace.pcap10", "trace.pcap1", "other.pcap", "other.pcap1"];
    assert.deepEqual(rotatedSet("trace.pcap1", names), ["trace.pcap", "trace.pcap1", "trace.pcap2", "trace.pcap10"]);
    assert.deepEqual(rotatedSet("other.pcap", names), ["other.pcap", "other.pcap1"]);
    assert.deepEqual(rotatedSet("trace.pcapng0", ["trace.pcapng0", "trace.pcapng1"]), ["trace.pcapng0", "trace.pcapng1"], "-W numbers the first one");
  });

  test("dumpcap ring buffers and editcap splits", () => {
    const names = [
      "cap_00002_20260927041600.pcapng",
      "cap_00001_20260927041500.pcapng",
      "cap_00003_20260927041700.pcapng.gz",
      "cap_00003_20260927041700.pcapng",
      "cap.pcapng",
    ];
    assert.deepEqual(rotatedSet("cap_00002_20260927041600.pcapng", names), [
      "cap_00001_20260927041500.pcapng",
      "cap_00002_20260927041600.pcapng",
      "cap_00003_20260927041700.pcapng",
    ]);
    assert.equal(rotationPiece("cap_00003_20260927041700.pcapng.gz")?.index, 3);
  });

  test("a single capture is not a rotated set", () => {
    assert.deepEqual(rotatedSet("trace.pcap", ["trace.pcap", "trace.pcap.bak"]), []);
    assert.deepEqual(rotatedSet("dump.cap", ["dump.cap", "dump1.cap"]), []);
    assert.deepEqual(rotatedSet("trace.pcap1", ["trace.pcap", "trace.pcap2"]), [], "the file itself must be there");
  });

  test("merged file name", () => {
    assert.equal(mergedFileName("trace.pcap3"), "trace-merged.pcapng");
    assert.equal(mergedFileName("cap_00002_20260927041600.pcapng"), "cap-merged.pcapng");
    assert.equal(mergedFileName("dump.cap"), "dump-merged.pcapng");
  });
});
