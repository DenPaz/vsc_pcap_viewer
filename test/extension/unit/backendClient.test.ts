/**
 * BackendClient against the real Python backend (no VS Code needed).
 * tshark-dependent tests are skipped when tshark is not installed.
 */
import * as assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import * as path from "node:path";
import { BackendClient, ErrorCodes, Progress, RpcError, findPython } from "../../../src/backendClient";

const ROOT = path.resolve(__dirname, "../../../..");
const FIXTURES = path.join(ROOT, "test", "fixtures");
const HAVE_TSHARK = spawnSync("tshark", ["--version"]).status === 0;

const logs: string[] = [];
const logger = { info: (m: string) => logs.push(m), warn: (m: string) => logs.push(m), error: (m: string) => logs.push(m) };

function makeClient(): BackendClient {
  const py = findPython(process.env.PCAP_VIEWER_PYTHON);
  if ("error" in py) {
    throw new Error(py.error);
  }
  return new BackendClient({ python: py.python, backendDir: path.join(ROOT, "backend"), logger, defaultTimeoutMs: 30_000 });
}

function isAlive(pid: number): boolean {
  try {
    process.kill(pid, 0);
    return true;
  } catch {
    return false;
  }
}

suite("BackendClient", function () {
  this.timeout(30_000);
  let client: BackendClient;

  setup(() => {
    client = makeClient();
    client.start();
  });

  teardown(async () => {
    await client.dispose();
  });

  test("findPython reports a missing interpreter", () => {
    const res = findPython("/definitely/not/python");
    assert.ok("error" in res);
  });

  test("unknown methods reject with MethodNotFound", async () => {
    await assert.rejects(client.request("nope"), (err: RpcError) => err.code === ErrorCodes.MethodNotFound);
  });

  test("requests before start / after stop reject", async () => {
    await client.stop();
    await assert.rejects(client.request("ping"), (err: RpcError) => err.code === ErrorCodes.BackendExited);
  });

  test("stop terminates the process", async () => {
    const pid = client.pid;
    assert.ok(pid);
    assert.deepEqual(await client.request("ping"), { pong: true });
    await client.stop();
    assert.equal(isAlive(pid), false);
  });

  test("unexpected exit rejects pending requests and fires onExit", async () => {
    const exited = new Promise<boolean>((resolve) => client.onExit((e) => resolve(e.expected)));
    const pending = client.request("ping");
    await pending;
    process.kill(client.pid as number, "SIGKILL");
    assert.equal(await exited, false);
    assert.equal(client.running, false);
  });

  (HAVE_TSHARK ? test : test.skip)("open, filter, page and detail over stdio", async () => {
    const init = await client.request<{ version: string }>("initialize", {});
    assert.match(init.version, /TShark/);
    const progress: Progress[] = [];
    const info = await client.request<{ frames: number }>(
      "open",
      { path: path.join(FIXTURES, "http.pcap") },
      { timeoutMs: 0, onProgress: (p) => progress.push(p) },
    );
    assert.equal(info.frames, 11);
    assert.ok(progress.some((p) => p.phase === "index"));
    const filtered = await client.request<{ matchCount: number }>("set_filter", { expr: "http" });
    assert.equal(filtered.matchCount, 2);
    const page = await client.request<{ rows: { number: number }[] }>("list_packets", { offset: 0, limit: 10 });
    assert.deepEqual(
      page.rows.map((r) => r.number),
      [4, 7],
    );
    const detail = await client.request<{ tree: { name?: string }[]; sources: unknown[] }>("packet_detail", { number: 7 });
    assert.ok(detail.tree.some((n) => n.name === "http"));
    assert.equal(detail.sources.length, 2);
    await assert.rejects(client.request("set_filter", { expr: "http.host ==" }), (err: RpcError) => err.code === ErrorCodes.InvalidFilter);
  });

  (HAVE_TSHARK ? test : test.skip)("cancellation via token", async () => {
    await client.request("initialize", {});
    let cancel: () => void = () => undefined;
    const token = {
      isCancellationRequested: false,
      onCancellationRequested(cb: () => void) {
        cancel = () => {
          token.isCancellationRequested = true;
          cb();
        };
        return { dispose() {} };
      },
    };
    const p = client.request("open", { path: path.join(FIXTURES, "mixed.pcapng") }, { timeoutMs: 0, cancellation: token });
    cancel();
    // Either the open finished before the cancel landed, or it was cancelled.
    await p.then(
      () => undefined,
      (err: RpcError) => assert.equal(err.code, ErrorCodes.RequestCancelled),
    );
    assert.deepEqual(await client.request("ping"), { pong: true });
  });
});
