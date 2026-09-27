import * as path from "node:path";

export async function run(): Promise<void> {
  // mocha 12 is ESM-only; a dynamic import loads it from this CommonJS module
  // in any Node/Electron (require(esm) needs Node >= 22.12).
  const { default: Mocha } = await import("mocha");
  const mocha = new Mocha({ ui: "tdd", color: true, timeout: 60_000 });
  mocha.addFile(path.resolve(__dirname, "smoke.test.js"));
  return new Promise((resolve, reject) => {
    mocha.run((failures) =>
      failures ? reject(new Error(`${failures} test(s) failed`)) : resolve(),
    );
  });
}
