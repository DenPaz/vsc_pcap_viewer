/**
 * Launches VS Code (downloaded by @vscode/test-electron) with this extension
 * and runs the smoke suite in test/extension/suite. On headless Linux run
 * under xvfb-run.
 */
import * as path from "node:path";
import { runTests } from "@vscode/test-electron";

async function main(): Promise<void> {
  const root = path.resolve(__dirname, "../../..");
  try {
    await runTests({
      extensionDevelopmentPath: root,
      extensionTestsPath: path.resolve(__dirname, "suite", "index"),
      launchArgs: [
        path.join(root, "test", "fixtures"),
        "--disable-extensions",
        "--disable-workspace-trust",
      ],
    });
  } catch (err) {
    console.error("Extension tests failed:", err);
    process.exit(1);
  }
}

void main();
