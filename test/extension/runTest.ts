/**
 * Launches VS Code (downloaded by @vscode/test-electron) with this extension
 * and runs the smoke suite in test/extension/suite. On headless Linux run
 * under xvfb-run.
 */
import * as fs from "node:fs";
import * as path from "node:path";
import { runTests } from "@vscode/test-electron";

async function main(): Promise<void> {
  const root = path.resolve(__dirname, "../../..");
  const venv = path.join(
    root,
    ".venv",
    process.platform === "win32" ? "Scripts/python.exe" : "bin/python",
  );
  const python = process.env.PCAP_VIEWER_PYTHON ?? (fs.existsSync(venv) ? venv : "python3");
  try {
    await runTests({
      extensionDevelopmentPath: root,
      extensionTestsPath: path.resolve(__dirname, "suite", "index"),
      // Live capture with a stand-in dumpcap (test/fixtures/fake_dumpcap.py): no capture rights needed.
      extensionTestsEnv: {
        PCAP_VIEWER_DUMPCAP: JSON.stringify([
          python,
          path.join(root, "test", "fixtures", "fake_dumpcap.py"),
        ]),
        FAKE_DUMPCAP_DELAY: "0.05",
      },
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
