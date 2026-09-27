import * as assert from "node:assert/strict";
import * as fs from "node:fs";
import * as path from "node:path";
import { copyName, isOnDisk, revealHow, whereLabel } from "../../../src/remote";

const ROOT = path.resolve(__dirname, "../../../..");

suite("remote windows", () => {
  test("where the extension runs", () => {
    assert.equal(whereLabel(undefined), undefined);
    assert.equal(whereLabel(""), undefined);
    assert.equal(whereLabel("wsl"), "WSL");
    assert.equal(whereLabel("ssh-remote"), "the SSH host");
    assert.equal(whereLabel("dev-container"), "the container");
    assert.equal(whereLabel("attached-container"), "the container");
    assert.equal(whereLabel("codespaces"), "the codespace");
    assert.equal(whereLabel("k8s-container"), "the remote machine (k8s-container)");
  });

  test("showing a saved file: the OS file manager only for local files", () => {
    assert.equal(revealHow(undefined, false), "os");
    assert.equal(revealHow(undefined, true), "os");
    assert.equal(revealHow(undefined, true, true), "explorer");
    assert.equal(revealHow(undefined, false, true), "os");
    assert.equal(revealHow("wsl", true), "explorer");
    assert.equal(revealHow("ssh-remote", false), "copyPath");
    assert.equal(revealHow("dev-container", false, true), "copyPath");
  });

  test("captures that aren't files on disk open as copies", () => {
    assert.ok(isOnDisk({ scheme: "file" }));
    for (const scheme of ["vsls", "vscode-vfs", "zip", "untitled"]) {
      assert.ok(!isOnDisk({ scheme }), scheme);
    }
    assert.equal(copyName({ path: "/shared/traces/http.pcapng" }), "http.pcapng");
    assert.equal(copyName({ path: "/a/b:c?.pcap" }), "b_c_.pcap");
    assert.equal(copyName({ path: "/" }), "capture.pcapng");
  });

  test("package.json: runs where the files are; Restricted Mode can't pick programs", () => {
    const pkg = JSON.parse(fs.readFileSync(path.join(ROOT, "package.json"), "utf8"));
    assert.deepEqual(pkg.extensionKind, ["workspace"]);
    const trust = pkg.capabilities.untrustedWorkspaces;
    assert.equal(trust.supported, "limited");
    const settings = pkg.contributes.configuration.properties;
    // Everything that names a program or a script tshark runs.
    for (const key of [
      "pcapViewer.pythonPath",
      "pcapViewer.tsharkPath",
      "pcapViewer.luaScripts",
      "pcapViewer.dissectorsFolder",
    ]) {
      assert.ok(trust.restrictedConfigurations.includes(key), key);
      assert.ok(settings[key], `${key} exists`);
    }
    assert.equal(pkg.capabilities.virtualWorkspaces.supported, "limited");
  });
});
