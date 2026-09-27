import * as assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import {
  bumpPackageJson,
  changelogSection,
  compareVersions,
  parseVersion,
  prepareChangelog,
  releaseProblems,
  tagVersion,
} from "../../scripts/release.mjs";

const CHANGELOG = `# Changelog

## Unreleased

- New thing.
- Fixed: old thing.

## 0.1.0

First release.
`;

suite("release helper", () => {
  test("versions and tags", () => {
    assert.deepEqual(parseVersion("0.10.2"), [0, 10, 2]);
    for (const bad of ["1.2", "01.2.3", "1.2.3-beta.1", "v1.2.3", ""]) {
      assert.equal(parseVersion(bad), undefined, bad);
    }
    assert.equal(compareVersions("0.10.0", "0.9.9"), 1);
    assert.equal(compareVersions("1.0.0", "1.0.0"), 0);
    assert.equal(compareVersions("0.1.0", "0.2.0"), -1);
    assert.equal(tagVersion("v0.2.0"), "0.2.0");
    assert.equal(tagVersion("refs/tags/v1.20.3"), "1.20.3");
    assert.equal(tagVersion("0.2.0"), undefined);
    assert.equal(tagVersion("v0.2"), undefined);
    assert.equal(tagVersion("main"), undefined);
  });

  test("CHANGELOG sections", () => {
    assert.equal(changelogSection(CHANGELOG, "Unreleased"), "- New thing.\n- Fixed: old thing.");
    assert.equal(changelogSection(CHANGELOG, "0.1.0"), "First release.");
    assert.equal(changelogSection(CHANGELOG, "0.2.0"), undefined);
    assert.equal(changelogSection("## Unreleased\n\n## 0.1.0\n", "Unreleased"), undefined);
  });

  test("prepare moves the Unreleased notes under the new version", () => {
    const next = prepareChangelog(CHANGELOG, "0.2.0", "2026-09-28");
    assert.equal(
      next,
      `# Changelog

## Unreleased

## 0.2.0 — 2026-09-28

- New thing.
- Fixed: old thing.

## 0.1.0

First release.
`,
    );
    assert.equal(changelogSection(next, "0.2.0"), "- New thing.\n- Fixed: old thing.");
    assert.equal(changelogSection(next, "Unreleased"), undefined);
    assert.throws(() => prepareChangelog(next, "0.3.0", "2026-10-01"), /empty/);
    assert.throws(() => prepareChangelog(CHANGELOG, "0.1.0", "2026-10-01"), /already has/);
    assert.throws(() => prepareChangelog("# Changelog\n", "0.2.0", "x"), /no "## Unreleased"/);
  });

  test("the version bump keeps package.json's formatting", () => {
    const pkg =
      '{\n  "name": "x",\n  "version": "0.1.0",\n  "engines": { "vscode": "^1.90.0" }\n}\n';
    assert.equal(bumpPackageJson(pkg, "0.2.0"), pkg.replace('"0.1.0"', '"0.2.0"'));
  });

  test("a tag is released only when it matches package.json and has notes", () => {
    const next = prepareChangelog(CHANGELOG, "0.2.0", "2026-09-28");
    assert.deepEqual(releaseProblems("v0.2.0", "0.2.0", next), []);
    assert.deepEqual(releaseProblems("v0.2.0", "0.1.0", next), [
      "the tag says 0.2.0 but package.json says 0.1.0",
    ]);
    assert.deepEqual(releaseProblems("v0.3.0", "0.3.0", next), [
      "CHANGELOG.md has no notes for 0.3.0",
    ]);
    assert.match(releaseProblems("nightly", "0.2.0", next)[0], /not a release tag/);
  });

  test("the repository's CHANGELOG has an Unreleased section and notes for its version", () => {
    const text = readFileSync(new URL("../../CHANGELOG.md", import.meta.url), "utf8");
    const pkg = JSON.parse(readFileSync(new URL("../../package.json", import.meta.url), "utf8"));
    assert.match(text, /^## Unreleased$/m);
    assert.ok(changelogSection(text, pkg.version), `no notes for ${pkg.version}`);
  });
});
