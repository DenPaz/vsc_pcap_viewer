/**
 * Release helper: version bumps, CHANGELOG sections and tag checks.
 *
 *   node scripts/release.mjs prepare 0.2.0   bump package.json, move "Unreleased" to "0.2.0 — <date>"
 *   node scripts/release.mjs check v0.2.0    the tag matches package.json and the CHANGELOG has notes
 *   node scripts/release.mjs notes 0.2.0     print that version's CHANGELOG section
 *
 * The CHANGELOG keeps an "## Unreleased" section on top; `prepare` moves its
 * entries under "## <version> — <YYYY-MM-DD>" and leaves it empty. The release
 * workflow (.github/workflows/release.yml) runs `check` and `notes` on a tag.
 */
import { readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const UNRELEASED = "Unreleased";

/** Marketplace versions are plain major.minor.patch (no pre-release suffix). */
export function parseVersion(text) {
  const m = /^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$/.exec(text);
  return m ? [Number(m[1]), Number(m[2]), Number(m[3])] : undefined;
}

export function compareVersions(a, b) {
  const [x, y] = [parseVersion(a), parseVersion(b)];
  if (!x || !y) {
    throw new Error(`not a version: ${!x ? a : b}`);
  }
  for (let i = 0; i < 3; i++) {
    if (x[i] !== y[i]) {
      return x[i] < y[i] ? -1 : 1;
    }
  }
  return 0;
}

/** "v0.2.0", "refs/tags/v0.2.0" → "0.2.0"; undefined for anything else. */
export function tagVersion(ref) {
  const m = /^(?:refs\/tags\/)?v(\d+\.\d+\.\d+)$/.exec(ref.trim());
  return m && parseVersion(m[1]) ? m[1] : undefined;
}

/** The "## " headings of a CHANGELOG with their line ranges. */
function sections(text) {
  const lines = text.split("\n");
  const found = [];
  lines.forEach((line, i) => {
    const m = /^## (.+?)\s*$/.exec(line);
    if (m) {
      found.push({ title: m[1], start: i });
    }
  });
  return found.map((s, i) => ({
    ...s,
    end: i + 1 < found.length ? found[i + 1].start : lines.length,
    lines,
  }));
}

/** A heading's version: "0.2.0 — 2026-09-28" → "0.2.0". */
function headingVersion(title) {
  return /^(\d+\.\d+\.\d+)(?:\s|$)/.exec(title)?.[1];
}

function body(s) {
  return s.lines
    .slice(s.start + 1, s.end)
    .join("\n")
    .trim();
}

/** The notes of `version` (or "Unreleased"), trimmed; undefined when missing or empty. */
export function changelogSection(text, version) {
  const s = sections(text).find((x) =>
    version === UNRELEASED ? x.title === UNRELEASED : headingVersion(x.title) === version,
  );
  const notes = s && body(s);
  return notes || undefined;
}

/** Move the Unreleased entries under a new "## <version> — <date>" heading. */
export function prepareChangelog(text, version, date) {
  const all = sections(text);
  const unreleased = all.find((s) => s.title === UNRELEASED);
  if (!unreleased) {
    throw new Error('CHANGELOG.md has no "## Unreleased" section');
  }
  if (all.some((s) => headingVersion(s.title) === version)) {
    throw new Error(`CHANGELOG.md already has a ${version} section`);
  }
  const notes = body(unreleased);
  if (!notes) {
    throw new Error('the "Unreleased" section is empty: nothing to release');
  }
  const { lines } = unreleased;
  return [
    ...lines.slice(0, unreleased.start + 1),
    "",
    `## ${version} — ${date}`,
    "",
    notes,
    "",
    ...lines.slice(unreleased.end),
  ].join("\n");
}

/** package.json text with a new "version", keeping its formatting. */
export function bumpPackageJson(text, version) {
  const re = /^(\s*"version":\s*")([^"]*)(")/m;
  if (!re.test(text)) {
    throw new Error('package.json has no "version"');
  }
  return text.replace(re, `$1${version}$3`);
}

/** Problems that should stop releasing `tag` (empty when it can be released). */
export function releaseProblems(tag, pkgVersion, changelog) {
  const version = tagVersion(tag);
  if (!version) {
    return [`"${tag}" is not a release tag (expected v<major>.<minor>.<patch>)`];
  }
  const problems = [];
  if (version !== pkgVersion) {
    problems.push(`the tag says ${version} but package.json says ${pkgVersion}`);
  }
  if (!changelogSection(changelog, version)) {
    problems.push(`CHANGELOG.md has no notes for ${version}`);
  }
  return problems;
}

function read(file) {
  return readFileSync(join(ROOT, file), "utf8");
}

function main([command, arg]) {
  const pkgText = read("package.json");
  const pkgVersion = JSON.parse(pkgText).version;
  const changelog = read("CHANGELOG.md");
  switch (command) {
    case "prepare": {
      if (!arg || !parseVersion(arg)) {
        throw new Error("usage: release.mjs prepare <major.minor.patch>");
      }
      if (compareVersions(arg, pkgVersion) <= 0) {
        throw new Error(`${arg} is not newer than the current version ${pkgVersion}`);
      }
      const date = new Date().toISOString().slice(0, 10);
      writeFileSync(join(ROOT, "CHANGELOG.md"), prepareChangelog(changelog, arg, date));
      writeFileSync(join(ROOT, "package.json"), bumpPackageJson(pkgText, arg));
      console.log(`Prepared ${arg}. Review the diff, then:
  git commit -am "Release ${arg}"
  git tag v${arg}
  git push origin HEAD v${arg}
Pushing the tag runs .github/workflows/release.yml.`);
      return;
    }
    case "check": {
      const problems = releaseProblems(arg ?? "", pkgVersion, changelog);
      if (problems.length) {
        throw new Error(problems.join("\n"));
      }
      console.log(`v${pkgVersion} can be released`);
      return;
    }
    case "notes": {
      const notes = changelogSection(changelog, arg ?? pkgVersion);
      if (!notes) {
        throw new Error(`CHANGELOG.md has no notes for ${arg ?? pkgVersion}`);
      }
      process.stdout.write(`${notes}\n`);
      return;
    }
    default:
      throw new Error("usage: release.mjs prepare <version> | check <tag> | notes [version]");
  }
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  try {
    main(process.argv.slice(2));
  } catch (err) {
    console.error(err.message);
    process.exitCode = 1;
  }
}
