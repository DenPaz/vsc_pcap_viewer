# Contributing

How to build, test and release PCAP Viewer. Architecture notes and design
decisions are in `CLAUDE.md`.

## Set up (Linux)

Commands are for Ubuntu/Debian; macOS and Windows work the same once the tools
are installed.

| Tool                | Install                                                                                      |
| ------------------- | -------------------------------------------------------------------------------------------- |
| Git, VS Code ≥ 1.90 | `sudo apt install git`; VS Code from [code.visualstudio.com](https://code.visualstudio.com/) |
| tshark              | `sudo apt install tshark` (Fedora `wireshark-cli`, Arch `wireshark-cli`)                     |
| uv and Python 3.14  | `curl -LsSf https://astral.sh/uv/install.sh \| sh`, then `uv python install 3.14`            |
| Node.js 22.13+      | [nvm](https://github.com/nvm-sh/nvm): `nvm install 22`                                       |
| pnpm                | `corepack enable pnpm` (version pinned in `package.json`)                                    |

Keep `~/.local/bin` on your `PATH` (VS Code must find `python3.14`), and don't
run VS Code as root (tshark disables Lua for root).

```sh
git clone https://github.com/DenPaz/vsc_pcap_viewer.git
cd vsc_pcap_viewer
uv sync            # .venv with Python 3.14 and the dev tools
pnpm install       # TypeScript toolchain, ESLint, mocha, vsce, Playwright
pnpm run compile   # build into out/
```

## Run

- **From source**: open the folder in VS Code and press `F5`. The Extension
  Development Host opens with `test/fixtures/`. `pnpm run watch` rebuilds on
  save; reload the host with `Ctrl+R`. `src/webview/` needs no build.
- **Installed**: `pnpm run package`, then
  `code --install-extension pcap-viewer-<version>.vsix`.

## Test and lint

The `Makefile` wraps everything (`make` lists the targets):

| Command                         | Does                                                                |
| ------------------------------- | ------------------------------------------------------------------- |
| `make check`                    | Lint and all tests except the VS Code smoke test (what CI runs)     |
| `make lint` / `make format`     | ESLint, Prettier, ruff, mypy / auto-fix what they can               |
| `make test-backend`             | `uv run pytest` (tshark tests skip without tshark)                  |
| `make test-acceptance`          | Gherkin scenarios in `test/backend/acceptance/features/`            |
| `make test-unit`                | Extension unit tests and webview tests, including headless Chromium |
| `make test-extension`           | VS Code smoke test (uses `xvfb-run` when there's no display)        |
| `make fixtures` / `make perf`   | Regenerate test captures / benchmark 1M packets                     |
| `make update` / `make outdated` | Upgrade dev dependencies / list available updates                   |
| `make package` / `make clean`   | Build the `.vsix` / remove build output                             |

- Formatting: Prettier (TS, JS, CSS, HTML, JSON, YAML, Markdown) and ruff
  (Python); VS Code formats on save with the recommended extensions.
- The Chromium test needs a Chromium:
  `pnpm exec playwright-core install --with-deps chromium`.
- Performance:

  ```sh
  uv run python test/fixtures/generate.py --large 1000000 test/fixtures/large-1m.pcap
  uv run python -u test/perf/bench.py test/fixtures/large-1m.pcap --no-tcp-analysis
  ```

- TLS decryption sample:
  `uv run python test/fixtures/generate.py --tls-keylog /tmp/tls.pcap /tmp/tls-keys.log`,
  then _PCAP: Set TLS Key Log File…_ with the `.log`.

CI (`.github/workflows/ci.yml`) runs everything on Linux, macOS and Windows for
pull requests and pushes to `main`.

### Development troubleshooting

| Symptom                                              | Fix                                                                                                                                                                           |
| ---------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `make fixtures` fails with "No module named '_zstd'" | Python was built without zstd (pyenv without `libzstd-dev`). Install it and rebuild, or use a uv Python: `uv venv --python 3.14 --python-preference only-managed && uv sync`. |
| `pnpm install` fails with "Ignored build scripts"    | Use the pinned pnpm (`corepack enable pnpm`); the policy is in `pnpm-workspace.yaml`.                                                                                         |

## Changelog

Add each user-visible change under `## Unreleased` in `CHANGELOG.md`, in the
right group (`### Added`, `### Changed`, `### Fixed`), with a link to its pull
request: `[#42]` in the entry and `[#42]: https://github.com/DenPaz/vsc_pcap_viewer/pull/42`
at the end of the same section. Link definitions stay inside their version's
section, so the GitHub release notes keep them.

## Release

```sh
pnpm run release:prepare 0.3.0   # bump package.json, move "Unreleased" under "0.3.0 — <date>"
git commit -am "Release 0.3.0"   # merge it to main (through a PR if main is protected)
git tag v0.3.0                   # on main
git push origin v0.3.0
```

The tag runs `.github/workflows/release.yml`:

1. The whole CI.
2. A check that the tag, `package.json` and the CHANGELOG agree.
3. `vsce package`.
4. A GitHub release with the `.vsix` and the version's notes.
5. Publishing to the VS Code Marketplace and Open VSX when the `VSCE_PAT` and
   `OVSX_PAT` repository secrets exist; otherwise those steps are skipped.

Running the workflow by hand on the tag retries a failed release. Versions are
plain `x.y.z`.

The icon is `media/icon.svg`, rendered by `node scripts/render-icon.js`. The
screenshots in `media/screenshots/` come from `node scripts/screenshots.js`
(after `pnpm run compile`).
