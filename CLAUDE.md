# CLAUDE.md — working notes for PCAP Viewer

Wireshark-like `.pcap`/`.pcapng` viewer for VS Code. TypeScript extension +
stdlib-only Python backend that orchestrates `tshark`. See README.md for the
user-facing description.

## Commands

| Task | Command |
|---|---|
| Install dev deps | `uv sync` and `pnpm install` |
| Build extension | `pnpm run compile` (tsc → `out/`) |
| Lint everything | `pnpm run lint && uv run ruff check && uv run ruff format --check && uv run mypy` |
| Backend tests | `uv run pytest` (tshark tests skip if tshark is missing) |
| Acceptance scenarios only | `uv run pytest test/backend/acceptance` (pytest-bdd, Gherkin in `features/`) |
| TS unit + webview tests | `pnpm run test:unit` (mocha; includes the Chromium e2e test of the webview) |
| VS Code smoke test | `pnpm run test:extension` (downloads VS Code; use `xvfb-run -a` on headless Linux) |
| Regenerate fixtures | `uv run python test/fixtures/generate.py` |
| Perf check | `uv run python test/fixtures/generate.py --large 1000000 test/fixtures/large-1m.pcap && uv run python -u test/perf/bench.py test/fixtures/large-1m.pcap` |
| Package | `pnpm run package` (vsce, `--no-dependencies`) |

## Toolchain

- **Python 3.14** everywhere: `requires-python >=3.14`, ruff `py314`, mypy
  `3.14`, `.python-version` (uv and CI's setup-python read it). The extension
  enforces the same minimum (`MIN_PYTHON` in `src/backendClient.ts`) and tries
  `python3.14` / `py -3.14` before generic names. Code uses 3.14 idioms: PEP 695
  generics, no `from __future__ import annotations` (PEP 649 lazy annotations).
- **pnpm** (version pinned by `packageManager` in package.json; use
  `corepack enable pnpm`). pnpm refuses to install until every dependency with
  an install script is allowed or denied: `pnpm-workspace.yaml` denies
  `keytar` and `@vscode/vsce-sign` (vsce's publishing/signing helpers, unused).
  `vsce package` runs with `--no-dependencies` because its dependency check
  runs `npm list`, which doesn't understand pnpm's layout (the extension has
  no runtime npm dependencies anyway). `.vscode/settings.json` makes VS Code's
  npm tasks use pnpm.
- Node tests that start the backend use `PCAP_VIEWER_PYTHON` if set, else the
  uv `.venv` interpreter, so they run on 3.14 even when the system `python3` is older.
- pytest turns `ResourceWarning` into errors: leaked tshark pipes are bugs.

## Layout

- `src/extension.ts` activation, config-change handling. `src/pcapEditor.ts`
  custom editor + one `PcapEditorSession` per panel. `src/backendClient.ts`
  JSON-RPC client (no `vscode` import: unit-testable). `src/settingsModel.ts`
  pure settings helpers. `src/commands/` command implementations.
- `src/webview/` plain JS/CSS/HTML (no build step). `lib.js` = pure helpers
  shared with Node tests; `main.js` = UI. Type-checked via JSDoc +
  `tsconfig.webview.json`.
- `src/panels/` statistics and follow-stream webview panels (`panelHtml.ts`
  builds their CSP'd HTML); their UIs are `src/webview/stats.js` and
  `follow.js` with `panel.css`.
- `backend/pcap_backend/` Python package run as `python -m pcap_backend`
  with `PYTHONPATH=backend`. `server.py` (JSON-RPC), `pcap_service.py`
  (methods), `tshark.py` (discovery/argv/process helpers), `cache.py`
  (row store, frame index, LRU), `pdml.py` (PDML + hexdump parsing),
  `stats.py` (`-z` report and follow parsers), `fields.py` (field catalogue),
  `protocol.py` (error codes, request context), `cancellation.py`.
- `backend/dissectors/example.lua` sample dissector (UDP/9999).
- `test/backend` pytest; `test/backend/acceptance` pytest-bdd scenarios
  (`features/*.feature` = brief's acceptance criteria against the backend,
  steps in its `conftest.py`, feature tag `@tshark` → skip without tshark,
  `@lua` → skip as root), `test/extension/unit` mocha (Node), `test/extension/suite`
  VS Code smoke test, `test/webview` mocha (lib + Chromium e2e), `test/fixtures`
  scapy-generated captures, `test/perf/bench.py`.

## Rules (from the brief — do not break)

- Never build shell strings; always argv arrays (`subprocess.Popen([...])`,
  `spawn(cmd, args, {shell: false})`). Never `shell=True`.
- Never put packet data into `innerHTML` (ESLint forbids `innerHTML`/`outerHTML`/
  `insertAdjacentHTML` in webview code). Use `textContent`/`createElement`.
- Webview CSP: `default-src 'none'`, scripts only with the per-load nonce.
- Backend runtime must stay **stdlib-only** (dev tools live in the uv `dev` group).
- stdout of the backend is protocol only; log to stderr.
- Kill child processes on close: `BackendClient.stop()` closes stdin → backend
  cancels requests and kills tshark (`PROCESSES.kill_all`) → SIGTERM/SIGKILL
  (tree kill with `taskkill /T` on Windows) as fallbacks.

## Writing acceptance scenarios

Add scenarios to `test/backend/acceptance/features/*.feature` using existing
steps where possible (`uv run pytest --collect-only test/backend/acceptance`
lists them; step definitions are in `acceptance/conftest.py`). New steps go in
that conftest. Keep step patterns specific: `parsers.parse` patterns such as
`the filter is {result}` also match longer sentences, so prefer `parsers.re`
with alternatives. Lists are written `a, b and c` and parsed by `items()`.
UI behaviour stays in the Chromium test (`test/webview/e2e.test.js`).

## Design decisions (defaults chosen where the brief was open)

- **Packaging of the backend**: a package (`backend/pcap_backend/`) rather than
  loose `server.py`/`pcap_service.py` files, managed by `pyproject.toml` + uv
  (no `requirements.txt`: there are no runtime dependencies).
- **One backend per editor panel** (not per document): the backend holds the
  current filter/sort view, so two panels on one file must not share it.
- **Row store on disk**: the open pass writes tshark's `-T fields` output to a
  temp file and keeps an `array('Q')` of line offsets (8 B/frame). Filters keep
  an `array('I')` of matching frame numbers (4 B/match), cached in an LRU keyed
  by expression and bounded by `pcapViewer.maxCachedFrames`. Scrolling never
  runs tshark.
- **Column field names**: tshark ≥ 4.2 uses `_ws.col.def_src/def_dst/protocol/info`;
  older versions `_ws.col.Source/…`. The index pass tries the new names and
  falls back automatically when tshark rejects them. Unknown custom column
  fields are dropped with a warning (tshark's "Some fields aren't valid" is parsed).
- **Never duplicate `-e` fields**: tshark blanks the first copy of a duplicated
  field (found the hard way with `frame.number`).
- **Detail**: `tshark -r f -c N -Y frame.number==N -T pdml` plus `-x` in
  parallel. `-c N` stops reading after frame N (it counts packets *read*), so
  cost is proportional to N, and earlier packets are still dissected (TCP
  reassembly etc. stay correct). Detail of frame ~1M therefore costs about one
  pass over the file; a random-access fast path (editcap) would lose
  reassembly context, so it is not used.
- **Byte sources**: PDML does not say which data source (frame vs reassembled)
  a field's `pos` refers to. Heuristic in `pdml.py`: top-level items after a
  `*.segments`/`*.fragments` node belong to the next `-x` source. Documented
  limitation for exotic multi-source packets (e.g. decrypted TLS + decompression).
- **Filter validation**: compile against a shared 24-byte empty pcap
  (`tshark -Y expr -r empty.pcap`), with the same `-X/-d/-o` options so Lua
  fields validate.
- **Sorting** is backend-side over the current filter's frames: one column is
  read from the row store (cached, 3 columns max), sorted in Python, and the
  resulting order is cached per (filter, column, direction). IP columns sort as
  text (tradeoff: simple and predictable; Wireshark sorts addresses numerically).
- **Progress** during open is estimated from summed frame lengths vs file size
  (no capinfos needed up front); capinfos runs in parallel for metadata.
- **Virtualized list**: fixed row height; above 10M px of content the scroll
  range is compressed (`lib.computeWindow`) so >1.6M rows still scroll.
- **Lua as root**: tshark refuses Lua when run as root; the backend warns. The
  Lua integration test skips as root (CI runs as a normal user).
- **Field catalogue** (`fields.py`): `tshark -G fields` must be tshark's
  *first* option (anything after it is a name filter), so it can't take
  `-X lua_script:`. Lua fields are picked up by a second `-G fields` run with
  `WIRESHARK_PLUGIN_DIR` pointing at a temp folder holding numbered copies of
  the configured scripts; that run replaces the global plugin folder, so both
  outputs are merged (deduplicated). Prefix search bisects a sorted,
  lower-cased key list (~250k entries). The webview warms it after `init`.
- **Autocomplete UX**: nothing is preselected, so `Enter` always applies the
  filter unless a suggestion was picked with the arrows; `Tab` takes the
  first suggestion. Operators are only offered right after a space (or on
  `Ctrl+Space`). Context detection (`lib.completionContext`) is heuristic:
  field / comparison operator / logical operator / none (strings, values).
- **Per-capture settings**: `luaScripts`, `dissectorsFolder`, `decodeAs` and
  `prefs` are `resource`-scoped and always read with the capture's URI
  (`readSettings(session.uri)`, `getSetting`), so multi-root folders can differ.
  Writes go through `updateSetting(key, value, scope)`, which targets the most
  specific level that already defines the key (`configTargetFor`).
- **Saved filters** are the `pcapViewer.savedFilters` setting (not
  `globalState`): user vs workspace scope gives "global or workspace"
  persistence, and they sync and can be edited in settings.json. Recent-filter
  history stays in `globalState` (50 entries).
- **Follow stream** uses tshark's `-z follow,<proto>,raw,<n>`: one hex line per
  segment, lines starting with a tab come from node 1. Exact bytes, so ASCII,
  hex dump and raw views plus raw save are all rendered client-side. The
  stream number for a packet comes from `tcp.stream`/`udp.stream`, extracted
  once through the row-store column machinery (first follow costs one pass).
  TLS/HTTP follow the TCP stream number. Payload is capped (`maxBytes`, 16 MB).
- **Statistics** parse tshark's human-readable `-z` reports into one generic
  table model (`stats.py`: columns, rows with optional `filter`/`frame`/`depth`),
  rendered by one panel (`src/webview/stats.js`). Sizes like "12 kB" are
  converted with SI units. Expert info joins `-z expert` (severity/group/
  protocol/count) with a `-T fields -e _ws.expert` pass (aggregator `\x1e`)
  to get frame numbers. Rows are matched by regex because multi-word groups
  ("Response code") overflow tshark's fixed-width column. The display-filter
  limit uses each tap's own filter argument (`conv,tcp,<filter>` etc.).
- **Never `str.splitlines()` on packet-derived text**: it also splits on
  `\x1c`–`\x1e`, `\x85`, `\u2028`… Stats parsers use `_lines()` (split on `\n`).
- **Panels** (`src/panels/`) are separate webview panels beside the editor. They
  share the editor's backend (`session.backend`), close with it
  (`session.onDidDispose`), and send filters/goto back to it. One stats panel
  per (editor, kind); follow panels are per invocation. The IO graph is a
  single-series SVG line in the theme's `--vscode-charts-blue` (no legend,
  hover crosshair, keyboard arrows/Home/End, the table below is the
  accessible view). Packets or bytes is a switch, never a second axis.
- **Dissector check**: `check_dissectors` loads the Lua scripts against the
  empty capture (no packets read) and returns tshark's `Lua:` stderr blocks
  (exit code stays 0 on Lua errors). Lua shortens long chunk paths to
  `...tail`, so the script is found by suffix (`script_in_lua_message`).
  "Reload Dissectors" runs it first, then re-indexes every open capture.
- **Decode As choices** come from tshark itself: an invalid `-d` rule makes it
  print "Valid layer types are:" or "Valid protocols for layer type X are:"
  lists (parsed by `parse_decode_as_choices`, cached). An unknown layer gets
  the layer list back, which is detected and rejected.
- **Protocol**: JSON-RPC 2.0 framing (`"jsonrpc": "2.0"`), LSP-style
  cancellation code -32800; app codes in `backend/pcap_backend/protocol.py`
  and mirrored in `src/backendClient.ts` (`ErrorCodes`). `open` returns the
  initial `filterId`; every `list_packets` result carries the current one so
  the webview drops stale pages.

## Performance notes (test/perf/bench.py, 1M synthetic packets, 146 MB)

With `-o tcp.analyze_sequence_numbers:FALSE`: open 36 s, filter 26 s, page
fetch < 1 ms, sort 0.6 s, detail of last frame 26 s, backend RSS 125 MB,
tshark 225 MB. With TCP analysis on, the synthetic file (512 replayed flows)
makes tshark super-linear (filter 165 s for 1M vs 4.5 s for 100k); real
captures are not expected to behave like that. Sorting streams one column from
the row store and sorts indices with a stable key list (no per-row tuples):
this took the backend from 710 MB to 125 MB peak.

## Status

Implemented: steps 1–6 of the brief (foundation, packet list with paging /
virtualization / sorting / custom columns, detail tree + hex with two-way
highlighting, display filters with validation, autocomplete, history, saved
filters, apply-as-filter, follow TCP/UDP/TLS/HTTP stream, and statistics
panels: conversations, endpoints, protocol hierarchy, IO graph, expert info,
capture properties).

Also step 6: Lua dissector commands (new from template, reload with error
check, open folder, reload offer on save) and a Decode As UI plus rule manager.

Not yet: export, coloring rules, quick view for late packets in huge files.
