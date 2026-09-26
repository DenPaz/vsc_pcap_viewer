# CLAUDE.md — working notes for PCAP Viewer

Wireshark-like `.pcap`/`.pcapng` viewer for VS Code. TypeScript extension +
stdlib-only Python backend that orchestrates `tshark`. See README.md for the
user-facing description.

## Commands

| Task | Command |
|---|---|
| Install dev deps | `uv sync` and `npm install` |
| Build extension | `npm run compile` (tsc → `out/`) |
| Lint everything | `npm run lint && uv run ruff check && uv run ruff format --check && uv run mypy` |
| Backend tests | `uv run pytest` (tshark tests skip if tshark is missing) |
| Acceptance scenarios only | `uv run pytest test/backend/acceptance` (pytest-bdd, Gherkin in `features/`) |
| TS unit + webview tests | `npm run test:unit` (mocha; includes the Chromium e2e test of the webview) |
| VS Code smoke test | `npm run test:extension` (downloads VS Code; use `xvfb-run -a` on headless Linux) |
| Regenerate fixtures | `uv run python test/fixtures/generate.py` |
| Perf check | `uv run python test/fixtures/generate.py --large 1000000 test/fixtures/large-1m.pcap && uv run python -u test/perf/bench.py test/fixtures/large-1m.pcap` |
| Package | `npm run package` (vsce) |

## Layout

- `src/extension.ts` activation, config-change handling. `src/pcapEditor.ts`
  custom editor + one `PcapEditorSession` per panel. `src/backendClient.ts`
  JSON-RPC client (no `vscode` import: unit-testable). `src/settingsModel.ts`
  pure settings helpers. `src/commands/` command implementations.
- `src/webview/` plain JS/CSS/HTML (no build step). `lib.js` = pure helpers
  shared with Node tests; `main.js` = UI. Type-checked via JSDoc +
  `tsconfig.webview.json`.
- `backend/pcap_backend/` Python package run as `python -m pcap_backend`
  with `PYTHONPATH=backend`. `server.py` (JSON-RPC), `pcap_service.py`
  (methods), `tshark.py` (discovery/argv/process helpers), `cache.py`
  (row store, frame index, LRU), `pdml.py` (PDML + hexdump parsing),
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

Implemented: steps 1–3 of the brief (foundation, packet list with paging /
virtualization / sorting / custom columns, detail tree + hex with two-way
highlighting), plus filter validation, history (datalist) and tree
context-menu "Apply/Prepare as Filter".

Not yet: autocomplete UI (backend `field_index` exists), saved filters,
follow stream, statistics, export, coloring rules, Lua management commands,
Decode As UI (settings already work end-to-end).
