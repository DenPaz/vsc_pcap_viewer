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
| Update dev deps | `make update` (`ncu -u` within `.ncurc.cjs`, `pnpm install`, `uv lock --upgrade`, `uv sync`) |

The `Makefile` wraps all of these (`make` lists the targets; `make check` = lint + tests).

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
- **Dependency updates**: `pnpm dlx npm-check-updates -u` reads `.ncurc.cjs`:
  `@types/vscode` is never bumped (it must not exceed `engines.vscode`, or vsce
  refuses to package; raise both together), `@types/node` stays on Node 20
  (VS Code 1.90's extension host), and peer ranges are respected
  (typescript-eslint caps TypeScript, so TS 7 waits). mocha 12 is ESM-only:
  the VS Code smoke suite loads it with `await import("mocha")`. Node ≥ 22.13
  is needed for the dev tools. Python dev tools: `uv lock --upgrade`.
- Node tests that start the backend use `PCAP_VIEWER_PYTHON` if set, else the
  uv `.venv` interpreter, so they run on 3.14 even when the system `python3` is older.
- pytest turns `ResourceWarning` into errors: leaked tshark pipes are bugs.
- **CI** (`.github/workflows/ci.yml`) runs everything on Linux (apt tshark),
  macOS (`brew install --formula wireshark`) and Windows (`choco install
  wireshark`, `C:\Program Files\Wireshark` added to PATH): lint, backend and
  acceptance tests with tshark, unit + Chromium e2e tests, and the VS Code
  smoke test (Linux under xvfb). It runs on pull requests, pushes to main and
  by hand (`workflow_dispatch`).

## Layout

- `src/extension.ts` activation, config-change handling. `src/pcapEditor.ts`
  custom editor + one `PcapEditorSession` per panel. `src/backendClient.ts`
  JSON-RPC client (no `vscode` import: unit-testable). `src/settingsModel.ts`
  pure settings helpers. `src/commands/` command implementations
  (`export.ts`, `coloring.ts`, `dissectors.ts`, `tls.ts`, …).
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
  `coloring.py` (coloring rules → `colorfilters`), `navigation.py` (find
  expressions, hex parsing, frame-set filters, time formatting), `export.py` (destination
  checks, atomic output, CSV/JSON writers), `protocol.py` (error codes,
  request context), `cancellation.py`, `index_cache.py` (saved indexes),
  `procs.py` (stopping children, also
  when the kill is refused), `sandbox.py` (AppArmor/Snap detection and hints).
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
- Never call `proc.kill()`/`terminate()` directly: use `procs.kill_process`
  (never raises) and `procs.stop_process` (reaps, closes pipes). A sandbox can
  refuse the signal (see *Sandboxed tshark*).

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
  runs tshark. `RowStore.publish()` flushes and makes appended rows visible
  (`len()` = published rows); the index pass publishes every progress tick.
- **Streaming open** (`open {stream: true}`, what the host sends): the index
  pass runs in the pool (`_run_index`); `open` returns once FIRST_BATCH (1000)
  rows are published or after FIRST_BATCH_S (0.5 s) with some (`indexing:
  true`), else when done. The pass then reports through backend notifications
  `index {event: progress|done|failed}` (`service.notify` = `server.notify`;
  `BackendClient.onNotification`). An `_Indexing` object is "attached" under
  `_lock` when `open` publishes the partial capture, so a pass ending at the
  same moment either completes `open` or finalises the attached capture, never
  neither. The host subscribes before sending `open` and buffers events until
  the webview has its `init` (a fast "done" can beat the response). While
  indexing, `_require_view` grows the unfiltered view to the published rows;
  everything that needs all rows raises `IndexingError` (-32012): sorting,
  find, conversation stepping, extra column passes (follow stream), CSV/JSON
  export, coloring (the host starts coloring after "done"), and non-streaming
  filters. A streaming filter works (see *Streaming filters*). Non-relative
  time formats show relative times until done. Index notifications carry
  `view {filterId, matchCount}` when a filter is applied. The webview refuses
  sorting with a notice, grows `total` on `indexProgress` (`growList`, which
  drops the cached short last page), and `refreshRows()` on done. Closing cancels the pass and waits
  for it (`_close_file` drops `_lock` meanwhile: the pass takes it to finish).
- **Saved indexes** (`index_cache.py`, `open {cache: {dir, maxBytes}}`; the
  host passes `globalStorageUri/index-cache`, `pcapViewer.indexCache.*`): an
  entry `<key>/` holds `rows.tsv`, `offsets.bin`, `meta.json` (info, fields,
  column names, kept columns) and up to 4 `colors-<rules>.bin/.json`. The key
  hashes the capture's resolved path, size, mtime_ns and inode; tshark path and
  version (`--version`, cached per path); Lua scripts by content; Decode As;
  prefs; requested columns; and a fingerprint (names, sizes, mtimes) of tshark's
  personal configuration and plugin folders (`tshark -G folders`), which change
  dissection too. Entries are written to `.key.pid.tmp` and renamed; a load
  touches `meta.json` (LRU) and the rows are hard-linked (else copied) into the
  work dir, so pruning never pulls the file from under an open capture.
  Saving runs after the pass, in the background, also hard-linking. Size cap:
  least recently used first. Coloring results are saved per rules digest and
  reused by `set_coloring` (`_coloring_pass` is skipped). Finished filter
  results are saved as `filter-<sha256(expr)[:24]>.bin` (array('I') bytes, the
  8 most recent per entry) and loaded by `set_filter` before running tshark.
  A preference whose value is an absolute file path (the TLS key log) adds the
  file's size and mtime to the key, so new keys mean a new index. *PCAP: Clear
  Index Cache* deletes the folder from the host. Custom columns added later are extra
  passes and not saved (the next open with them is a new key).
- **Streaming filters** (`set_filter {stream: true}`, what the webview sends):
  after validation, `_start_filter` installs a view with a `_Filtering`
  (`view.live`) and runs `_filter_pass` in the pool; `set_filter` returns after
  FIRST_BATCH matches or FIRST_BATCH_S with `filtering: true`. The pass appends
  to `live.frames`; every progress tick copies it into `live.snapshot` (readers
  never see the array grow) and sends `filter {event: progress, filterId,
  matchCount, fraction}`; the end sends `done`, `stopped` (`stop_filter
  {filterId}`) or `failed` (with `message`). Stopped/failed views keep their
  matches (`view.partial`, not cached; applying the same filter reruns it).
  `_require_view` shows the snapshot, and while a streaming open still indexes
  only the matches among the published rows (bisect), even after the pass is
  done; such results are cached only once indexing is done. `_install_view`
  cancels the pass of the view it replaces; cancelling the `set_filter`
  request during its first wait restores the previous view. Matches stay in
  capture order while `live` is set (`_apply_sort` returns them unsorted and
  keeps `view.sort` None), so the first request after `done` sorts.
  `_require_complete` (IndexingError with `filtering: true`) guards find,
  conversation stepping and CSV/JSON export; `find_frame`/`view_frames` work
  (positions are stable while matches are appended). `_run_filter` checks the
  token per line, since tshark's buffered output would otherwise still come.
  Webview: `filtering`/`filterFraction`/`filterPartial`; ■ (`#filter-cancel`)
  cancels the request, then stops the filter; a sort chosen meanwhile gets a
  notice and applies on `done` (`resetView`); events for a newer `filterId`
  than the webview knows wait in `earlyFilterEvents` (a fast pass can report
  before its `set_filter` result arrives); a selected frame not found yet is
  kept and looked up again on `done`. The host forwards `filter` notifications
  as `filterEvent`.
- **TLS key log** (`pcapViewer.tlsKeyLogFile`, resource-scoped): `readSettings`
  resolves it like the dissectors folder (`resolveSettingPath`) and adds it to
  `prefs` as `tls.keylog_file` (`withTlsKeyLog`; it overrides that pref). Any
  pref ending in `.keylog_file` naming a missing file is a warning
  (`check_scripts`). Changing the setting reloads the sessions whose
  `keyLogFile` differs, without asking (extension.ts). Each load watches the
  file (`watchKeyLog`, RelativePattern on its folder, debounced 1 s) and offers
  a reload when it changes, one question at a time. *PCAP: Set TLS Key Log
  File…* (`commands/tls.ts`) checks the file with `looksLikeKeyLog` (empty is
  fine: a fresh SSLKEYLOGFILE) and can stop using the current one. Tests use
  `generate.tls_keylog_capture`: a TLS 1.2 PSK session (no certificate) run in
  memory with `ssl.MemoryBIO` and `keylog_filename`, generated per run (the
  randoms differ, so it isn't committed; `tls_keylog` fixture, skipped without
  PSK support).
- **Column field names**: tshark ≥ 4.2 uses `_ws.col.def_src/def_dst/protocol/info`;
  older versions `_ws.col.Source/…`. The index pass tries the new names and
  falls back automatically when tshark rejects them. Unknown custom column
  fields are dropped with a warning (tshark's "Some fields aren't valid" is parsed).
- **Never duplicate `-e` fields**: tshark blanks the first copy of a duplicated
  field (found the hard way with `frame.number`).
- **File types**: tshark detects the format from the content, so the file name
  only picks the editor. Two `customEditors` contributions share one provider:
  `pcapViewer.editor` (priority `default`) for unambiguous capture files
  (pcap/pcapng/cap/ntar, `.gz`/`.zst`/`.lz4` compressed pcap(ng), `*.pcap[0-9]*`
  tcpdump rotation, snoop, ERF, PacketLogger, btsnoop) and
  `pcapViewer.editorOptional` (priority `option`: *Reopen Editor With…* only)
  for generic extensions (`*.[0-9]`, `.log`, `.dmp`, `.trc`, `.ber`). VS Code
  matches selectors against the basename, ignoring case
  (`globMatchesResource`); the patterns were checked with VS Code's own
  `glob.ts`, and the smoke test opens every `test/fixtures/formats/` file to
  check which editor VS Code picks. `when` clauses use
  `activeCustomEditorId =~ /^pcapViewer\.editor(Optional)?$/`. Every pattern
  has a fixture (`test_every_file_pattern_has_a_fixture`); fixtures in other
  formats are hand-written by `generate.py` (stdlib only: gzip, `compression.zstd`
  (imported lazily: Pythons built without libzstd lack `_zstd`, and `--large`
  must work there),
  an LZ4 frame with stored blocks, snoop, ERF, PacketLogger, btsnoop, raw BER).
  Open progress is estimated only for uncompressed pcap/pcapng recognised by
  magic number (`sniff_format`); otherwise it's indeterminate (null fraction)
  instead of stalling at 99%. "isn't a capture file in a format TShark
  understands" becomes `UnsupportedFormatError` (-32011), shown in the viewer
  with a *Reopen Editor With…* button. `exportFileName` strips compression and
  format suffixes (`trace.pcap.gz` → `trace-filtered.pcapng`).
- **Detail**: `tshark -r f -c N -Y frame.number==N -T pdml` plus `-x` in
  parallel. `-c N` stops reading after frame N (it counts packets *read*), so
  cost is proportional to N, and earlier packets are still dissected (TCP
  reassembly etc. stay correct). Detail of frame ~1M therefore costs about one
  pass over the file (20 s on the benchmark capture).
- **Quick detail** (`packet_detail {mode: "quick", window}`): for frames past
  `pcapViewer.quickDetail.after` (default 20k) the webview asks for the exact
  and the quick detail together and shows whichever comes first; the exact one
  replaces the quick one (same frame: `showDetail` keeps expansion, the
  selected field and the scroll position; the quick request is cancelled when
  the exact one lands). Quick = `editcap -F pcapng -r <capture> <tmp> first-N`
  (reads records without dissecting: 0.13 s at the end of 1M packets) then
  `_dissect` of the window's last frame, ~0.3 s in all. The window numbers
  its frames from 1, so `pdml.renumber_tree` adds `first - 1` to
  `frame.number`, the "Frame N:" header, `*.segments` `#N(len)` references
  and every FT_FRAMENUM field (field catalogue; while it is still loading, a
  name list `_FRAMENUM_HINT`, and the catalogue is warmed in the background,
  once), only for values inside the window, and puts the capture's
  `frame.time_relative` back (the window measures from its own start).
  Result: `approximate: true, window: [first, N]`; the webview shows a sticky
  note ("only packets X–N were dissected…"). References to packets before
  the window are simply absent (e.g. `http.request_in`). A quick request
  returns the exact detail when cached or when the window starts at frame 1,
  and `{unavailable}` without editcap (the webview then waits for the exact
  one). Quick results have their own LRU (16) keyed by (frame, window). Ask
  Copilot uses quick details for late packets too, and the prompt says which
  trees are approximate.
- **Byte sources**: PDML does not say which data source (frame vs reassembled)
  a field's `pos` refers to. Heuristic in `pdml.py`: top-level items after a
  `*.segments`/`*.fragments` node belong to the next `-x` source. Documented
  limitation for exotic multi-source packets (e.g. decrypted TLS + decompression).
  The first source is always named "Frame" (`pdml.FRAME_SOURCE`): tshark 4.6
  prints "Packet (N bytes):" where 4.2/4.4 print "Frame", and single-source
  packets print no header at all, so the byte tabs and *Export Packet Bytes*
  read the same across versions.
- **Filter validation**: compile against a shared 24-byte empty pcap
  (`tshark -Y expr -r empty.pcap`), with the same `-X/-d/-o` options so Lua
  fields validate.
- **Sorting** is backend-side over the current filter's frames: one column is
  read from the row store (cached, 3 columns max), sorted in Python, and the
  resulting order is cached per (filter, column, direction). Source/Destination
  and custom columns of FT_IPv4/FT_IPv6/FT_ETHER fields (catalogue lookup) sort
  by `cache.address_key`: IPv4 < IPv6 < MAC < other text, numerically within
  each, as one fixed-width hex string per row (no tuples, so memory stays flat).
  The Time column sorts by the time format shown: the absolute formats (and a
  time reference) keep capture order, the two delta formats sort by the delta
  (internal sort keys `@delta_displayed`/`@delta_captured`, computed from
  `frame.time_epoch`). Every request that returns or takes row indexes
  (`list_packets`, `find_frame`, `view_frames`, `find_packet`,
  `neighbor_frame`) carries `sort`/`timeFormat` and applies it first
  (`_apply_sort`): an index request must not overtake the page request that
  changes the sort (found by the multi-select e2e test: the selection was
  relocated with the old order).
- **Progress** during open is estimated from summed frame lengths vs file size
  (no capinfos needed up front); capinfos runs in parallel for metadata.
- **Virtualized list**: fixed row height; above 10M px of content the scroll
  range is compressed (`lib.computeWindow`) so >1.6M rows still scroll.
- **Sandboxed tshark**: Ubuntu's apparmor package ships `/etc/apparmor.d/tshark`
  (upstream since 2025), which confines `/usr/bin/tshark` to `/tmp` and
  Wireshark's folders, so `-r ~/x.pcap` fails with "You don't have permission
  to read the file". The backend is unconfined: `open` first reads a byte
  itself (real permission problems get their own message), and every tshark
  failure goes through `Tshark.error()`, which appends `permission_hint()`
  (AppArmor profile loaded in enforce mode → local-rule instructions; Snap →
  use the distro package; else generic). Temp files (empty capture, coloring
  config) live in `/tmp`, which the profile allows.
  The profile also only lets tshark receive signals from itself, so killing a
  cancelled tshark raises `PermissionError` (kernel log: `operation="signal"
  … peer="vscode"`, VS Code's own profile, or `peer="unconfined"` in the
  tests). Hints and detection live in `sandbox.py`: `APPARMOR_HINT` suggests
  `owner @{HOME}/** rw,`, `signal (receive) peer=unconfined,` and
  `signal (receive) peer=vscode,` plus `apparmor_parser -r`, both for tshark
  permission errors and (`kill_denied_hint`) for a refused kill, logged once
  to stderr. Cancellation never depends on the signal (`procs.py`): the thread
  that owns a process polls (`communicate(timeout)` in `run()`, a selector on
  stdout in `stream_lines` on POSIX; Windows reads blocking, its kill always
  works), and `stop_process` closes our end of stdout when the kill is refused,
  so tshark's next write fails (the kernel's SIGPIPE isn't mediated) and it
  exits. Anything still running after `STOP_TIMEOUT` goes to a reaper thread
  (it stays in `PROCESSES` until reaped), so no pipe or `Popen` is leaked
  (pytest turns ResourceWarning into errors). `test_procs.py` fakes the
  refusal with real children whose `kill` raises `PermissionError`.
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
  converted with SI units. tshark 4.6 adds a top-level `frame` row to the
  protocol hierarchy (eth at depth 1, dns at 4; 4.2: 0 and 3), so tests check
  parent rows ("dns one level below udp") and totals, never absolute depths.
  Percentages divide by the depth-0 rows, which cover every packet either way. Expert info joins `-z expert` (severity/group/
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
- **Coloring rules** are evaluated by tshark (`--color`, field
  `frame.coloring_rule.name`, first match wins), which only reads them from
  `colorfilters` in the personal config folder. Each `set_coloring` pass sets
  `WIRESHARK_CONFIG_DIR` to a temp folder holding the generated file plus
  copies of the user's other personal config files (found via `tshark -G
  folders`), so dissection matches the other passes. Rules are named by index
  (the file format can't quote names; filters with `@` are rejected), tshark's
  "Could not compile" stderr is mapped back to rule indexes. The result is one
  byte per frame (`array('B')`, max 255 rules); `list_packets` rows carry
  `color` plus the page's `coloringId`, and the webview only uses colors whose
  `coloringId` matches its palette (it's part of the page cache key).
  *At open* the rules are evaluated by the index pass itself (`open {coloring:
  {rules}}`, `_InlineColoring`): `--color` in the same `WIRESHARK_CONFIG_DIR`
  setup (`work_dir/colorfilters`) and `frame.coloring_rule.name` as the last
  `-e` field, split off each line before the row is stored (`_read_rows`,
  `_add_color`), so the row store is unchanged and every published row
  already has its color. Measured +2 s on 1M packets (34.6 → 36.7 s) instead
  of a separate ~30 s pass that had to wait for indexing. `open` returns
  `coloring: {coloringId}` (plus `colored`/`errors` when complete; else in
  "done"); compile-error stderr blocks are rules' errors, not warnings. If
  tshark rejects the field, the pass is retried without colors. The colors
  are saved with the index (`save_colors` after `save`, same rules digest as
  set_coloring), and a saved-index open loads them (else no `coloring` and
  the host runs set_coloring). *Rule changes* still use `set_coloring`, a
  separate pass (never re-indexes): the host defers it while indexing
  (`coloringStale`, run on "done") and reports its progress to the webview
  (`coloringProgress`: "Coloring… 40%" in the status bar). The selected row
  keeps the theme's selection colors. Defaults in package.json
  are checked against tshark by `test_default_coloring_rules_compile`; note
  tshark 4.2 rejects space-separated sets (`{3 4}`), so they avoid sets.
- **Export**: captures via `tshark [-Y f] -F pcapng|pcap -w tmp` (`-P -T
  fields -e frame.number` gives progress when filtering; without a filter
  nothing is dissected). Default filter = the current view's; `""` = all.
  CSV/JSON come from the row store in the view's current order (no tshark).
  Every export writes `.<name>.<pid>.part` and `replace()`s it at the end, and
  a destination that is the open capture is refused (tshark would truncate
  its input). CSV cells that look like formulas get a `'` prefix (packet text
  is untrusted); JSON is keyed by column id with numbers for numeric columns.
- **AI filter help** (`src/aiFilter.ts` pure, `src/ai.ts` host, `src/commands/ai.ts`):
  Copilot's inline completions can't reach the webview, so the host uses
  `vscode.lm.selectChatModels({ vendor: "copilot" })` (stable in 1.90 = our
  `engines.vscode`; 1.90 has no system role, so the instructions are the first
  user turn). The prompt holds only the request, the current filter, protocol
  names (`stats phs` column 0, cached per backend) and field names/types/
  descriptions (`field_index` prefix search on the request's keywords).
  **Never packet data.** The model answers JSON `[{filter, explanation}]` (the
  parser tolerates fences, prose and `{suggestions: [...]}`, max 3). Every filter
  goes through the backend's `validate_filter`; if none is valid, there is one
  retry that includes tshark's errors. Webview: ✨ puts the filter bar in "ask
  mode" (the input holds a description: no validation or completions; Enter
  asks, Esc cancels with `aiCancel`), and results reuse the suggestion dropdown
  (mode `ai`). Picking one fills the bar without applying it. The host posts
  `aiAvailable` after init and on `lm.onDidChangeChatModels` or setting changes.
  No model, consent denied (`LanguageModelError` NoPermissions/Blocked) or
  `pcapViewer.ai.enabled: false` hide the action. A failed or cancelled request
  only shows a short message; the action stays, since those are usually
  transient. `@pcap` (package.json `chatParticipants`) is registered only if
  `vscode.chat.createChatParticipant` exists, and answers with validated filters
  plus `pcapViewer.applyFilter` buttons.
- **Explaining packets** (`src/aiExplain.ts` pure, `FilterAssistant.explain` in
  `src/ai.ts`, `src/commands/ai.ts`): the one AI feature that **sends packet
  data**, so it is gated by `pcapViewer.ai.allowPacketData` (default false,
  `scope: application` so a workspace can't enable it) with a one-time modal
  consent (`PACKET_DATA_CONSENT`, which states the limits and is unit-tested
  against them) that saves the setting. The row menu's *Ask Copilot About This
  Packet…* / *…About N Selected Packets…* (shown only when `aiAvailable`) posts
  `askAboutPackets`; the host runs `workbench.action.chat.open` with
  `{query: "@pcap /explain 1-3 7"}` (`explainQuery`), falling back to a direct
  `vscode.lm` request streamed into an untitled Markdown editor when the chat
  API or command is missing or refuses. `/explain` (a `chatParticipants`
  command) parses leading frames/ranges then a question (`parseExplainArgs`);
  no frames = the selection. The backend supplies rows (`list_packets
  {frames, inView: false}`: displayed or not) and `packet_detail` trees. The
  prompt (`buildExplainPrompt`) holds the question, current filter, the row
  (column titles) and each tree as indented labels, capped by `EXPLAIN_LIMITS`
  (8 packets, 250 lines, depth 10, 160 chars/line, 48k chars overall: the tree
  budget halves until it fits). **No raw bytes by default**: field `value`s are
  never used, the hex dump only with `pcapViewer.ai.allowPacketBytes` (256
  bytes/packet), and byte dumps in labels (`isByteDump`: hex strings of ≥ 8
  bytes, payload fields) become "[N bytes not sent]". The prompt says the
  data is untrusted. The answer streams as Markdown; ```filter blocks
  (`extractFilters`) are validated with tshark and become *Apply filter*
  buttons, plus *Go to packet N* for each packet explained.
- **Navigation and customisation** (Wireshark-like; all over the *current view*,
  i.e. the filter and sort order, which only the backend knows in full):
  - *Find Packet* is backend `find_packet`. It turns the search into a display
    filter (`navigation.find_expression`: string → `frame contains "…"`, or
    case-insensitive `frame matches "(?i)<re-escaped>"`; hex →
    `frame contains aa:bb:cc`, a single byte as `"\xaa"`). The filter is
    validated, run once and cached in the filter LRU. Matches go into a
    one-byte-per-frame bitmap, then view order is walked from the selection,
    wrapping around. The `marked` mode walks the marks instead.
  - *Conversation stepping* is backend `neighbor_frame`: `tcp.stream`/
    `udp.stream` columns, extracted once into the row store, else the unordered
    Source/Destination pair. It reads cells in chunks along the view and
    doesn't wrap.
  - *Marks* live in the backend (`mark_packets`/`unmark_all`, per session,
    not persisted). Rows carry `marked`; the webview patches its cached pages
    instead of refetching. *Export marked* uses `export` with `marked: true`:
    `frame.number in {…}` with ranges compressed, split into chunks when the
    filter would exceed `MAX_FILTER_ARG` (16k characters, under Windows'
    32767-character command line), and the chunks joined with `mergecap -a`.
  - *Times* are formatted by the backend when `list_packets` gets `timeFormat`
    (and `timeRef`). Plain relative time uses the index pass's column; every
    other format uses `frame.time_epoch`, extracted once, parsed to integer ns.
    "Since previous displayed" is since the previous packet *of the filter* in
    capture order (bisect in `view.matched`), like Wireshark's
    `frame.time_delta_displayed` but for our filter (tshark's field only knows
    the unfiltered pass). It is a property of the packet, whatever the sort,
    which is what lets the Time column sort by it. There is one time reference; its row shows `*REF*` in every format. The format
    and reference are part of the webview's page cache key.
  - *Multi-selection* lives in the webview as a `Set` of frame numbers
    (`state.selection`, empty when one row is selected) plus the focused row
    (`selectedIndex`/`selectedFrame`, the detail pane). Click selects one row;
    Ctrl/Cmd+click toggles; Shift+click and Shift+arrows select from the
    anchor (the last plain or Ctrl click) and take frames for rows not loaded
    from `view_frames {offset, limit}`. Ctrl+A can't be a keybinding: VS Code's
    webview doesn't stop the key, so Chromium selects the page's text, and
    VS Code's Select All runs `execCommand("selectAll")` in the webview (found
    in real VS Code; a package.json binding didn't win). Both fire a cancelable
    `selectstart` on `<body>` (in an input the target is the input): the
    webview cancels it and selects the view via `view_frames` (deduplicated,
    since both can arrive). *PCAP: Select All Packets* has no key. Limits:
    `MAX_SELECTION` (1M frames) and 100k rows per copy. A new filter drops the
    selection; a new sort keeps it (same frames). Right-click inside the
    selection keeps it and the menu acts on all of it: mark (Ctrl+M: mark all
    unless all are marked), copy rows (TSV of the visible columns in view
    order: cached pages, else `view_frames {frames}` for the order then
    `list_packets {frames}` in chunks), copy frame numbers, *Export Selected
    Packets…* (`export` with `frames`, the same chunked `frame.number in {…}`
    path as marked packets; CSV/JSON can export the selected rows). Ctrl+C
    arrives as a `copy` event (VS Code runs `execCommand("copy")` in the
    webview). The host learns the selection from `selection {frame, frames}`.
  - *Frame links*: after a detail loads, the webview asks `field_types` (exact
    catalogue lookups) for the tree's field names once, and `FT_FRAMENUM`
    fields become links. The back/forward history covers jumps (links, go to,
    find, marks, conversation, first/last), not arrow keys.
  - *Keys*: the webview handles keys VS Code leaves to a focused webview
    (Ctrl+F, F3, Ctrl+Home/End, Esc). Keys VS Code binds globally even then
    (Ctrl+M, Ctrl+T, Ctrl+,, Ctrl+Shift+N/B, and Alt+Left, which is Back on
    Windows) are package.json keybindings scoped to the viewer
    (`… && !sideBarFocus && !panelFocus && !inputFocus`). They send a
    `command` message and the webview ignores the raw key, so nothing runs
    twice.
  - *Columns*: `pcapViewer.columnLayout` holds `{order, hidden}` by column id
    (`number`…`info`, `custom:<field>`), and `lib.layoutColumns` maps visible
    columns to cell indexes. `pcapViewer.columns` is now resource-scoped, so
    *Apply as Column*, rename and remove write for the capture's folder.
    `lib.cellFilter` builds cell filters (ip/ipv6/eth by address form; none for
    Time or Info). `lib.formatBytesAs` has the bytes-pane copy formats.
- **Protocol**: JSON-RPC 2.0 framing (`"jsonrpc": "2.0"`), LSP-style
  cancellation code -32800; app codes in `backend/pcap_backend/protocol.py`
  and mirrored in `src/backendClient.ts` (`ErrorCodes`; -32011 unsupported format,
  -32012 still indexing or still filtering). `open` returns the
  initial `filterId`; every `list_packets` result carries the current one so
  the webview drops stale pages.

## Performance notes (test/perf/bench.py, 1M synthetic packets, 146 MB)

With `-o tcp.analyze_sequence_numbers:FALSE`: open 29–36 s (first rows after
0.5 s with streaming, colored; +2 s with the 14 default coloring rules; reopening from the saved index 0.01 s, 104 MB), filter 26 s
(first matches after 0.5 s when streaming), page
fetch < 1 ms, sort 0.6 s, detail of last frame 20–26 s (quick view of any
frame 0.25–0.3 s with a 300-packet window), backend RSS 125 MB,
tshark 225 MB. With TCP analysis on, the synthetic file (512 replayed flows)
makes tshark super-linear (filter 165 s for 1M vs 4.5 s for 100k); real
captures are not expected to behave like that. Sorting streams one column from
the row store and sorts indices with a stable key list (no per-row tuples):
this took the backend from 710 MB to 125 MB peak.

## Status

Implemented: steps 1–7 of the brief (foundation, packet list with paging /
virtualization / sorting / custom columns, detail tree + hex with two-way
highlighting, display filters with validation, autocomplete, history, saved
filters, apply-as-filter, follow TCP/UDP/TLS/HTTP stream, and statistics
panels: conversations, endpoints, protocol hierarchy, IO graph, expert info,
capture properties).

Also step 6: Lua dissector commands (new from template, reload with error
check, open folder, reload offer on save) and a Decode As UI plus rule manager.

Step 7: coloring rules (defaults, Colorize with Filter, toggle), export
(pcapng/pcap, CSV/JSON packet list, packet bytes), CHANGELOG, packaging.

Beyond the brief: navigation and customisation, multi-select, AI help for
filters and explaining packets, a quick view for late packets in huge files,
streaming open and filters with saved indexes, and TLS decryption with a key log.
