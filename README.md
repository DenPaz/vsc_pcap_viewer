# PCAP Viewer for VS Code

Open `.pcap` / `.pcapng` captures directly in VS Code with a Wireshark-like
packet list, protocol tree and hex view. All dissection and filtering is done
by **tshark** (Wireshark's command-line tool), so results match Wireshark exactly.

> Status: v0.1, feature-complete against the project brief. Offline analysis only; live capture is out of scope.

## Features

- **Packet list** (No., Time, Source, Destination, Protocol, Length, Info) that
  stays smooth on captures with millions of packets: the webview renders only
  the visible rows and the backend pages through a cached index; scrolling
  never re-runs tshark.
- **Multi-select** like Wireshark: `Shift+click` or `Shift+arrow keys` select a
  range, `Ctrl+click` (`Cmd+click`) adds or removes a packet, `Ctrl+A` (`Cmd+A`) selects
  every displayed packet and `Esc` goes back to one. `Ctrl+M` marks the
  selection, `Ctrl+C` or the right-click menu copies its rows (visible
  columns, tab-separated) or frame numbers, and *Export Selected Packets…*
  saves it as pcapng or pcap.
- **Sorting** by any column (done in the backend). Addresses sort numerically
  (`8.8.8.8` before `10.0.0.1`; IPv4, then IPv6, then MAC addresses), and the
  Time column sorts by the time format shown (by the delta for "since
  previous packet"). **Custom columns** from
  any tshark field (`tcp.stream`, `http.host`, …) via `pcapViewer.columns` or
  *PCAP: Manage Custom Columns*.
- **Display filters** with Wireshark syntax, validated as you type (green/red),
  with inline error messages. Invalid filters are never applied.
- **Filter autocomplete** from tshark's own field list (including fields added
  by your Lua dissectors): field and protocol names with their type and
  description, then operators (`==`, `contains`, `&&`, …) after a field.
  `Tab` takes the first suggestion, `↑`/`↓` + `Enter` pick one, `Ctrl+Space` asks explicitly.
- **AI help for display filters** (optional, through VS Code's Language Model
  API and GitHub Copilot): click ✨ in the filter bar, describe the packets you
  want ("DNS queries that got no answer"), press Enter, and pick one of up to
  three suggestions. It goes into the filter bar; Enter applies it as usual.
  Every suggestion is checked with tshark first, and invalid ones are dropped.
  Also available as *PCAP: Suggest Display Filter…* and as `@pcap` in the chat
  view, with an *Apply* button. The ✨ action only appears when a model is
  available; see the privacy note below.
- **Saved and recent filters** in the filter bar's ★ menu (or `↓` on an empty
  filter bar). Saved filters live in the `pcapViewer.savedFilters` setting, so
  they can be personal (user settings) or shared with a project (workspace settings).
- **Packet details**: collapsible protocol tree and hex/ASCII pane with
  **two-way highlighting** (select a field to see its bytes; click a byte to
  find its field), including reassembled data (e.g. HTTP over several TCP segments).
- Tree context menu: *Apply as Filter*, *Prepare as Filter*, *…and/or/and not
  Selected*, *Colorize with Filter…*, *Apply as Column*, *Copy Value / Line / Field Name / as Filter / Bytes*.
- **Find Packet** (`Ctrl+F`): a find bar under the filter bar that searches by
  display filter, string (optionally case-sensitive) or hex bytes (`47 45 54`,
  `47:45:54` or `474554`). `Enter`/`F3` finds the next match and
  `Shift+Enter`/`Shift+F3` the previous one. The search covers the displayed
  packets in their current order and wraps around.
- **Frame links**: fields that reference another packet (*Request in frame*,
  *ACK of frame*, *Response in*…) are links in the detail tree. Click one or
  press `Enter` to jump; `Alt+Left`/`Alt+Right` go back and forward through the
  jumps. If the filter hides the packet, you're offered *Clear filter and go*.
- **Packet navigation**: next/previous packet in the same conversation (TCP or
  UDP stream, else the address pair), first/last packet.
- **Marks**: `Ctrl+M` marks the selected packets. Marked rows stand out over
  coloring rules. You can jump to the next or previous marked packet, unmark
  all, and *Export Marked Packets…* to pcapng or pcap. Marks last while the
  capture is open.
- **Time display formats**: seconds since the beginning (default), since the
  previous displayed packet (the previous packet of the filter, whatever the
  sort order), since the
  previous captured packet, local or UTC date and time, or epoch seconds.
  Click the time format in the status bar to change it. A **time reference**
  (`Ctrl+T`) makes relative times count from that packet, marked `*REF*`.
- **Column customisation**: right-click a header to hide or show any column,
  rename or remove custom columns, resize to contents or reset widths. Drag
  headers to reorder them. Order and visibility are saved in
  `pcapViewer.columnLayout`.
- **Cell menu**: right-click a packet-list cell for *Apply / Prepare as Filter*
  and *…and/or/and not Selected* on its value. Source and Destination use
  `ip`/`ipv6`/`eth` depending on the address, Protocol uses the protocol's
  filter name, Length uses `frame.len`, and custom columns use their field.
- **Bytes pane copy menu**: copy the packet's bytes, or the selected field's
  bytes, as a hex dump, hex stream, C array, escaped string, Base64 or
  printable text.
- **Coloring rules** like Wireshark's: the first matching rule colors a packet.
  A default set (bad TCP, checksum errors, TCP RST, ICMP errors, ARP, ICMP,
  SYN/FIN, HTTP, DNS, SMB, routing, TCP, UDP, broadcast) comes with the
  extension. Rules live in `pcapViewer.coloringRules`, so they can be edited,
  disabled (`"enabled": false`) or shared per workspace. *Colorize with Filter…*
  adds a rule on top, *PCAP: Toggle Packet Coloring* turns coloring off.
  Changing rules recolors open captures in the background without re-indexing.
- **Export**: *PCAP: Export Specified Packets…* writes the displayed packets,
  all packets or the selected packets to a new **pcapng** or **pcap** file.
  *PCAP: Export Packet List as CSV/JSON…* saves the displayed (or selected)
  rows (current filter and sort order, including custom columns). *PCAP: Export Packet
  Bytes…* (also in the packet list's right-click menu) saves a packet's raw
  bytes or its reassembled data. The follow-stream panel saves stream data.
  Exports appear only once complete, so cancelling leaves no partial file,
  and the open capture can never be overwritten.
- **Follow TCP / UDP / TLS / HTTP stream** from the selected packet (right-click
  a packet or use the command palette). The stream opens in a panel with the
  two directions coloured and labelled. You can show one direction only, switch
  between ASCII, hex dump and raw hex, step to other streams, filter the capture
  to the stream, and save it (raw bytes or the text shown).
- **Statistics**: Conversations and Endpoints (Ethernet, IPv4, IPv6, TCP, UDP),
  Protocol Hierarchy, I/O Graph (line chart plus table, adjustable interval),
  Expert Information and Capture File Properties. Each opens in a panel with
  sortable columns, CSV copy, and an option to limit it to the current display
  filter. Rows can apply or prepare a display filter, and expert rows jump to their packet.
- **Lua dissectors**: *PCAP: New Lua Dissector* scaffolds one in your
  dissectors folder. *PCAP: Reload Dissectors* checks the scripts first, so
  Lua errors appear immediately with a link to the line, then re-indexes open
  captures. Saving a loaded script offers a reload.
- **Decode As**: *PCAP: Decode As…* (also in the packet list's right-click menu)
  suggests the selected packet's ports, offers tshark's own lists of layers and
  protocols, and stores the rule in `pcapViewer.decodeAs`. *PCAP: Manage Decode
  As Rules* removes rules. Rules, Lua scripts and **preference overrides**
  (`-o`) apply to every tshark call.
- Progress and cancellation while indexing large files; clear errors when
  tshark or Python is missing; no orphaned processes after closing.

## Requirements

- **Wireshark / tshark** 4.x recommended (developed and tested with 4.2; older 3.x releases use different column field names, which the backend falls back to automatically). Install from
  [wireshark.org](https://www.wireshark.org/download.html) or your package
  manager (`apt install tshark`, `brew install wireshark`,
  `choco install wireshark`). tshark is found on `PATH` or in the default
  install locations; otherwise set `pcapViewer.tsharkPath`.
- **Python 3.14+** on `PATH` (`python3.14`, `python3`, `python`, or
  `py -3.14` / `py -3` on Windows), or set `pcapViewer.pythonPath`. The backend
  only uses the standard library, so no packages need to be installed.

## Usage

Open a capture file and it opens in the PCAP Viewer (use *Reopen Editor With…*
to switch). tshark recognises the format from the file's content, so what the
file is called only decides which editor VS Code offers:

| Opens in the viewer by default | |
|---|---|
| `*.pcap`, `*.pcapng`, `*.cap`, `*.ntar` | pcap / pcapng (`.ntar` is pcapng's old extension) |
| `*.pcap.gz`, `*.pcapng.gz`, `*.pcap.zst`, `*.pcapng.zst`, `*.pcap.lz4`, `*.pcapng.lz4` | compressed captures (gzip, Zstandard, LZ4), read directly |
| `*.pcap0`, `*.pcap1`, … (`*.pcap[0-9]*`) | files rotated by `tcpdump -C` |
| `*.snoop`, `*.erf` | Sun snoop, Endace ERF |
| `*.pklg`, `*.btsnoop` | Bluetooth HCI logs (macOS PacketLogger, Android/Symbian btsnoop) |

| Offered in *Reopen Editor With…* only | |
|---|---|
| `*.[0-9]` (`capture.1`), `*.log`, `*.dmp`, `*.trc`, `*.ber` | generic extensions that are sometimes captures (the viewer never takes these over from other editors) |

Other formats Wireshark reads work as well when the file has one of these names
(for example a Microsoft Network Monitor capture saved as `.cap`, or a Sniffer
`.trc`). A file tshark doesn't recognise
shows "*name* is not a capture file that tshark can read" in the viewer, with a
button to reopen it in another editor. Reading zstd and LZ4 files needs a
tshark built with them (`tshark --version` lists "with Zstandard", "with LZ4").

| Command | Default key | Description |
|---|---|---|
| PCAP: Apply Display Filter | `Ctrl+/` (`Cmd+/`) | Prompt for a filter (validated) and apply it |
| PCAP: Clear Display Filter | | |
| PCAP: Save Display Filter… | | Save the current filter under a name |
| PCAP: Suggest Display Filter… | | Describe the packets; pick an AI-suggested, tshark-checked filter (also ✨ in the filter bar and `@pcap` in chat) |
| PCAP: Saved Display Filters | | Apply or delete saved filters |
| PCAP: Go to Packet | `Ctrl+G` (`Cmd+G`) | Jump to a frame number |
| PCAP: Find Packet… / Find Next / Find Previous | `Ctrl+F`, `F3`, `Shift+F3` | Find by display filter, string or hex bytes |
| PCAP: Go Back / Go Forward (Packet History) | `Alt+Left`, `Alt+Right` | Walk back and forth over jumps (links, go to, find…) |
| PCAP: Next / Previous Packet in Conversation | `Ctrl+.`, `Ctrl+,` | Same TCP/UDP stream, else the same address pair |
| PCAP: First Packet / Last Packet | `Ctrl+Home`, `Ctrl+End` | |
| PCAP: Select All Packets | `Ctrl+A` (`Cmd+A`) in the packet list | Select every displayed packet |
| PCAP: Mark/Unmark Selected Packets | `Ctrl+M` | Mark the selected packets (unmark them if all are marked) |
| PCAP: Next / Previous Marked Packet | `Ctrl+Shift+N`, `Ctrl+Shift+B` | |
| PCAP: Unmark All Packets / Export Marked Packets… | | Clear the marks / save the marked packets as pcapng or pcap |
| PCAP: Set/Unset Time Reference | `Ctrl+T` | Relative times count from the selected packet |
| PCAP: Time Display Format… | | Choose how the Time column is shown |
| PCAP: Follow TCP / UDP / TLS / HTTP Stream | | Follow the selected packet's stream (also in the packet list's right-click menu) |
| PCAP Statistics: Conversations, Endpoints, Protocol Hierarchy, I/O Graph, Expert Information, Capture File Properties | | Open the report in a panel beside the capture |
| PCAP: Manage Custom Columns | | Add or remove columns (searches tshark's field list) |
| PCAP: Reload Capture | | Re-run tshark on the current capture |
| PCAP: Reload Dissectors | | Check the Lua dissectors for errors, then re-index all open captures |
| PCAP: New Lua Dissector… | | Create a dissector from a template in the dissectors folder |
| PCAP: Open Dissectors Folder | | Reveal (or set up) `pcapViewer.dissectorsFolder` |
| PCAP: Decode As… / Manage Decode As Rules | | Add or remove `-d` rules (stored in settings) |
| PCAP: Export Specified Packets… | | Displayed / all / selected packets to pcapng or pcap |
| PCAP: Export Selected Packets… | | The selected packets to pcapng or pcap |
| PCAP: Export Packet List as CSV/JSON… | | The displayed (or selected) rows with their columns |
| PCAP: Export Packet Bytes… | | Raw bytes of the selected packet (or a reassembled source) |
| PCAP: Colorize with Filter… | | Add a coloring rule (also in the detail tree's right-click menu) |
| PCAP: Toggle Packet Coloring / Manage Coloring Rules | | Turn coloring on or off / edit `pcapViewer.coloringRules` |
| PCAP: Show Log | | Backend and tshark messages (Lua errors, warnings) |

Keyboard: in the list use ↑/↓/PgUp/PgDn/Home/End, `Enter`/`→` to move to the
tree; in the tree use arrows to navigate and expand/collapse (`Enter` on a frame
link jumps to that packet); `Esc` in the filter bar restores the applied filter
and in the find bar closes it. On macOS use `Cmd` instead of `Ctrl`. The viewer
shortcuts only apply while a capture is the active editor and focus isn't in
the side bar or panel.

## Settings

| Setting | Description |
|---|---|
| `pcapViewer.tsharkPath` | Path to `tshark` (empty: auto-detect) |
| `pcapViewer.pythonPath` | Python 3.14+ interpreter (empty: auto-detect) |
| `pcapViewer.luaScripts` | Lua dissectors, passed as `-X lua_script:<path>` |
| `pcapViewer.dissectorsFolder` | Folder whose `*.lua` files are also loaded |
| `pcapViewer.decodeAs` | Decode As rules, e.g. `"tcp.port==8080,http"` |
| `pcapViewer.prefs` | Preference overrides, e.g. `{ "tcp.desegment_tcp_streams": false }` |
| `pcapViewer.columns` | Extra columns: `"tcp.stream"` or `{ "field": "http.host", "title": "Host" }` (per workspace folder) |
| `pcapViewer.columnLayout` | Column order and hidden columns by id, e.g. `{ "order": ["protocol", "number"], "hidden": ["time"] }` (set by the header menu and dragging) |
| `pcapViewer.timeFormat` | Time column: `relative` (default), `delta_displayed`, `delta_captured`, `absolute`, `utc` or `epoch` |
| `pcapViewer.savedFilters` | Named filters: `{ "name": "Web", "filter": "http \|\| tls" }` |
| `pcapViewer.coloringRules` | Coloring rules, first match wins: `{ "name": "DNS", "filter": "dns", "foreground": "#12272e", "background": "#c8e2ff" }` |
| `pcapViewer.colorize` | Color the packet list (default `true`) |
| `pcapViewer.ai.enabled` | Offer AI help for display filters when a language model is available (default `true`) |
| `pcapViewer.maxCachedFrames` | Backend cache budget for filter results / sort orders |
| `pcapViewer.requestTimeoutSeconds` | Timeout for quick requests (long ones are cancellable instead) |

A Lua dissector template is available as the `dissector` snippet in Lua files;
see `backend/dissectors/example.lua` for a complete example. Note that tshark
disables Lua when run as root/administrator.

## How it works

```
Webview (HTML/JS)  --postMessage-->  Extension host (TypeScript)
                                       |  newline-delimited JSON-RPC over stdio
                                       v
                                    Python backend (python -m pcap_backend)
                                       |  argv-only subprocess calls
                                       v
                                    tshark / capinfos
```

- Opening a file runs one `tshark -T fields` pass and stores the list columns
  in a temporary file with an in-memory offset index (8 bytes per packet).
- Applying a filter runs `tshark -Y <filter> -T fields -e frame.number` once
  and caches the matching frame numbers (4 bytes per match).
- Selecting a packet runs `tshark -c N -Y frame.number==N -T pdml` (and `-x`
  for the bytes), so tshark stops reading after that packet.
- Coloring runs one `tshark --color` pass in the background and keeps one
  byte per packet (the matching rule). tshark reads coloring rules only from
  its configuration folder, so the pass points `WIRESHARK_CONFIG_DIR` at a
  temporary folder with the generated rules and copies of your other
  Wireshark settings.
- Exporting packets runs `tshark -Y <filter> -w <file>`; the packet list and
  packet bytes are written from the backend's own index and detail cache.

### Performance

Measured with `test/perf/bench.py` on 1,000,000 synthetic packets (146 MB,
4-core Linux VM, tshark 4.2, `tcp.analyze_sequence_numbers` off):

| Operation | Time |
|---|---|
| Open (index pass) | 36 s (tshark-bound; progress shown, cancellable) |
| Fetch a 200-row page (any position) | < 1 ms |
| 1000 random scroll pages | 0.09 s total |
| Apply a filter | 26 s (one tshark pass; re-applying a cached filter is instant) |
| Sort 1M rows by Length | 0.6 s |
| Detail of frame 10 / frame 1,000,000 | 0.2 s / 26 s |
| Peak memory: backend / tshark | 125 MB / 225 MB |

Almost all of the time is tshark's own dissection. Wireshark preferences that
make dissection cheaper can be set through `pcapViewer.prefs`, for example
`{ "tcp.analyze_sequence_numbers": false }` (the synthetic benchmark capture
replays the same flows, which makes this analysis 6x slower: 165 s instead of 26 s
for the filter). Opening a packet near the end of a huge capture re-reads the
file up to that packet so reassembly stays correct (see the roadmap below).

## Roadmap

Every item of the project brief is implemented. Possible next steps: a faster
"quick view" of late packets in huge captures (without reassembly context),
exporting full dissections (PDML/JSON), and a visual editor for coloring rules.

## Running locally (Linux)

These steps take a fresh Linux machine to a running development copy of the
extension. Commands are shown for Ubuntu/Debian, with Fedora and Arch
equivalents where they differ. macOS and Windows work the same way once the
tools below are installed.

### 1. Install the tools

| Tool | Why | Install |
|---|---|---|
| Git, VS Code ≥ 1.90 | source and editor | `sudo apt install git`, VS Code from [code.visualstudio.com](https://code.visualstudio.com/) (`.deb`/`.rpm`, Snap or Flatpak) |
| tshark | dissection and filtering | `sudo apt install tshark` · Fedora: `sudo dnf install wireshark-cli` · Arch: `sudo pacman -S wireshark-cli` |
| uv | Python toolchain; installs Python 3.14 | `curl -LsSf https://astral.sh/uv/install.sh \| sh` |
| Python 3.14 | runs the backend | `uv python install 3.14` (puts `python3.14` in `~/.local/bin`) |
| Node.js 22.13+ | builds the extension (vsce 4, eslint 10 and @vscode/test-electron 3 need Node 22) | [nvm](https://github.com/nvm-sh/nvm): `nvm install 22`, or your distro/NodeSource package |
| pnpm | JavaScript package manager | `corepack enable pnpm` (or `npm install -g pnpm`); the version is pinned in `package.json` |

Notes:

- When `apt install tshark` asks whether non-superusers should be able to
  capture packets, either answer works: the viewer only reads files and never captures.
- Make sure `~/.local/bin` is on your `PATH` (the uv installer offers to add
  it). Otherwise VS Code won't find `python3.14`; see Troubleshooting below.
- Don't run VS Code as root: tshark refuses to load Lua dissectors for root.

Check the installs:

```sh
tshark --version | head -1     # TShark (Wireshark) 4.x
python3.14 --version           # Python 3.14.x
node --version && pnpm --version
```

### 2. Get the code and install dependencies

```sh
git clone https://github.com/DenPaz/vsc_pcap_viewer.git
cd vsc_pcap_viewer
uv sync               # .venv with Python 3.14 + dev tools (pytest, pytest-bdd, ruff, mypy, scapy)
pnpm install          # TypeScript toolchain, ESLint, mocha, vsce, Playwright
pnpm run compile      # build the extension into out/
```

The `Makefile` wraps these and the other tasks below (`make` lists them):

| Command | Does |
|---|---|
| `make install` | `uv sync` and `pnpm install` |
| `make update` | Upgrade all dev dependencies: `ncu -u` (within the limits in `.ncurc.cjs`), `pnpm install`, `uv lock --upgrade`, `uv sync` |
| `make outdated` | Show available updates without changing anything |
| `make compile` / `make watch` | Build the extension once / on every change |
| `make lint` / `make format` | All linters / auto-fix what they can |
| `make test` | Backend tests plus TS unit and webview tests (`make test-backend`, `make test-acceptance`, `make test-unit` for parts) |
| `make test-extension` | VS Code smoke test (uses `xvfb-run` automatically when there's no display) |
| `make check` | `lint` + `test`: what CI runs, except the smoke test |
| `make fixtures` / `make perf` | Regenerate the test captures / benchmark the 1M-packet capture |
| `make package` / `make clean` | Build the `.vsix` / remove build output and caches |

### 3. Run the extension

**From source (for development).** Open the folder in VS Code with
`code .` and press `F5` (the "Run Extension" launch configuration). A second
VS Code window, the *Extension Development Host*, opens with
`test/fixtures/` loaded. Open `http.pcap` or `mixed.pcapng` there to see the
viewer. `pnpm run watch` rebuilds TypeScript on save; reload the host window
with `Ctrl+R` to pick up changes. Webview files (`src/webview/`) need no build step.

**As an installed extension.** Build a `.vsix` and install it into your normal VS Code:

```sh
pnpm run package
code --install-extension pcap-viewer-0.1.0.vsix
```

Then open any `.pcap`/`.pcapng` file. Backend and tshark messages are shown in
*PCAP: Show Log* (the "PCAP Viewer" output channel).

### 4. Run the tests and checks

```sh
uv run pytest                  # backend tests + Gherkin acceptance scenarios (skip without tshark)
pnpm run test:unit             # extension unit tests + webview tests
pnpm run lint && uv run ruff check && uv run ruff format --check && uv run mypy
```

- The webview end-to-end test drives the real UI in headless Chromium. If
  it reports no Chromium, install one with
  `pnpm exec playwright-core install --with-deps chromium`.
- The VS Code smoke test downloads VS Code and needs a display. On a desktop
  run `pnpm run test:extension`. On a headless machine or over SSH, install
  Xvfb (`sudo apt install xvfb`) and run `xvfb-run -a pnpm run test:extension`.
- The acceptance criteria are written as Gherkin scenarios in
  `test/backend/acceptance/features/`, run by pytest-bdd.

### 5. Sample and large captures

`test/fixtures/` has small captures (HTTP, DNS, TLS, a custom UDP protocol
for `backend/dissectors/example.lua`, and a truncated file). To regenerate them,
or to make a big capture for performance testing:

```sh
uv run python test/fixtures/generate.py
uv run python test/fixtures/generate.py --large 1000000 test/fixtures/large-1m.pcap
uv run python -u test/perf/bench.py test/fixtures/large-1m.pcap --no-tcp-analysis
```

### Troubleshooting

| Symptom | Fix |
|---|---|
| "No Python 3.14+ interpreter found" | VS Code doesn't see `~/.local/bin`. Set `pcapViewer.pythonPath` to the output of `uv python find 3.14`, or start VS Code from a terminal where `python3.14` works. |
| "tshark was not found" | Install tshark (step 1) or set `pcapViewer.tsharkPath`, e.g. `/usr/bin/tshark`. |
| `tshark: You don't have permission to read the file "…"` although the file is yours | On Ubuntu with tshark 4.6, the AppArmor profile `/etc/apparmor.d/tshark` only lets tshark use `/tmp` and Wireshark's own folders. Allow your files with a local rule: `echo 'owner @{HOME}/** rw,' \| sudo tee -a /etc/apparmor.d/local/tshark` then `sudo apparmor_parser -r /etc/apparmor.d/tshark` (add e.g. `owner /media/** rw,` for other places). Check with `sudo aa-status \| grep tshark`; denials show in `journalctl -k \| grep 'profile="tshark"'`. A Snap-packaged tshark has similar limits: use the distribution's package instead. |
| Cancelling a filter is slow, *PCAP: Show Log* says "could not stop tshark … Permission denied", or the kernel log shows `apparmor="DENIED" operation="signal" profile="tshark" … peer="vscode"` | The same AppArmor profile doesn't let tshark receive signals from the extension (VS Code runs under its own `vscode` profile; the tests run unconfined). The backend then closes tshark's output instead, so tshark stops at its next write, but a pass that writes nothing runs to its end. Allow the signals with two more local rules and reload: `printf '%s\n' 'signal (receive) peer=unconfined,' 'signal (receive) peer=vscode,' \| sudo tee -a /etc/apparmor.d/local/tshark` then `sudo apparmor_parser -r /etc/apparmor.d/tshark`. |
| Lua dissector isn't applied | Check *PCAP: Show Log* for Lua errors. Don't run as root. Use *PCAP: Reload Capture* after editing the script. |
| Opening a huge file is slow | Indexing speed is tshark's. Settings such as `"pcapViewer.prefs": { "tcp.analyze_sequence_numbers": false }` make it cheaper. |
| `pnpm install` fails with "Ignored build scripts" | Use the pnpm version pinned in `package.json` (`corepack enable pnpm`). The build-script policy is in `pnpm-workspace.yaml`. |

See `CLAUDE.md` for architecture notes and design decisions.

## Security

- tshark and Python are always started with argument arrays, never through a shell.
- Packet contents are untrusted: the webview inserts them only as text (never
  `innerHTML`) and runs under a strict Content-Security-Policy with a per-load nonce.
- The webview can only call a fixed allow-list of backend methods.
- **AI help sends no packet data.** A request to the language model contains
  only your description, the current display filter, the names of the
  protocols in the capture (from the protocol hierarchy) and the names,
  types and descriptions of Wireshark fields that match words of your
  request. Addresses, payloads and other packet contents are never sent.
  Requests go through VS Code's Language Model API, so VS Code asks for your
  consent first, and your Copilot plan and policies apply. Turn it off with
  `"pcapViewer.ai.enabled": false`.
- CSV exports prefix cells that a spreadsheet would run as a formula (`=`,
  `+`, `@`, `-`…) with `'`, since packet text is attacker-controlled.

## License and Wireshark

This extension is MIT licensed. **tshark is part of Wireshark, which is
licensed under the GNU GPL v2.** The extension does not bundle, link to or
modify Wireshark; it runs a tshark you installed yourself as a separate
process and reads its output.
