# PCAP Viewer for VS Code

Open `.pcap` / `.pcapng` captures directly in VS Code with a Wireshark-like
packet list, protocol tree and hex view. All dissection and filtering is done
by **tshark** (Wireshark's command-line tool), so results match Wireshark exactly.

> Status: early development (v0.1). Offline analysis only; live capture is out of scope.

## Features

- **Packet list** (No., Time, Source, Destination, Protocol, Length, Info) that
  stays smooth on captures with millions of packets: the webview renders only
  the visible rows and the backend pages through a cached index; scrolling
  never re-runs tshark.
- **Sorting** by any column (done in the backend) and **custom columns** from
  any tshark field (`tcp.stream`, `http.host`, …) via `pcapViewer.columns` or
  *PCAP: Manage Custom Columns*.
- **Display filters** with Wireshark syntax, validated as you type (green/red),
  inline error messages, and a history dropdown. Invalid filters are never applied.
- **Packet details**: collapsible protocol tree and hex/ASCII pane with
  **two-way highlighting** (select a field to see its bytes; click a byte to
  find its field), including reassembled data (e.g. HTTP over several TCP segments).
- Tree context menu: *Apply as Filter*, *Prepare as Filter*, *…and/or/and not
  Selected*, *Copy Value / Line / Field Name / as Filter / Bytes*.
- **Lua dissectors**, **Decode As** (`-d`) rules and **preference overrides**
  (`-o`) from settings, applied to every tshark call.
- Progress and cancellation while indexing large files; clear errors when
  tshark or Python is missing; no orphaned processes after closing.

## Requirements

- **Wireshark / tshark** 4.x recommended (developed and tested with 4.2; older 3.x releases use different column field names, which the backend falls back to automatically). Install from
  [wireshark.org](https://www.wireshark.org/download.html) or your package
  manager (`apt install tshark`, `brew install wireshark`,
  `choco install wireshark`). tshark is found on `PATH` or in the default
  install locations; otherwise set `pcapViewer.tsharkPath`.
- **Python 3.10+** on `PATH` (`python3`, `python` or `py -3`), or set
  `pcapViewer.pythonPath`. The backend only uses the standard library, so no
  packages need to be installed.

## Usage

Open any `.pcap`, `.pcapng` or `.cap` file. It opens in the PCAP Viewer by default
(use *Reopen Editor With…* to switch).

| Command | Default key | Description |
|---|---|---|
| PCAP: Apply Display Filter | `Ctrl+/` (`Cmd+/`) | Prompt for a filter (validated) and apply it |
| PCAP: Clear Display Filter | | |
| PCAP: Go to Packet | `Ctrl+G` (`Cmd+G`) | Jump to a frame number |
| PCAP: Manage Custom Columns | | Add or remove columns (searches tshark's field list) |
| PCAP: Reload Capture | | Re-run tshark, e.g. after editing a Lua dissector |
| PCAP: Show Log | | Backend and tshark messages (Lua errors, warnings) |

Keyboard: in the list use ↑/↓/PgUp/PgDn/Home/End, `Enter`/`→` to move to the
tree; in the tree use arrows to navigate and expand/collapse; `Esc` in the
filter bar restores the applied filter.

## Settings

| Setting | Description |
|---|---|
| `pcapViewer.tsharkPath` | Path to `tshark` (empty: auto-detect) |
| `pcapViewer.pythonPath` | Python 3.10+ interpreter (empty: auto-detect) |
| `pcapViewer.luaScripts` | Lua dissectors, passed as `-X lua_script:<path>` |
| `pcapViewer.dissectorsFolder` | Folder whose `*.lua` files are also loaded |
| `pcapViewer.decodeAs` | Decode As rules, e.g. `"tcp.port==8080,http"` |
| `pcapViewer.prefs` | Preference overrides, e.g. `{ "tcp.desegment_tcp_streams": false }` |
| `pcapViewer.columns` | Extra columns: `"tcp.stream"` or `{ "field": "http.host", "title": "Host" }` |
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

Performance (1M synthetic packets, 146 MB, 4-core Linux VM, tshark 4.2): see
`test/perf/bench.py` and the numbers recorded in the CLAUDE.md / PR notes.
Indexing time is dominated by tshark's own dissection speed.

## Development

```sh
uv sync            # Python dev tools (pytest, ruff, mypy, scapy) in .venv
npm install        # TypeScript toolchain
npm run compile    # build the extension
uv run pytest      # backend tests (tshark-dependent tests skip without tshark)
npm run test:unit  # extension unit tests + webview tests (incl. headless Chromium)
npm run test:extension   # VS Code smoke test (xvfb-run -a on headless Linux)
```

Press `F5` in VS Code ("Run Extension") to launch a development host with the
`test/fixtures` folder open. See `CLAUDE.md` for architecture notes and design decisions.

## Security

- tshark and Python are always started with argument arrays, never through a shell.
- Packet contents are untrusted: the webview inserts them only as text (never
  `innerHTML`) and runs under a strict Content-Security-Policy with a per-load nonce.
- The webview can only call a fixed allow-list of backend methods.

## License and Wireshark

This extension is MIT licensed. **tshark is part of Wireshark, which is
licensed under the GNU GPL v2.** The extension does not bundle, link to or
modify Wireshark; it runs a tshark you installed yourself as a separate
process and reads its output.
