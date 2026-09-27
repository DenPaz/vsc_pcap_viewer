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
  columns, tab-separated) or frame numbers, and _Export Selected Packets…_
  saves it as pcapng or pcap.
- **Sorting** by any column (done in the backend). Addresses sort numerically
  (`8.8.8.8` before `10.0.0.1`; IPv4, then IPv6, then MAC addresses), and the
  Time column sorts by the time format shown (by the delta for "since
  previous packet"). **Custom columns** from
  any tshark field (`tcp.stream`, `http.host`, …) via `pcapViewer.columns` or
  _PCAP: Manage Custom Columns_.
- **Display filters** with Wireshark syntax, validated as you type (green/red),
  with inline error messages. Invalid filters are never applied. On big
  captures the matches show as tshark finds them ("Filtering… 12,000 matches
  so far (40%)"): scroll and open packets meanwhile, or press ■ to stop and
  keep the matches found so far. A sort chosen meanwhile applies when the
  filter is done. Finished filter results are cached, also with the saved
  index, so reapplying a recent filter after reopening a capture is instant.
- **TLS decryption** with a key log file: _PCAP: Set TLS Key Log File…_ picks
  the file your browser or curl writes when `SSLKEYLOGFILE` is set
  (`pcapViewer.tlsKeyLogFile`). The capture reloads with HTTP, HTTP/2 and
  QUIC traffic decrypted, and when the browser adds keys to the file, the
  viewer offers to reload so newer sessions are decrypted too.
- **Filter autocomplete** from tshark's own field list (including fields added
  by your Lua dissectors): field and protocol names with their type and
  description, then operators (`==`, `contains`, `&&`, …) after a field.
  `Tab` takes the first suggestion, `↑`/`↓` + `Enter` pick one, `Ctrl+Space` asks explicitly.
- **AI help for display filters** (optional, through VS Code's Language Model
  API and GitHub Copilot): click ✨ in the filter bar, describe the packets you
  want ("DNS queries that got no answer"), press Enter, and pick one of up to
  three suggestions. It goes into the filter bar; Enter applies it as usual.
  Every suggestion is checked with tshark first, and invalid ones are dropped.
  Also available as _PCAP: Suggest Display Filter…_ and as `@pcap` in the chat
  view, with an _Apply_ button. The ✨ action only appears when a model is
  available; see the privacy note below.
- **Ask Copilot about packets** (optional, off until you allow it): right-click
  a packet for _Ask Copilot About This Packet…_ (or _…About N Selected
  Packets…_). It opens the chat view with `@pcap /explain 12 15-17`; you can
  also type that yourself and add a question (`@pcap /explain 12 why the
reset?`). The answer streams in with _Go to packet_ buttons and _Apply
  filter_ buttons for the display filters it suggests (checked with tshark).
  Without the chat view, the answer opens in a Markdown editor instead. This
  **sends packet data**, so the first time you are asked, and your choice is
  saved in `pcapViewer.ai.allowPacketData`; see the privacy note below.
- **Saved and recent filters** in the filter bar's ★ menu (or `↓` on an empty
  filter bar). Saved filters live in the `pcapViewer.savedFilters` setting, so
  they can be personal (user settings) or shared with a project (workspace settings).
- **Packet details**: collapsible protocol tree and hex/ASCII pane with
  **two-way highlighting** (select a field to see its bytes; click a byte to
  find its field), including reassembled data (e.g. HTTP over several TCP segments).
- **Fast opening of big captures**: the first packets show within about half a
  second while tshark indexes the rest; the status bar counts along
  ("Indexing… 250,000 packets so far"). A filter you apply meanwhile starts
  at once and shows its matches among the packets indexed so far; sorting
  needs every packet, so it says it is waiting. The finished index is saved, so **reopening an unchanged
  capture is instant** (0.01 s instead of ~30 s per million packets). It is
  rebuilt when the file or anything that changes dissection changes (tshark
  version, Lua scripts, Decode As rules, preferences, the TLS key log file's
  contents, custom columns, your Wireshark configuration). Saved indexes take about 100 MB per million
  packets, are capped at 1 GB (`pcapViewer.indexCache.maxSizeMB`, least
  recently opened first) and hold the packet list's text; turn them off with
  `pcapViewer.indexCache.enabled` or delete them with _PCAP: Clear Index Cache_.
- **Quick view of late packets**: a packet's exact details come from dissecting
  the capture up to it, which takes long near the end of a big capture (20 s at
  packet 1,000,000). From packet 20,000 on (`pcapViewer.quickDetail.after`), a
  quick view shows first: only the 300 packets before it are dissected
  (`pcapViewer.quickDetail.window`), in about 0.3 s anywhere in the file. It is
  marked _Quick view_ because reassembly, TCP analysis and "Request in frame"
  links that depend on earlier packets can be missing; the exact view replaces
  it when ready, keeping the expanded nodes and the selected field. Recently
  viewed packets are cached, so going back is instant.
- Tree context menu: _Apply as Filter_, _Prepare as Filter_, _…and/or/and not
  Selected_, _Colorize with Filter…_, _Apply as Column_, _Copy Value / Line / Field Name / as Filter / Bytes_.
- **Find Packet** (`Ctrl+F`): a find bar under the filter bar that searches by
  display filter, string (optionally case-sensitive) or hex bytes (`47 45 54`,
  `47:45:54` or `474554`). `Enter`/`F3` finds the next match and
  `Shift+Enter`/`Shift+F3` the previous one. The search covers the displayed
  packets in their current order and wraps around.
- **Frame links**: fields that reference another packet (_Request in frame_,
  _ACK of frame_, _Response in_…) are links in the detail tree. Click one or
  press `Enter` to jump; `Alt+Left`/`Alt+Right` go back and forward through the
  jumps. If the filter hides the packet, you're offered _Clear filter and go_.
- **Packet navigation**: next/previous packet in the same conversation (TCP or
  UDP stream, else the address pair), first/last packet.
- **Marks**: `Ctrl+M` marks the selected packets. Marked rows stand out over
  coloring rules. You can jump to the next or previous marked packet, unmark
  all, and _Export Marked Packets…_ to pcapng or pcap. Marks last while the
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
- **Cell menu**: right-click a packet-list cell for _Apply / Prepare as Filter_
  and _…and/or/and not Selected_ on its value. Source and Destination use
  `ip`/`ipv6`/`eth` depending on the address, Protocol uses the protocol's
  filter name, Length uses `frame.len`, and custom columns use their field.
- **Bytes pane copy menu**: copy the packet's bytes, or the selected field's
  bytes, as a hex dump, hex stream, C array, escaped string, Base64 or
  printable text.
- **Coloring rules** like Wireshark's: the first matching rule colors a packet.
  A default set (bad TCP, checksum errors, TCP RST, ICMP errors, ARP, ICMP,
  SYN/FIN, HTTP, DNS, SMB, routing, TCP, UDP, broadcast) comes with the
  extension. Rules live in `pcapViewer.coloringRules`, so they can be edited,
  disabled (`"enabled": false`) or shared per workspace. _Colorize with Filter…_
  adds a rule on top, _PCAP: Toggle Packet Coloring_ turns coloring off, and
  _PCAP: Edit Coloring Rules_ opens an editor: reorder rules (the first match
  wins), turn them on and off, pick colors with a preview, and see filters
  checked by tshark as you type.
  Colors come with the packets: opening a capture evaluates the rules in the
  same tshark pass that builds the packet list (about 6% slower than without
  colors), so even a big capture shows colored rows within half a second, and
  the colors are saved with the capture's index. Changing rules recolors open
  captures in the background without re-indexing ("Coloring… 40%" in the
  status bar).
- **Export**: _PCAP: Export Specified Packets…_ writes the displayed packets,
  all packets or the selected packets to a new **pcapng** or **pcap** file.
  _PCAP: Export Packet List as CSV/JSON…_ saves the displayed (or selected)
  rows (current filter and sort order, including custom columns). _PCAP: Export Packet
  Bytes…_ (also in the packet list's right-click menu) saves a packet's raw
  bytes or its reassembled data. _PCAP: Export Packet Dissections…_ saves the
  full packet details of the displayed, all, selected or marked packets as
  plain text, **PDML** or **JSON** (optionally with each packet's bytes), like
  Wireshark's _Export Packet Dissections_. The follow-stream panel saves
  stream data. Exports appear only once complete, so cancelling leaves no
  partial file, and the open capture can never be overwritten.
- **Export Objects**: _PCAP: Export Objects…_ lists the files the capture
  carried over HTTP, SMB, TFTP, IMF (mail), DICOM and FTP-DATA, with the
  packet that carried each one, its host, content type and size. Filter by
  protocol or text, sort, double-click to go to the packet, and save one
  object or all those shown. tshark extracts them (`--export-objects`, one
  pass over the capture, then kept for the session); HTTP bodies are saved
  decoded (chunked, gzip). Saved names are made safe and never overwrite an
  existing file.
- **Name resolution**: show names instead of addresses and port numbers, like
  Wireshark's _View › Name Resolution_: MAC vendor and well-known names (on by
  default), host names for IP addresses from the capture's own DNS answers,
  the system's hosts file and a `hosts` file in Wireshark's personal
  configuration folder, and service names for ports. Nothing is looked up on
  the network unless you allow it (user settings only). Choose with
  _PCAP: Name Resolution…_ or the _Names_ link in the status bar; the capture
  is re-indexed (switching back is instant thanks to the saved index). A
  resolved name shows its address as a tooltip, cell filters use the address,
  and statistics always show addresses.
- **Merge captures**: opening one piece of a rotated capture (`tcpdump -C`'s
  `trace.pcap`, `trace.pcap1`, …, or a Wireshark/dumpcap ring buffer's
  `name_00001_<time>.pcapng`, …) offers to merge all the pieces into one
  capture and open it. _PCAP: Merge Captures…_ does the same, or merges any
  capture files you choose by timestamp (with `mergecap`).
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
- **Lua dissectors**: _PCAP: New Lua Dissector_ scaffolds one in your
  dissectors folder. _PCAP: Reload Dissectors_ checks the scripts first, so
  Lua errors appear immediately with a link to the line, then re-indexes open
  captures. Saving a loaded script offers a reload.
- **Decode As**: _PCAP: Decode As…_ (also in the packet list's right-click menu)
  suggests the selected packet's ports, offers tshark's own lists of layers and
  protocols, and stores the rule in `pcapViewer.decodeAs`. _PCAP: Manage Decode
  As Rules_ removes rules. Rules, Lua scripts and **preference overrides**
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

Open a capture file and it opens in the PCAP Viewer (use _Reopen Editor With…_
to switch). tshark recognises the format from the file's content, so what the
file is called only decides which editor VS Code offers:

| Opens in the viewer by default                                                         |                                                                  |
| -------------------------------------------------------------------------------------- | ---------------------------------------------------------------- |
| `*.pcap`, `*.pcapng`, `*.cap`, `*.ntar`                                                | pcap / pcapng (`.ntar` is pcapng's old extension)                |
| `*.pcap.gz`, `*.pcapng.gz`, `*.pcap.zst`, `*.pcapng.zst`, `*.pcap.lz4`, `*.pcapng.lz4` | compressed captures (gzip, Zstandard, LZ4), read directly        |
| `*.pcap0`, `*.pcap1`, … (`*.pcap[0-9]*`)                                               | files rotated by `tcpdump -C`                                    |
| `*.snoop`, `*.erf`                                                                     | Sun snoop, Endace ERF                                            |
| `*.pklg`, `*.btsnoop`                                                                  | Bluetooth HCI logs (macOS PacketLogger, Android/Symbian btsnoop) |

| Offered in _Reopen Editor With…_ only                       |                                                                                                       |
| ----------------------------------------------------------- | ----------------------------------------------------------------------------------------------------- |
| `*.[0-9]` (`capture.1`), `*.log`, `*.dmp`, `*.trc`, `*.ber` | generic extensions that are sometimes captures (the viewer never takes these over from other editors) |

Other formats Wireshark reads work as well when the file has one of these names
(for example a Microsoft Network Monitor capture saved as `.cap`, or a Sniffer
`.trc`). A file tshark doesn't recognise
shows "_name_ is not a capture file that tshark can read" in the viewer, with a
button to reopen it in another editor. Reading zstd and LZ4 files needs a
tshark built with them (`tshark --version` lists "with Zstandard", "with LZ4").

| Command                                                                                                               | Default key                           | Description                                                                                                       |
| --------------------------------------------------------------------------------------------------------------------- | ------------------------------------- | ----------------------------------------------------------------------------------------------------------------- |
| PCAP: Apply Display Filter                                                                                            | `Ctrl+/` (`Cmd+/`)                    | Prompt for a filter (validated) and apply it                                                                      |
| PCAP: Clear Display Filter                                                                                            |                                       |                                                                                                                   |
| PCAP: Save Display Filter…                                                                                            |                                       | Save the current filter under a name                                                                              |
| PCAP: Suggest Display Filter…                                                                                         |                                       | Describe the packets; pick an AI-suggested, tshark-checked filter (also ✨ in the filter bar and `@pcap` in chat) |
| PCAP: Ask Copilot About Selected Packets…                                                                             |                                       | Explain the selected packets in chat (`@pcap /explain`; sends packet data, asks first)                            |
| PCAP: Clear Index Cache                                                                                               |                                       | Delete the saved packet-list indexes                                                                              |
| PCAP: Set TLS Key Log File…                                                                                           |                                       | Decrypt TLS with an `SSLKEYLOGFILE` key log (or stop using it)                                                    |
| PCAP: Saved Display Filters                                                                                           |                                       | Apply or delete saved filters                                                                                     |
| PCAP: Go to Packet                                                                                                    | `Ctrl+G` (`Cmd+G`)                    | Jump to a frame number                                                                                            |
| PCAP: Find Packet… / Find Next / Find Previous                                                                        | `Ctrl+F`, `F3`, `Shift+F3`            | Find by display filter, string or hex bytes                                                                       |
| PCAP: Go Back / Go Forward (Packet History)                                                                           | `Alt+Left`, `Alt+Right`               | Walk back and forth over jumps (links, go to, find…)                                                              |
| PCAP: Next / Previous Packet in Conversation                                                                          | `Ctrl+.`, `Ctrl+,`                    | Same TCP/UDP stream, else the same address pair                                                                   |
| PCAP: First Packet / Last Packet                                                                                      | `Ctrl+Home`, `Ctrl+End`               |                                                                                                                   |
| PCAP: Select All Packets                                                                                              | `Ctrl+A` (`Cmd+A`) in the packet list | Select every displayed packet                                                                                     |
| PCAP: Mark/Unmark Selected Packets                                                                                    | `Ctrl+M`                              | Mark the selected packets (unmark them if all are marked)                                                         |
| PCAP: Next / Previous Marked Packet                                                                                   | `Ctrl+Shift+N`, `Ctrl+Shift+B`        |                                                                                                                   |
| PCAP: Unmark All Packets / Export Marked Packets…                                                                     |                                       | Clear the marks / save the marked packets as pcapng or pcap                                                       |
| PCAP: Set/Unset Time Reference                                                                                        | `Ctrl+T`                              | Relative times count from the selected packet                                                                     |
| PCAP: Time Display Format…                                                                                            |                                       | Choose how the Time column is shown                                                                               |
| PCAP: Follow TCP / UDP / TLS / HTTP Stream                                                                            |                                       | Follow the selected packet's stream (also in the packet list's right-click menu)                                  |
| PCAP Statistics: Conversations, Endpoints, Protocol Hierarchy, I/O Graph, Expert Information, Capture File Properties |                                       | Open the report in a panel beside the capture                                                                     |
| PCAP: Manage Custom Columns                                                                                           |                                       | Add or remove columns (searches tshark's field list)                                                              |
| PCAP: Reload Capture                                                                                                  |                                       | Re-run tshark on the current capture                                                                              |
| PCAP: Reload Dissectors                                                                                               |                                       | Check the Lua dissectors for errors, then re-index all open captures                                              |
| PCAP: New Lua Dissector…                                                                                              |                                       | Create a dissector from a template in the dissectors folder                                                       |
| PCAP: Open Dissectors Folder                                                                                          |                                       | Reveal (or set up) `pcapViewer.dissectorsFolder`                                                                  |
| PCAP: Decode As… / Manage Decode As Rules                                                                             |                                       | Add or remove `-d` rules (stored in settings)                                                                     |
| PCAP: Export Specified Packets…                                                                                       |                                       | Displayed / all / selected packets to pcapng or pcap                                                              |
| PCAP: Export Selected Packets…                                                                                        |                                       | The selected packets to pcapng or pcap                                                                            |
| PCAP: Export Packet List as CSV/JSON…                                                                                 |                                       | The displayed (or selected) rows with their columns                                                               |
| PCAP: Export Packet Bytes…                                                                                            |                                       | Raw bytes of the selected packet (or a reassembled source)                                                        |
| PCAP: Export Packet Dissections…                                                                                      |                                       | Full packet details as plain text, PDML or JSON                                                                   |
| PCAP: Merge Captures…                                                                                                 |                                       | Merge a rotated capture's pieces, or any captures, into one file and open it                                      |
| PCAP: Export Objects…                                                                                                 |                                       | Files carried over HTTP, SMB, TFTP, IMF, DICOM and FTP-DATA: list, go to packet, save                             |
| PCAP: Name Resolution…                                                                                                |                                       | Names for MAC addresses, IP addresses and ports (also the status bar's _Names_ link)                              |
| PCAP: Colorize with Filter…                                                                                           |                                       | Add a coloring rule (also in the detail tree's right-click menu)                                                  |
| PCAP: Toggle Packet Coloring / Edit Coloring Rules                                                                    |                                       | Turn coloring on or off / edit `pcapViewer.coloringRules` in a rules editor                                       |
| PCAP: Show Log                                                                                                        |                                       | Backend and tshark messages (Lua errors, warnings)                                                                |

Keyboard: in the list use ↑/↓/PgUp/PgDn/Home/End, `Enter`/`→` to move to the
tree; in the tree use arrows to navigate and expand/collapse (`Enter` on a frame
link jumps to that packet); `Esc` in the filter bar restores the applied filter
and in the find bar closes it. On macOS use `Cmd` instead of `Ctrl`. The viewer
shortcuts only apply while a capture is the active editor and focus isn't in
the side bar or panel.

## Settings

| Setting                                 | Description                                                                                                                                     |
| --------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------- |
| `pcapViewer.tsharkPath`                 | Path to `tshark` (empty: auto-detect)                                                                                                           |
| `pcapViewer.pythonPath`                 | Python 3.14+ interpreter (empty: auto-detect)                                                                                                   |
| `pcapViewer.luaScripts`                 | Lua dissectors, passed as `-X lua_script:<path>`                                                                                                |
| `pcapViewer.dissectorsFolder`           | Folder whose `*.lua` files are also loaded                                                                                                      |
| `pcapViewer.decodeAs`                   | Decode As rules, e.g. `"tcp.port==8080,http"`                                                                                                   |
| `pcapViewer.prefs`                      | Preference overrides, e.g. `{ "tcp.desegment_tcp_streams": false }`                                                                             |
| `pcapViewer.tlsKeyLogFile`              | TLS key log file (`SSLKEYLOGFILE` format) for decryption, passed as the `tls.keylog_file` preference (per workspace folder)                     |
| `pcapViewer.nameResolution.mac`         | Names for MAC addresses, e.g. `Broadcast` (default `true`)                                                                                      |
| `pcapViewer.nameResolution.network`     | Host names for IP addresses, from the capture's DNS answers and hosts files (default `false`)                                                   |
| `pcapViewer.nameResolution.capturedDns` | With network names, use the capture's DNS answers (default `true`)                                                                              |
| `pcapViewer.nameResolution.transport`   | Service names for ports, e.g. `http(80)` (default `false`)                                                                                      |
| `pcapViewer.nameResolution.external`    | With network names, also ask your DNS server (default `false`; slower, the server sees the addresses; user settings only)                       |
| `pcapViewer.columns`                    | Extra columns: `"tcp.stream"` or `{ "field": "http.host", "title": "Host" }` (per workspace folder)                                             |
| `pcapViewer.columnLayout`               | Column order and hidden columns by id, e.g. `{ "order": ["protocol", "number"], "hidden": ["time"] }` (set by the header menu and dragging)     |
| `pcapViewer.timeFormat`                 | Time column: `relative` (default), `delta_displayed`, `delta_captured`, `absolute`, `utc` or `epoch`                                            |
| `pcapViewer.savedFilters`               | Named filters: `{ "name": "Web", "filter": "http \|\| tls" }`                                                                                   |
| `pcapViewer.coloringRules`              | Coloring rules, first match wins: `{ "name": "DNS", "filter": "dns", "foreground": "#12272e", "background": "#c8e2ff" }`                        |
| `pcapViewer.colorize`                   | Color the packet list (default `true`)                                                                                                          |
| `pcapViewer.ai.enabled`                 | Offer AI help when a language model is available (default `true`)                                                                               |
| `pcapViewer.ai.allowPacketData`         | Let _Ask Copilot About This Packet…_ / `@pcap /explain` send packet rows and dissection trees (default `false`; asked once; user settings only) |
| `pcapViewer.ai.allowPacketBytes`        | Also send raw bytes when explaining packets (default `false`; user settings only)                                                               |
| `pcapViewer.maxCachedFrames`            | Backend cache budget for filter results / sort orders                                                                                           |
| `pcapViewer.indexCache.enabled`         | Save each capture's packet-list index so reopening it is instant (default `true`)                                                               |
| `pcapViewer.indexCache.maxSizeMB`       | Disk space the saved indexes may use (default `1024`)                                                                                           |
| `pcapViewer.quickDetail.after`          | From this packet number on, show a quick (approximate) view first (default `20000`; `0` = never)                                                |
| `pcapViewer.quickDetail.window`         | How many packets the quick view dissects (default `300`)                                                                                        |
| `pcapViewer.requestTimeoutSeconds`      | Timeout for quick requests (long ones are cancellable instead)                                                                                  |

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
  Rows are published in batches while the pass runs, so the list shows the
  first ones right away; the finished file and offsets are saved in the
  extension's storage and reused while nothing that changes them changed.
- Applying a filter runs `tshark -Y <filter> -T fields -e frame.number` once
  and caches the matching frame numbers (4 bytes per match). The pass runs in
  the background and the list shows the matches found so far; the result is
  saved with the capture's index (the 8 most recent filters).
- Selecting a packet runs `tshark -c N -Y frame.number==N -T pdml` (and `-x`
  for the bytes), so tshark stops reading after that packet. For late packets
  a quick view comes first: `editcap -r` copies the last few hundred packets
  up to it into a small temporary file (it reads records without dissecting
  them), tshark dissects only those, and the frame numbers in the tree are
  shifted back to the capture's.
- Coloring keeps one byte per packet (the matching rule). When a capture is
  opened, the index pass also runs with `--color` and reports each packet's
  rule as one more field, so colors arrive with the rows; changed rules run
  one separate `tshark --color` pass in the background. tshark reads coloring
  rules only from its configuration folder, so these passes point
  `WIRESHARK_CONFIG_DIR` at a temporary folder with the generated rules and
  copies of your other Wireshark settings.
- Exporting packets runs `tshark -Y <filter> -w <file>`; the packet list and
  packet bytes are written from the backend's own index and detail cache.

### Performance

Measured with `test/perf/bench.py` on 1,000,000 synthetic packets (146 MB,
4-core Linux VM, tshark 4.2, `tcp.analyze_sequence_numbers` off):

| Operation                                   | Time                                                                                                        |
| ------------------------------------------- | ----------------------------------------------------------------------------------------------------------- |
| Open (index pass)                           | 29–36 s (tshark-bound); the first rows show after 0.5 s, already colored                                    |
| Coloring with the 14 default rules          | +2 s on the index pass (a separate pass, used when rules change: ~30 s)                                     |
| Reopen an unchanged capture (saved index)   | 0.01 s                                                                                                      |
| Fetch a 200-row page (any position)         | < 1 ms                                                                                                      |
| 1000 random scroll pages                    | 0.09 s total                                                                                                |
| Apply a filter                              | 26 s (one tshark pass; the first matches show after 0.5 s; re-applying a cached or saved filter is instant) |
| Sort 1M rows by Length                      | 0.6 s                                                                                                       |
| Detail of frame 10 / frame 1,000,000        | 0.2 s / 20–26 s                                                                                             |
| Quick view of any frame (300-packet window) | 0.25–0.3 s                                                                                                  |
| Peak memory: backend / tshark               | 125 MB / 225 MB                                                                                             |

Almost all of the time is tshark's own dissection. Wireshark preferences that
make dissection cheaper can be set through `pcapViewer.prefs`, for example
`{ "tcp.analyze_sequence_numbers": false }` (the synthetic benchmark capture
replays the same flows, which makes this analysis 6x slower: 165 s instead of 26 s
for the filter). Opening a packet near the end of a huge capture re-reads the
file up to that packet so reassembly stays correct; the quick view above shows
something in the meantime.

## Roadmap

Every item of the project brief is implemented. Possible next steps: live
capture from a network interface (`dumpcap`), and getting ready to publish
(an icon, a release workflow, screenshots).

## Running locally (Linux)

These steps take a fresh Linux machine to a running development copy of the
extension. Commands are shown for Ubuntu/Debian, with Fedora and Arch
equivalents where they differ. macOS and Windows work the same way once the
tools below are installed.

### 1. Install the tools

| Tool                | Why                                                                               | Install                                                                                                                       |
| ------------------- | --------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------- |
| Git, VS Code ≥ 1.90 | source and editor                                                                 | `sudo apt install git`, VS Code from [code.visualstudio.com](https://code.visualstudio.com/) (`.deb`/`.rpm`, Snap or Flatpak) |
| tshark              | dissection and filtering                                                          | `sudo apt install tshark` · Fedora: `sudo dnf install wireshark-cli` · Arch: `sudo pacman -S wireshark-cli`                   |
| uv                  | Python toolchain; installs Python 3.14                                            | `curl -LsSf https://astral.sh/uv/install.sh \| sh`                                                                            |
| Python 3.14         | runs the backend                                                                  | `uv python install 3.14` (puts `python3.14` in `~/.local/bin`)                                                                |
| Node.js 22.13+      | builds the extension (vsce 4, eslint 10 and @vscode/test-electron 3 need Node 22) | [nvm](https://github.com/nvm-sh/nvm): `nvm install 22`, or your distro/NodeSource package                                     |
| pnpm                | JavaScript package manager                                                        | `corepack enable pnpm` (or `npm install -g pnpm`); the version is pinned in `package.json`                                    |

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

| Command                       | Does                                                                                                                       |
| ----------------------------- | -------------------------------------------------------------------------------------------------------------------------- |
| `make install`                | `uv sync` and `pnpm install`                                                                                               |
| `make update`                 | Upgrade all dev dependencies: `ncu -u` (within the limits in `.ncurc.cjs`), `pnpm install`, `uv lock --upgrade`, `uv sync` |
| `make outdated`               | Show available updates without changing anything                                                                           |
| `make compile` / `make watch` | Build the extension once / on every change                                                                                 |
| `make lint` / `make format`   | All linters / auto-fix what they can                                                                                       |
| `make test`                   | Backend tests plus TS unit and webview tests (`make test-backend`, `make test-acceptance`, `make test-unit` for parts)     |
| `make test-extension`         | VS Code smoke test (uses `xvfb-run` automatically when there's no display)                                                 |
| `make check`                  | `lint` + `test`: what CI runs, except the smoke test                                                                       |
| `make fixtures` / `make perf` | Regenerate the test captures / benchmark the 1M-packet capture                                                             |
| `make package` / `make clean` | Build the `.vsix` / remove build output and caches                                                                         |

### 3. Run the extension

**From source (for development).** Open the folder in VS Code with
`code .` and press `F5` (the "Run Extension" launch configuration). A second
VS Code window, the _Extension Development Host_, opens with
`test/fixtures/` loaded. Open `http.pcap` or `mixed.pcapng` there to see the
viewer. `pnpm run watch` rebuilds TypeScript on save; reload the host window
with `Ctrl+R` to pick up changes. Webview files (`src/webview/`) need no build step.

**As an installed extension.** Build a `.vsix` and install it into your normal VS Code:

```sh
pnpm run package
code --install-extension pcap-viewer-0.1.0.vsix
```

Then open any `.pcap`/`.pcapng` file. Backend and tshark messages are shown in
_PCAP: Show Log_ (the "PCAP Viewer" output channel).

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

To try TLS decryption, generate an HTTPS session and the key log that
decrypts it (open the capture, then _PCAP: Set TLS Key Log File…_ with the
`.log` file):

```sh
uv run python test/fixtures/generate.py --tls-keylog /tmp/tls.pcap /tmp/tls-keys.log
```

To capture your own, start the browser with the variable set
(`SSLKEYLOGFILE=~/tls-keys.log firefox`) and capture with Wireshark or
`tcpdump -w`.

### Troubleshooting

| Symptom                                                                                                                                                                                         | Fix                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 |
| ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| "No Python 3.14+ interpreter found"                                                                                                                                                             | VS Code doesn't see `~/.local/bin`. Set `pcapViewer.pythonPath` to the output of `uv python find 3.14`, or start VS Code from a terminal where `python3.14` works.                                                                                                                                                                                                                                                                                                                                                                                  |
| "tshark was not found"                                                                                                                                                                          | Install tshark (step 1) or set `pcapViewer.tsharkPath`, e.g. `/usr/bin/tshark`.                                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| `tshark: You don't have permission to read the file "…"` although the file is yours                                                                                                             | On Ubuntu with tshark 4.6, the AppArmor profile `/etc/apparmor.d/tshark` only lets tshark use `/tmp` and Wireshark's own folders. Allow your files with a local rule: `echo 'owner @{HOME}/** rw,' \| sudo tee -a /etc/apparmor.d/local/tshark` then `sudo apparmor_parser -r /etc/apparmor.d/tshark` (add e.g. `owner /media/** rw,` for other places). Check with `sudo aa-status \| grep tshark`; denials show in `journalctl -k \| grep 'profile="tshark"'`. A Snap-packaged tshark has similar limits: use the distribution's package instead. |
| Cancelling a filter is slow, _PCAP: Show Log_ says "could not stop tshark … Permission denied", or the kernel log shows `apparmor="DENIED" operation="signal" profile="tshark" … peer="vscode"` | The same AppArmor profile doesn't let tshark receive signals from the extension (VS Code runs under its own `vscode` profile; the tests run unconfined). The backend then closes tshark's output instead, so tshark stops at its next write, but a pass that writes nothing runs to its end. Allow the signals with two more local rules and reload: `printf '%s\n' 'signal (receive) peer=unconfined,' 'signal (receive) peer=vscode,' \| sudo tee -a /etc/apparmor.d/local/tshark` then `sudo apparmor_parser -r /etc/apparmor.d/tshark`.         |
| `make fixtures` fails with "No module named '_zstd'"                                                                                                                                            | Your Python was built without zstd support (common with pyenv when `libzstd-dev` is missing); only the `.zst` test fixtures need it, so `make large-fixture` works anyway. Install `libzstd-dev` and rebuild it (`pyenv install --force 3.14`), or switch the venv to a uv-managed Python: `uv venv --python 3.14 --python-preference only-managed`, then `uv sync`.                                                                                                                                                                                |
| Lua dissector isn't applied                                                                                                                                                                     | Check _PCAP: Show Log_ for Lua errors. Don't run as root. Use _PCAP: Reload Capture_ after editing the script.                                                                                                                                                                                                                                                                                                                                                                                                                                      |
| TLS stays encrypted with a key log file set                                                                                                                                                     | The key log must hold the keys of the sessions in the capture: start the browser with `SSLKEYLOGFILE` set _before_ the capture, and don't clear the file. _PCAP: Show Log_ says so if the file doesn't exist. TLS 1.3 needs the `*_TRAFFIC_SECRET` lines, TLS 1.2 the `CLIENT_RANDOM` ones.                                                                                                                                                                                                                                                         |
| Opening a huge file is slow                                                                                                                                                                     | Indexing speed is tshark's. Settings such as `"pcapViewer.prefs": { "tcp.analyze_sequence_numbers": false }` make it cheaper.                                                                                                                                                                                                                                                                                                                                                                                                                       |
| `pnpm install` fails with "Ignored build scripts"                                                                                                                                               | Use the pnpm version pinned in `package.json` (`corepack enable pnpm`). The build-script policy is in `pnpm-workspace.yaml`.                                                                                                                                                                                                                                                                                                                                                                                                                        |

See `CLAUDE.md` for architecture notes and design decisions.

## Security

- tshark and Python are always started with argument arrays, never through a shell.
- Packet contents are untrusted: the webview inserts them only as text (never
  `innerHTML`) and runs under a strict Content-Security-Policy with a per-load nonce.
- The webview can only call a fixed allow-list of backend methods.
- **AI filter help sends no packet data.** A request to the language model contains
  only your description, the current display filter, the names of the
  protocols in the capture (from the protocol hierarchy) and the names,
  types and descriptions of Wireshark fields that match words of your
  request. Addresses, payloads and other packet contents are never sent.
  Requests go through VS Code's Language Model API, so VS Code asks for your
  consent first, and your Copilot plan and policies apply. Turn it off with
  `"pcapViewer.ai.enabled": false`.
- **Explaining packets sends packet data, only if you allow it.** With
  `pcapViewer.ai.allowPacketData` off (the default), _Ask Copilot About This
  Packet…_ and `@pcap /explain` first ask you. What is sent, for at most 8
  packets at a time: their packet-list row (the columns you see) and their
  dissection tree (field names and values, at most 250 lines each), plus your
  question and the current display filter. Raw bytes (the hex dump, and
  payload fields shown as bytes, which become "[N bytes not sent]") are not
  sent unless `pcapViewer.ai.allowPacketBytes` is also on (then the first 256
  bytes of each packet). Both settings can only be set in user settings, so a
  workspace can't turn them on. The prompt tells the model that packet data is
  untrusted.
- CSV exports prefix cells that a spreadsheet would run as a formula (`=`,
  `+`, `@`, `-`…) with `'`, since packet text is attacker-controlled.

## License and Wireshark

This extension is MIT licensed. **tshark is part of Wireshark, which is
licensed under the GNU GPL v2.** The extension does not bundle, link to or
modify Wireshark; it runs a tshark you installed yourself as a separate
process and reads its output.
