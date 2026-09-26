# Changelog

## Unreleased

- Quick view of late packets: from packet 20,000 on (`pcapViewer.quickDetail.after`),
  the details show in about 0.3 s instead of up to ~20 s per million packets:
  only the 300 packets before it (`pcapViewer.quickDetail.window`) are
  dissected (cut out with editcap), marked *Quick view*, until the exact view
  replaces it. Ask Copilot uses it for late packets too.
- *Ask Copilot About This Packet…* (and *…About N Selected Packets…*) in the
  packet list, and `@pcap /explain <frames> [question]` in chat: the language
  model explains the packets, with *Go to packet* and *Apply filter* buttons.
  It sends the packets' rows and dissection trees (capped; no raw bytes unless
  `pcapViewer.ai.allowPacketBytes`), only after a one-time consent that sets
  `pcapViewer.ai.allowPacketData`.
- Fixed: the busy bar kept spinning after sorting by a column.
- Fixed: a notice (e.g. "Packet 4 is not displayed") shown right after applying a
  filter could be wiped by the late validation of what was typed.
- Cancelling works when tshark can't be killed: under Ubuntu's AppArmor tshark
  profile `kill()` is refused (`PermissionError`), which crashed cancellation
  and could leave tshark running. The backend now closes tshark's output
  instead, reaps it, logs one warning, and the AppArmor hint suggests the
  `signal (receive) peer=unconfined,` / `peer=vscode,` local rules.
- tshark 4.6: the packet's own bytes are still labelled "Frame" (4.6 says
  "Packet"); tests no longer depend on the protocol hierarchy's depth.
- Ctrl+A in the packet list now selects every packet in VS Code (it used to
  select the page's text).
- Multi-select in the packet list: Shift+click / Shift+arrows ranges,
  Ctrl/Cmd+click, Ctrl+A, Esc. Mark, copy (rows or frame numbers) and export
  the selection (*Export Selected Packets…*; the CSV/JSON packet list can
  export the selected rows).
- Source/Destination (and custom IPv4/IPv6/MAC columns) sort numerically:
  IPv4, then IPv6, then MAC addresses, then names.
- The Time column sorts by the time format shown: the delta formats sort by
  the delta.
- "Since previous displayed packet" now means the previous packet of the
  filter in capture order (like Wireshark), whatever the sort order.
- Fixed: after a sort change the selection could be drawn on the row where
  the packet was before the sort.

- Wireshark-like navigation: Find Packet (display filter / string / hex),
  clickable frame references with back/forward history, next/previous packet
  in the conversation, first/last packet, marks (with export of marked
  packets), time display formats and a time reference.
- Customisation: Apply as Column, header menu (hide/show, rename, remove,
  resize to contents, reset) and drag-to-reorder columns (pcapViewer.columnLayout),
  cell Apply as Filter, and bytes-pane copy formats (hex dump, hex stream,
  C array, escaped string, Base64, printable text).

- Optional AI help for display filters (VS Code Language Model API / Copilot):
  ✨ in the filter bar, *PCAP: Suggest Display Filter…* and `@pcap` in chat.
  Suggestions are validated with tshark; no packet data is sent.

- Opens more capture file types by default: gzip/zstd/lz4-compressed pcap and
  pcapng, `.ntar`, `tcpdump -C` rotated files (`*.pcap1`…), snoop, ERF,
  PacketLogger and btsnoop. Generic extensions (`*.1`, `.log`, `.dmp`, `.trc`,
  `.ber`) are offered in *Reopen Editor With…*.
- Files tshark can't read show a clear message; open progress no longer
  stalls at 99% for compressed files and other formats.
- Export file names drop compression suffixes (`trace.pcap.gz` →
  `trace-filtered.pcapng`).

## 0.1.0

First release: every item of the project brief.

- Custom read-only editor for `.pcap` / `.pcapng` / `.cap` files, backed by
  tshark through a stdlib-only Python backend (JSON-RPC over stdio).
- Packet list for captures with millions of packets: virtualized rows, backend
  paging over a cached index, backend-side sorting, custom columns.
- Protocol tree and hex/ASCII view with two-way byte highlighting, including
  reassembled data sources.
- Display filters with validation, inline errors, autocomplete from tshark's
  field list, history and saved filters; apply/prepare as filter from the tree.
- Follow TCP / UDP / TLS / HTTP stream panel.
- Statistics panels: conversations, endpoints, protocol hierarchy, I/O graph,
  expert information, capture file properties.
- Lua dissectors (new from template, reload with error check, dissectors
  folder), Decode As rules and preference overrides.
- Coloring rules (default Wireshark-like set, *Colorize with Filter…*,
  toggle), evaluated by tshark in one background pass.
- Export: displayed / all / selected packets to pcapng or pcap, the packet
  list as CSV or JSON, packet bytes, and stream data.
