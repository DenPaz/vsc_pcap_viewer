# Changelog

## Unreleased

- More statistics: _PCAP Statistics: HTTP_ (packet counter by status code and
  method, requests by host and URI, load distribution by server), _DNS_,
  _Packet Lengths_ and _Service Response Time_ (ICMP/ICMPv6, SMB, SMB2, LDAP,
  SNMP, Diameter, GTP and others; protocols with traffic are marked). Their
  rows apply or prepare the display filter of the packets they count.
- Filter buttons under the filter bar, like Wireshark's: one click applies a
  filter. Add one with **+** or _PCAP: Add Filter Button…_; right-click a
  button to edit, move or remove it (`pcapViewer.filterButtons`).
- _PCAP: Import from Hex Dump…_ builds a capture from a hex dump in the
  editor, the clipboard or a text file (text2pcap): Ethernet frames, IP
  packets, or payloads with a dummy UDP/TCP/SCTP header, optionally with a
  time before each packet. It opens as a new unsaved capture.

- ☰ in the viewer's filter bar lists every PCAP Viewer command under headings
  (Filters, Packets, Statistics, Export, Capture, Editing, Dissectors, AI,
  Other) with its key binding, filters them as you type and runs the one you
  pick on that capture. Commands that can't run right now are greyed out with
  the reason. On narrow editors the filter bar's buttons now wrap to a second
  line instead of squeezing the filter box.

- VoIP calls: _PCAP Statistics: VoIP Calls_ lists the SIP calls (state, setup
  time, duration) with a sequence diagram of each call's messages and media,
  and the RTP streams with lost packets, delta and jitter. A stream can be
  analysed packet by packet (jitter over time, sequence errors linked to
  their packets), its G.711 audio played in the panel or saved as a WAV
  file (other codecs as raw payload), and a call or stream shown in the
  capture with one click. RTP without SIP signalling can be found with
  tshark's RTP heuristic.

- Fixed: closing VS Code (or a capture) while a big capture was still being
  indexed could save the packets read so far as the capture's complete
  index, so the next open showed a truncated packet list. Only a pass that
  really reached the end of the file is saved as complete now, and saved
  colors and filter results come only from complete indexes.
- Opening big captures is resumable: closing a capture before it is fully
  indexed keeps what was indexed, and the next open shows those packets at
  once, re-reads them to check they still match ("Resuming… re-reading
  packets 1–N (already shown)"), then goes on with the rest.
- A progress bar under the filter bar for indexing (determinate when the
  size is known, animated otherwise, a quieter style while resuming),
  streaming filters, coloring and exports, with the percentage and packet
  count in the status bar ("Indexing… 42% · 420,000 packets").

- Remote windows (WSL, SSH, Dev Containers, Codespaces): PCAP Viewer runs on
  the remote machine, next to the captures and the tools, and says so when
  Python or tshark is missing there. Saved files are shown in the Explorer
  view (or their path is offered) instead of the local file manager. The
  README has a Dev Container example.
- Captures that aren't files on disk (Live Share, archives, virtual file
  systems) offer to open a copy.
- Restricted Mode: the extension now works in untrusted workspaces, where the
  Python and tshark paths and the Lua dissectors come from user settings only.

- **Get Started with PCAP Viewer** walkthrough (_Help › Welcome_, or _PCAP:
  Get Started_): checks Python and tshark and says how to install what's
  missing on your system, opens a sample capture, and introduces filters,
  statistics and the optional AI features. _PCAP: Check Python and TShark_
  runs the check at any time; a capture that can't open because either is
  missing offers the guide.
- _PCAP: Open Sample Capture_: a small capture with ARP, ICMP, DNS and HTTP.
- An icon, screenshots and Marketplace details.
- Releases: pushing a `v<version>` tag builds the `.vsix` and attaches it to
  a GitHub release with the version's CHANGELOG notes, and publishes it to the
  VS Code Marketplace and Open VSX when their tokens are configured.

- Capture summary with Copilot: _PCAP: Summarize Capture with Copilot_ or
  `@pcap /summary` describes the capture from its statistics (properties,
  protocol hierarchy, top conversations and endpoints, expert counts, traffic
  over time), never from packet contents, with _Apply filter_ buttons for the
  filters it suggests.
- Anomaly explanations: _Ask Copilot…_ in the Expert Information panel and in
  the TCP Stream Graph panel (`@pcap /anomaly`) explains expert entries with
  their conversation, or a TCP stream from its sequence numbers, windows,
  round-trip times and retransmissions (never its payload).
- `@pcap` answers questions with read-only tools on the open capture (packet
  counts for display filters, statistics, capture properties, field search,
  packet rows) where VS Code has language model tools; the tools never change
  the viewer's filter, and at most 8 calls are made per question.
- New setting `pcapViewer.ai.allowCaptureStatistics` (off; asked once; user
  settings only) for the features above; `pcapViewer.ai.allowPacketData`
  implies it and is still needed for packet rows. The README lists what each
  AI feature sends.
- Backend: `count_matches` counts a display filter's packets without changing
  the view.

- Live capture: _PCAP: Start Capture…_ captures on one or more interfaces,
  with a capture filter checked as you type, into a new capture that fills as
  packets arrive (the list follows them). _Stop_ in the status bar or the
  editor title, or `pcapViewer.capture.stopAfter*`. The capture is unsaved
  until saved (`Ctrl+S` asks where); closing it without saving discards it.
- Capture editing (_PCAP: Edit Capture…_): time shift, remove duplicate
  packets, keep packets by number or time, truncate packets, split into files
  of N packets or seconds, and embed a TLS key log in the capture. The result
  opens as a new unsaved capture.
- Packet comments: shown on the packet's row and above its details; add, edit
  and delete them (`Ctrl+Alt+C`, the row menu, _PCAP: Delete All Packet
  Comments_). Edits are ordinary unsaved changes: undo with `Ctrl+Z`, save
  into the capture with `Ctrl+S` (a new `.pcapng` for other formats).
- _PCAP Statistics: Flow Graph_: the displayed packets as arrows between their
  endpoints.
- _PCAP Statistics: TCP Stream Graph_: Stevens, throughput, round-trip time
  and window scaling graphs of a TCP stream.
- _PCAP: Export Objects…_: the files a capture carried over HTTP, SMB, TFTP,
  IMF, DICOM and FTP-DATA, with the packet, host, content type and size of
  each; filter, sort, go to the packet, and save one or all of them.
- Name resolution (_PCAP: Name Resolution…_, the status bar's _Names_ link,
  `pcapViewer.nameResolution.*`): names for MAC addresses, IP addresses (from
  the capture's DNS answers and hosts files; network lookups only if allowed)
  and ports. Resolved names show their address as a tooltip and cell filters
  use the address.
- Fixed: statistics showed MAC names such as "Broadcast" from Wireshark's
  preferences, and their rows then built filters that matched nothing; reports
  now always show addresses.
- _PCAP: Export Packet Dissections…_: the full packet details of the
  displayed, all, selected or marked packets as plain text, PDML or JSON,
  optionally with the packet bytes.
- Merging captures: opening a piece of a rotated capture (`tcpdump -C`, or a
  dumpcap/Wireshark ring buffer) offers to merge all its pieces into one
  capture; _PCAP: Merge Captures…_ merges them, or any captures by timestamp.
- _PCAP: Edit Coloring Rules_ (was _Manage Coloring Rules_, which opened the
  settings) is an editor: reorder, enable, rename, recolor with a preview, add
  and remove rules, with filters checked by tshark as you type.
- CI uses the Node 24 versions of its GitHub Actions.
- Colors come with the packets: opening a capture evaluates the coloring rules
  in the same tshark pass that builds the packet list, so rows are colored as
  soon as they show (0.5 s on a million packets) instead of after indexing and
  a second full pass (about a minute). It adds about 6% to the pass, and the
  colors are saved with the index. A coloring pass after changing rules shows
  "Coloring… N%" in the status bar.
- Fixed: after scrolling to the end of the list while a big capture was still
  being indexed (or a filter was still running), the list stopped growing.
- Streaming filters: on big captures the matches show as tshark finds them,
  with a count and progress in the status bar. ■ stops the filter and keeps
  the matches found so far; a sort chosen meanwhile applies when it's done.
  A filter applied while a capture is still being indexed starts at once.
  Finished filter results are saved with the index, so reapplying one after
  reopening the capture is instant.
- TLS decryption: _PCAP: Set TLS Key Log File…_ (`pcapViewer.tlsKeyLogFile`)
  decrypts TLS and QUIC with an `SSLKEYLOGFILE` key log. The capture reloads
  when the setting changes, the viewer offers a reload when the file gets new
  keys, and saved indexes follow the file's contents. `generate.py
--tls-keylog` makes a sample capture and key log to try it.
- Big captures open faster: the first packets show within about half a second
  while the rest is indexed, and the
  finished index is saved, so reopening an unchanged capture is instant
  (`pcapViewer.indexCache.enabled`, `pcapViewer.indexCache.maxSizeMB`,
  _PCAP: Clear Index Cache_).
- The large-capture generator (`make large-fixture`) works on Pythons built
  without zstd.
- Quick view of late packets: from packet 20,000 on (`pcapViewer.quickDetail.after`),
  the details show in about 0.3 s instead of up to ~20 s per million packets:
  only the 300 packets before it (`pcapViewer.quickDetail.window`) are
  dissected (cut out with editcap), marked _Quick view_, until the exact view
  replaces it. Ask Copilot uses it for late packets too.
- _Ask Copilot About This Packet…_ (and _…About N Selected Packets…_) in the
  packet list, and `@pcap /explain <frames> [question]` in chat: the language
  model explains the packets, with _Go to packet_ and _Apply filter_ buttons.
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
  the selection (_Export Selected Packets…_; the CSV/JSON packet list can
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
  ✨ in the filter bar, _PCAP: Suggest Display Filter…_ and `@pcap` in chat.
  Suggestions are validated with tshark; no packet data is sent.

- Opens more capture file types by default: gzip/zstd/lz4-compressed pcap and
  pcapng, `.ntar`, `tcpdump -C` rotated files (`*.pcap1`…), snoop, ERF,
  PacketLogger and btsnoop. Generic extensions (`*.1`, `.log`, `.dmp`, `.trc`,
  `.ber`) are offered in _Reopen Editor With…_.
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
- Coloring rules (default Wireshark-like set, _Colorize with Filter…_,
  toggle), evaluated by tshark in one background pass.
- Export: displayed / all / selected packets to pcapng or pcap, the packet
  list as CSV or JSON, packet bytes, and stream data.
