# Changelog

All notable changes, newest first. Each entry links to the pull request that
made it. The format follows [Keep a Changelog](https://keepachangelog.com);
versions are plain `major.minor.patch`.

## Unreleased

### Added

- The ☰ menu's groups fold: it opens as a short list of headings with their
  command counts; a click, `Enter` or `→` unfolds one, and typing still
  searches every command. Open groups are remembered. [#34]
- _PCAP: Lua Dissectors…_ (also the status bar's _Lua_ link): choose which of
  the configured Lua scripts each capture loads, remembered per file. [#34]
- _PCAP: Open File in PCAP Viewer…_ (also in the Explorer's right-click menu):
  open any file tshark reads, whatever its name or without an extension, or
  get told why it can't be read (for example several BER records back to
  back). [#34]
- The log says why each capture (re)loads and how long starting tshark, the
  first rows and the whole index took. [#35]

### Fixed

- Opening a capture failed when tshark's first run took over 30 s (macOS
  checks Wireshark.app the first time it runs after an install or update).
  tshark now gets 2 minutes, the viewer says why it's waiting after 5 s, and
  a backend that never answered is stopped. [#35]

[#34]: https://github.com/DenPaz/vsc_pcap_viewer/pull/34
[#35]: https://github.com/DenPaz/vsc_pcap_viewer/pull/35

## 0.2.0 — 2026-09-28

The first published release. It adds everything since 0.1.0 below.

### Added

**Opening big captures**

- The first packets show within about half a second while the rest is
  indexed. The finished index is saved, so reopening an unchanged capture is
  instant (`pcapViewer.indexCache.*`, _PCAP: Clear Index Cache_). [#18]
- Resumable indexing: a capture closed before it was fully indexed shows the
  saved packets at once on the next open, then continues. [#29]
- A progress bar for indexing, filters, coloring and exports, with the
  percentage and packet count in the status bar. [#29]
- Quick view of late packets: from packet 20,000 on, details show in about
  0.3 s by dissecting only the 300 packets before (`pcapViewer.quickDetail.*`).
  [#17]
- Streaming filters: matches show as tshark finds them; ■ stops and keeps them.
  Finished results are saved with the index. [#19]
- Colors come with the packets: the coloring rules run in the index pass
  (about 6% slower) instead of a second full pass. [#20]

**Packet list and navigation**

- More file types open by default: gzip/zstd/lz4-compressed pcap(ng), `.ntar`,
  `tcpdump -C` pieces, snoop, ERF, PacketLogger, btsnoop; generic extensions
  via _Reopen Editor With…_. [#10]
- Find Packet (display filter, string, hex), frame links with back/forward
  history, conversation stepping, first/last packet, marks, time display
  formats and a time reference. [#12]
- Column customisation (Apply as Column, hide, rename, reorder), cell filters
  and bytes-pane copy formats. [#12]
- Multi-select (Shift/Ctrl+click, Shift+arrows, Ctrl+A) with mark, copy and
  export of the selection. [#13]
- Addresses sort numerically; the Time column sorts by the format shown. [#13]
- Packet comments: shown on rows and above the details; edit, undo and save
  them into the pcapng. [#23]
- Name resolution for MAC addresses, IP addresses and ports
  (`pcapViewer.nameResolution.*`). [#22]
- The ☰ menu in the filter bar lists every command, greyed out with the reason
  when it can't run. [#31]
- Filter buttons under the filter bar (`pcapViewer.filterButtons`). [#32]

**Analysis**

- TLS decryption with an `SSLKEYLOGFILE` key log (`pcapViewer.tlsKeyLogFile`,
  _PCAP: Set TLS Key Log File…_). [#19]
- Coloring rules editor (_PCAP: Edit Coloring Rules_). [#21]
- Flow graph and TCP stream graphs (Stevens, throughput, RTT, window). [#23]
- VoIP calls: SIP calls with a call flow, RTP streams with loss and jitter,
  per-packet stream analysis, G.711 playback and WAV export. [#30]
- HTTP, DNS, packet length and service response time statistics. [#32]

**Capture, export and import**

- Live capture on one or more interfaces into a new unsaved capture. [#24]
- Capture editing: time shift, remove duplicates, keep a range, truncate,
  split, embed TLS keys. [#24]
- Export Packet Dissections (text, PDML, JSON). [#21]
- Merge captures, and an offer to merge a rotated capture's pieces. [#21]
- Export Objects (HTTP, SMB, TFTP, IMF, DICOM, FTP-DATA). [#22]
- Import from Hex Dump (text2pcap). [#32]

**AI (optional, through VS Code's Language Model API)**

- Display filter suggestions (✨, _PCAP: Suggest Display Filter…_, `@pcap`),
  validated by tshark; no packet data is sent. [#11]
- _Ask Copilot About This Packet…_ and `@pcap /explain`, after a one-time
  consent (`pcapViewer.ai.allowPacketData`). [#16]
- Capture summaries (`@pcap /summary`), anomaly explanations
  (`@pcap /anomaly`) and read-only `@pcap` tools, gated by
  `pcapViewer.ai.allowCaptureStatistics`. [#25]

**Setup and distribution**

- _Get Started_ walkthrough, _PCAP: Check Python and TShark_ and _PCAP: Open
  Sample Capture_. [#26]
- Icon, screenshots, Marketplace details and a release workflow. [#26]
- Remote windows (WSL, SSH, Dev Containers), captures not on disk (open a
  copy) and Restricted Mode. [#27]

### Changed

- "Since previous displayed packet" is the previous packet of the filter in
  capture order, whatever the sort. [#13]
- _Manage Coloring Rules_ became _Edit Coloring Rules_, an editor instead of
  the settings. [#21]
- Statistics always show addresses, so their row filters match. [#22]
- On narrow editors the filter bar's buttons wrap to a second line. [#31]
- CI tests with tshark on Linux, macOS and Windows [#19], on the Node 24
  versions of its actions [#21].

### Fixed

- Cancelling works when AppArmor refuses to let tshark be killed. [#14]
- tshark 4.6 output: byte tabs stay named "Frame"; statistics trees parse the
  4.4+ layout. [#14], [#32]
- Ctrl+A selected the page's text instead of the packets. [#14]
- The busy indicator kept spinning after a sort; a notice could be wiped by a
  late validation. [#16]
- The list stopped growing after scrolling to its end while indexing or
  filtering. [#20]
- A streaming filter race. [#22]
- Pipes leaked when cancelling tshark. [#28]
- Closing VS Code mid-index could save a truncated index as complete. [#29]
- A background tshark outlived the backend at shutdown. [#32]

[#10]: https://github.com/DenPaz/vsc_pcap_viewer/pull/10
[#11]: https://github.com/DenPaz/vsc_pcap_viewer/pull/11
[#12]: https://github.com/DenPaz/vsc_pcap_viewer/pull/12
[#13]: https://github.com/DenPaz/vsc_pcap_viewer/pull/13
[#14]: https://github.com/DenPaz/vsc_pcap_viewer/pull/14
[#16]: https://github.com/DenPaz/vsc_pcap_viewer/pull/16
[#17]: https://github.com/DenPaz/vsc_pcap_viewer/pull/17
[#18]: https://github.com/DenPaz/vsc_pcap_viewer/pull/18
[#19]: https://github.com/DenPaz/vsc_pcap_viewer/pull/19
[#20]: https://github.com/DenPaz/vsc_pcap_viewer/pull/20
[#21]: https://github.com/DenPaz/vsc_pcap_viewer/pull/21
[#22]: https://github.com/DenPaz/vsc_pcap_viewer/pull/22
[#23]: https://github.com/DenPaz/vsc_pcap_viewer/pull/23
[#24]: https://github.com/DenPaz/vsc_pcap_viewer/pull/24
[#25]: https://github.com/DenPaz/vsc_pcap_viewer/pull/25
[#26]: https://github.com/DenPaz/vsc_pcap_viewer/pull/26
[#27]: https://github.com/DenPaz/vsc_pcap_viewer/pull/27
[#28]: https://github.com/DenPaz/vsc_pcap_viewer/pull/28
[#29]: https://github.com/DenPaz/vsc_pcap_viewer/pull/29
[#30]: https://github.com/DenPaz/vsc_pcap_viewer/pull/30
[#31]: https://github.com/DenPaz/vsc_pcap_viewer/pull/31
[#32]: https://github.com/DenPaz/vsc_pcap_viewer/pull/32

## 0.1.0

The project brief, never published.

### Added

- Custom editor for `.pcap`/`.pcapng`/`.cap`, backed by tshark through a
  stdlib-only Python backend. [#1]
- Packet list for millions of packets: virtualized rows, backend paging and
  sorting, custom columns. [#1]
- Protocol tree and hex view with two-way highlighting, including reassembled
  data. [#1]
- Display filters with validation, autocomplete, history and saved filters.
  [#2]
- Follow TCP/UDP/TLS/HTTP stream; statistics panels (conversations, endpoints,
  protocol hierarchy, I/O graph, expert information, capture properties). [#3]
- Lua dissectors, Decode As rules and preference overrides, per workspace
  folder. [#4], [#5]
- Coloring rules and export (pcapng/pcap, CSV/JSON, packet bytes). [#6]
- tshark permission errors under AppArmor or Snap explain the fix. [#7]
- A Makefile for installs, updates, checks and packaging. [#9]

[#1]: https://github.com/DenPaz/vsc_pcap_viewer/pull/1
[#2]: https://github.com/DenPaz/vsc_pcap_viewer/pull/2
[#3]: https://github.com/DenPaz/vsc_pcap_viewer/pull/3
[#4]: https://github.com/DenPaz/vsc_pcap_viewer/pull/4
[#5]: https://github.com/DenPaz/vsc_pcap_viewer/pull/5
[#6]: https://github.com/DenPaz/vsc_pcap_viewer/pull/6
[#7]: https://github.com/DenPaz/vsc_pcap_viewer/pull/7
[#9]: https://github.com/DenPaz/vsc_pcap_viewer/pull/9
