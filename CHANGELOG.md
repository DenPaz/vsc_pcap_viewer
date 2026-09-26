# Changelog

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
