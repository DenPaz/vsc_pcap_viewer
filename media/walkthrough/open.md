# Open a capture

Captures open in the viewer like any other file: from the Explorer,
**File › Open File…**, or by dragging a file onto the editor.

- **pcap** and **pcapng**, also compressed (`.gz`, `.zst`, `.lz4`), tcpdump
  rotation files (`trace.pcap1`…), snoop, ERF, PacketLogger and btsnoop.
- Files with generic extensions (`.log`, `.dmp`, `.trc`…) open through
  **Reopen Editor With… › PCAP Viewer**.
- Big captures show their first packets within about half a second while
  the rest is indexed; reopening them later is instant.

The sample capture has ARP, ICMP, DNS and an HTTP request split over two TCP
segments. Try:

- clicking a packet to see its **protocol tree** and **bytes** (select a field
  to highlight its bytes, or click a byte to find its field);
- right-clicking a packet for **Follow TCP Stream**, **Mark**, **Apply as
  Filter** and more.

No capture yet? **PCAP: Start Capture…** records one live.
