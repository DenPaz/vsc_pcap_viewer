@tshark
Feature: Capture file types
  Besides pcap and pcapng the viewer opens compressed captures and the other
  formats tshark reads, whatever the file is called: tshark recognises the
  format from the content. The files are the same packets as the other
  fixtures, written in each format by test/fixtures/generate.py.

  Scenario Outline: Open a <kind>
    When I open the capture "formats/<file>"
    Then the capture has <packets> packets
    And the "Protocol" column of row 1 is "<protocol>"

    Examples: default editor (unambiguous capture files)
      | kind                        | file             | packets | protocol |
      | gzip-compressed pcap        | http.pcap.gz     | 11      | TCP      |
      | gzip-compressed pcapng      | mixed.pcapng.gz  | 26      | ARP      |
      | zstd-compressed pcap        | http.pcap.zst    | 11      | TCP      |
      | zstd-compressed pcapng      | mixed.pcapng.zst | 26      | ARP      |
      | lz4-compressed pcap         | http.pcap.lz4    | 11      | TCP      |
      | lz4-compressed pcapng       | mixed.pcapng.lz4 | 26      | ARP      |
      | pcapng with .ntar extension | mixed.ntar       | 26      | ARP      |
      | tcpdump -C rotated file     | trace.pcap1      | 6       | DNS      |
      | Sun snoop file              | http.snoop       | 11      | TCP      |
      | Endace ERF file             | http.erf         | 11      | TCP      |
      | macOS PacketLogger log      | hci.pklg         | 4       | HCI_CMD  |
      | btsnoop Bluetooth log       | hci.btsnoop      | 4       | HCI_CMD  |

    Examples: "Reopen Editor With…" only (generic extensions)
      | kind                        | file             | packets | protocol |
      | numbered rotation file      | capture.1        | 11      | TCP      |
      | capture named .log          | capture.log      | 26      | ARP      |
      | capture named .dmp          | capture.dmp      | 11      | TCP      |
      | snoop capture named .trc    | capture.trc      | 11      | TCP      |
      | raw ASN.1 BER file          | capture.ber      | 1       | BER      |

  Scenario: Progress is estimated for an uncompressed pcap, whatever its name
    When I open the capture "formats/trace.pcap1"
    Then the open progress is estimated

  Scenario Outline: Progress is indeterminate when file size says nothing
    When I open the capture "formats/<file>"
    Then the open progress is indeterminate

    Examples:
      | file          |
      | http.pcap.gz  |
      | http.pcap.zst |
      | http.snoop    |

  Scenario: A file that is not a capture is reported clearly
    When I open the capture "formats/notes.log"
    Then the request fails because "notes.log" is not a capture file
