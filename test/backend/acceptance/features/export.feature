@tshark
Feature: Export
  Filtered packets are written to a new capture file by tshark; the packet
  list and a packet's bytes come from the backend's own data (brief 4.8,
  acceptance criterion "Export filtered packets to pcapng works").

  Background:
    Given the capture "http.pcap" is open

  Scenario: Export the displayed packets to pcapng
    Given the display filter "http" is applied
    When I export the displayed packets as pcapng
    Then the exported capture is a pcapng file with 2 packets
    And the export reports 2 packets

  Scenario: Export every packet whatever the display filter
    Given the display filter "http" is applied
    When I export all packets as pcap
    Then the exported capture is a pcap file with 11 packets

  Scenario: Export the packet list as CSV
    Given the display filter "tcp.port == 80" is applied
    When I export the packet list as CSV
    Then the exported CSV has the columns No., Time, Source, Destination, Protocol, Length and Info
    And the exported CSV has 11 rows

  Scenario: Export the packet list as JSON
    Given the display filter "http" is applied
    When I export the packet list as JSON
    Then the exported JSON lists the frames 4 and 7

  Scenario: Export a packet's bytes
    When I export the bytes of packet 4
    Then the exported file has 144 bytes

  Scenario: The open capture is never overwritten
    When I export the displayed packets over the open capture
    Then the export is refused
