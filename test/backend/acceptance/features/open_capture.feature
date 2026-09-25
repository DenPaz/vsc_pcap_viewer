@tshark
Feature: Opening capture files
  Opening a .pcap or .pcapng file indexes every packet once, so the packet
  list can be shown without freezing the UI (brief 4.1, acceptance criterion 1).

  Scenario: Open a pcap file
    When I open the capture "http.pcap"
    Then the capture has 11 packets
    And the link type is "ether"
    And the capture starts at 1700000000.0
    And there are no warnings

  Scenario: Open a pcapng file
    When I open the capture "mixed.pcapng"
    Then the capture has 26 packets
    And the "Protocol" column of rows 1 to 3 is ARP, ICMP and ICMP

  Scenario: A truncated capture is still usable
    When I open the capture "truncated.pcap"
    Then the capture has 10 packets
    And a warning mentions "cut short"

  Scenario: A missing file is reported clearly
    When I open the capture "does-not-exist.pcap"
    Then the request fails with "not found"

  Scenario: An unknown custom column is dropped with a warning
    Given the custom columns "tcp.stream" and "no.such.field"
    When I open the capture "http.pcap"
    Then a warning mentions "no.such.field"
    And the columns end with "tcp.stream"
