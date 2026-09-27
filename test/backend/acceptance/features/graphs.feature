@tshark
Feature: Flow graph and TCP stream graphs
  The flow graph draws the displayed packets as arrows between their
  endpoints; the TCP stream graphs plot one TCP stream's segments.

  Scenario: The flow graph follows the display filter
    Given the capture "mixed.pcapng" is open
    When I request the flow graph
    Then the flow graph has 26 packets between 8 endpoints
    And the first endpoints of the flow graph are "02:00:00:00:00:01", "Broadcast" and "192.168.1.10"
    Given the display filter "dns" is applied
    When I request the flow graph
    Then the flow graph has 6 packets between 2 endpoints

  Scenario: The TCP stream graph of a packet
    Given the capture "http.pcap" is open
    When I request the TCP stream graph of packet 4
    Then the TCP stream graph shows stream 0 between "192.168.1.10:50000" and "93.184.216.34:80" with 11 packets
