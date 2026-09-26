@tshark
Feature: Packet detail and bytes
  Selecting a packet returns its protocol tree with byte ranges, so the UI can
  highlight a field's bytes and find the field for a byte (brief 4.3,
  acceptance criterion 4).

  Background:
    Given the capture "http.pcap" is open

  Scenario: Protocol tree of an HTTP request
    When I select packet 4
    Then the protocol tree is frame, eth, ip, tcp and http
    And the packet has the byte sources "Frame"
    And the field "ip.src" covers the bytes c0 a8 01 0a

  Scenario: Reassembled data gets its own byte source
    When I select packet 7
    Then the packet has the byte sources "Frame" and "Reassembled TCP"
    And the "http" protocol is in the byte source "Reassembled TCP"
    And the "http" protocol bytes start with "HTTP/1.1 200 OK"

  Scenario: A quick view dissects only a window of packets before the selected one
    When I request the quick view of packet 11 with a window of 10 packets
    Then the detail is approximate, dissected from packet 2
    And the field "frame.number" shows "11"
    And the field "tcp.analysis.acks_frame" shows "10"

  Scenario: A quick view loses references to packets before its window
    When I request the quick view of packet 7 with a window of 2 packets
    Then the detail is approximate, dissected from packet 6
    And the tree has no field "http.request_in"

  Scenario: Selecting a packet outside the capture fails
    When I select packet 12
    Then the request fails with "out of range"
