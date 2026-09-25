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

  Scenario: Selecting a packet outside the capture fails
    When I select packet 12
    Then the request fails with "out of range"
