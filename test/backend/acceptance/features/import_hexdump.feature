@tshark
Feature: Import from Hex Dump
  text2pcap turns a hex dump into a capture: frames as Wireshark copies them,
  payloads behind a dummy header, raw IP packets with times. No capture needs
  to be open.

  Scenario: Frames copied from Wireshark
    When I import the hex dump "frames.txt"
    Then the import wrote 11 packets
    When I open the imported capture
    Then the capture has 11 packets
    And the "Protocol" column of row 4 is "HTTP"
    And the "Info" column of row 4 starts with "GET /index.html"

  Scenario: The dump given as text instead of a file
    When I import the text of the hex dump "frames.txt"
    Then the import wrote 11 packets

  Scenario: Payloads behind a dummy UDP header
    When I import the hex dump "sip-payload.txt" with header udp, srcPort 5060, dstPort 5060, srcIp 10.0.0.1 and dstIp 10.0.0.2
    Then the import wrote 2 packets
    When I open the imported capture
    Then the "Protocol" column of row 1 is "SIP"
    And the "Source" column of row 1 is "10.0.0.1"
    And the "Info" column of row 2 starts with "Status: 200 OK"

  Scenario: Raw IPv4 packets with a time before each
    When I import the hex dump "timed-ipv4.txt" with linkType 101 and timestamp %H:%M:%S.%f
    Then the import wrote 2 packets
    When I open the imported capture
    Then the "Protocol" column of row 1 is "DNS"
    And the "Time" column of row 2 is "1.000000000"

  Scenario: Text without a hex dump writes nothing
    When I import the text "this is not a hex dump"
    Then the request fails with "no packets found in the hex dump"
    And no imported capture was written

  Scenario: Invalid dummy header options are rejected
    When I import the hex dump "sip-payload.txt" with header udp, srcIp 10.0.0.1 and dstIp ::1
    Then the request fails with "must both be IPv4 or both IPv6"
