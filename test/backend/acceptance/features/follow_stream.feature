@tshark
Feature: Follow stream
  Following a stream shows the reassembled payload of a conversation, split
  by direction, from any packet in it (brief 4.5, acceptance criterion 5).

  Scenario: Follow a TCP stream from a selected packet
    Given the capture "http.pcap" is open
    When I follow the "tcp" stream of packet 4
    Then the followed stream is number 0 between "192.168.1.10:50000" and "93.184.216.34:80"
    And the client sent 90 bytes and the server sent 491 bytes
    And the client data starts with "GET /index.html HTTP/1.1"
    And the server data starts with "HTTP/1.1 200 OK"
    And the stream filter is "tcp.stream eq 0"

  Scenario: Follow a UDP stream
    Given the capture "dns.pcap" is open
    When I follow the "udp" stream of packet 1
    Then the client sent 29 bytes and the server sent 56 bytes

  Scenario: Follow an HTTP stream by number
    Given the capture "http.pcap" is open
    When I follow "http" stream number 0
    Then the server data starts with "HTTP/1.1 200 OK"

  Scenario: A packet outside any TCP stream
    Given the capture "mixed.pcapng" is open
    When I follow the "tcp" stream of packet 1
    Then the request fails with "not part of a TCP stream"

  Scenario: TLS without keys explains why nothing is shown
    Given the capture "tls.pcap" is open
    When I follow the "tls" stream of packet 4
    Then the followed stream is empty
    And the follow hint mentions "tls.keylog_file"
