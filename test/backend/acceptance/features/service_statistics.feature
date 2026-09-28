@tshark
Feature: Service statistics
  HTTP, DNS, packet length and service response time reports come from
  tshark's stats trees and SRT taps; rows that stand for a set of packets
  carry a display filter that selects exactly those packets.

  Background:
    Given the capture "services.pcap" is open

  Scenario: HTTP packet counter by status code and method
    When I request the "http" statistics
    Then the statistics row "Total HTTP Packets" has "Count" 8
    And the statistics row "404 Not Found" below "4xx: Client Error" has "Count" 1
    And the statistics row "GET" below "HTTP Request Packets" has "Count" 3
    And the filter of the statistics row "404 Not Found" matches 1 packet
    And the filter of the statistics row "3xx: Redirection" matches 1 packet
    And the filter of the statistics row "POST" matches 1 packet

  Scenario: HTTP requests by host and URI
    When I request the "http" statistics for "requests"
    Then the statistics row "example.com" has "Count" 3
    And the statistics row "/v1/items" below "api.example.net" has "Count" 1
    And the filter of the statistics row "example.com" matches 3 packets
    And the filter of the statistics row "/missing.png" matches 1 packet

  Scenario: HTTP load distribution by server
    When I request the "http" statistics for "load"
    Then the statistics row "93.184.216.34" below "HTTP Requests by Server Address" has "Count" 3
    And the filter of the statistics row "Error" below "93.184.216.34" matches 1 packet
    And the filter of the statistics row "OK" below "93.184.216.34" matches 2 packets

  Scenario: DNS statistics
    When I request the "dns" statistics
    Then the statistics row "No such name" below "rcode" has "Count" 1
    And the statistics row "AAAA" below "Query Type" has "Count" 2
    And the filter of the statistics row "AAAA" matches 2 packets
    And the filter of the statistics row "No such name" matches 1 packet
    And the filter of the statistics row "Query" below "Query/Response" matches 4 packets

  Scenario: Packet lengths
    When I request the "plen" statistics
    Then the statistics row "Packet Lengths" has "Count" 61
    And the filter of the statistics row "40-79" matches 45 packets
    And the filter of the statistics row "80-159" matches 16 packets

  Scenario: Service response time picks a protocol with traffic
    When I request the "srt" statistics
    Then the service response time is for "icmp", out of icmp and snmp
    And row 1 has "Requests" 3, "Replies" 2 and "Lost" 1

  Scenario: SNMP service response time per procedure
    When I request the "srt" statistics for "snmp"
    Then the statistics row "Get" has "Calls" 3
    And the statistics row "GetNext" has "Calls" 1
    And the filter of the statistics row "Get" matches 3 packets

  Scenario: A protocol without a response time report is rejected
    When I request the "srt" statistics for "http"
    Then the request fails with "type must be auto or one of"
