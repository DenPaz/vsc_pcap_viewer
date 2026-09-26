@tshark
Feature: Display filters
  Filters use Wireshark's syntax via tshark -Y. Invalid filters are reported
  and never applied (brief 4.4, acceptance criterion 3).

  Background:
    Given the capture "http.pcap" is open

  Scenario: A valid filter narrows the packet list
    When I apply the display filter "http"
    Then 2 packets are displayed
    And the displayed frames are 4 and 7

  Scenario: An invalid filter is rejected and the view is kept
    Given the display filter "http" is applied
    When I apply the display filter "tcp.port =="
    Then the filter is rejected with an error
    And 2 packets are displayed

  Scenario Outline: Filter validation
    When I validate the display filter "<filter>"
    Then the filter is <result>

    Examples:
      | filter                          | result  |
      | tcp.port == 80                  | valid   |
      | ip.src == 192.168.1.10 && http  | valid   |
      | tcp.port ==                     | invalid |
      | ip.src == 1.2.3                 | invalid |

  Scenario: A filter with no matches
    When I apply the display filter "dns"
    Then 0 packets are displayed

  Scenario: Clearing the filter restores all packets
    Given the display filter "http" is applied
    When I clear the display filter
    Then 11 packets are displayed

  Scenario: A cancelled filter leaves no tshark process behind
    When I apply the display filter "tcp" and cancel it
    Then the request is cancelled
    And no tshark process is left running
