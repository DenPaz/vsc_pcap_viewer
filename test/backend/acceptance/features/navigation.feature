@tshark
Feature: Navigating a capture
  Find Packet, conversation stepping, time display formats and marked-packet
  export work on the current view: its display filter and sort order.

  Background:
    Given the capture "mixed.pcapng" is open

  Scenario Outline: Find the next matching packet
    When I find the next packet matching the <mode> "<value>"
    Then the found packet is <frame>

    Examples:
      | mode           | value      | frame |
      | display filter | dns        | 4     |
      | string         | INDEX.HTML | 13    |
      | hex bytes      | 47:45:54   | 13    |
      | hex bytes      | 474554     | 13    |

  Scenario: A case-sensitive string search
    When I find the next packet matching the string "INDEX.HTML" case-sensitively
    Then no packet is found

  Scenario: Find wraps around after the last match
    When I find the next packet matching the display filter "dns" after packet 9
    Then the found packet is 4
    And the search wrapped around

  Scenario: Find looks only at the displayed packets, in their order
    Given the display filter "udp" is applied
    When I sort by "Length" descending
    And I find the next packet matching the display filter "dns"
    Then the found packet is 7

  Scenario: An invalid search is reported
    When I find the next packet matching the display filter "tcp.port =="
    Then the filter is rejected with an error

  Scenario Outline: Step through a conversation
    When I step to the <direction> packet in the conversation of packet <from>
    Then the found packet is <to>

    Examples:
      | direction | from | to |
      | next      | 4    | 5  |
      | next      | 10   | 11 |
      | previous  | 20   | 19 |
      | next      | 2    | 3  |

  Scenario: No next packet at the end of a conversation
    When I step to the next packet in the conversation of packet 5
    Then no packet is found

  Scenario Outline: Time display formats
    When I show times as "<format>"
    Then the time of packet <frame> is "<time>"

    Examples:
      | format         | frame | time                       |
      | relative       | 5     | 0.008000                   |
      | delta_captured | 5     | 0.002000                   |
      | epoch          | 1     | 1700000000.000000          |
      | utc            | 1     | 2023-11-14 22:13:20.000000 |

  Scenario: "Since previous displayed packet" is measured within the filter, whatever the sort
    Given the display filter "dns || frame.number == 1 || frame.number == 20" is applied
    When I sort by "Length" descending
    And I show times as "delta_displayed"
    Then the time of packet 1 is "0.000000"
    And the time of packet 4 is "0.006000"
    And the time of packet 5 is "0.002000"
    And the time of packet 20 is "0.022000"

  Scenario: The Time column sorts by the time format shown
    Given the display filter "dns || frame.number == 1 || frame.number == 20" is applied
    And I show times as "delta_displayed"
    When I sort by "Time" descending
    Then the rows are frames 20, 4, 5, 6, 7, 8, 9 and 1

  Scenario: Addresses sort numerically, not as text
    When I sort by "Source" ascending
    Then the "Source" column of rows 1 to 4 is 8.8.8.8, 8.8.8.8, 8.8.8.8 and 10.0.0.1
    And the "Source" column of row 26 is "02:00:00:00:00:01"

  Scenario: Times relative to a time reference
    Given packet 4 is the time reference
    When I show times as "relative"
    Then the time of packet 4 is "*REF*"
    And the time of packet 5 is "0.002000"
    And the time of packet 1 is "-0.006000"

  Scenario: Export the marked packets
    Given packets 1, 3 and 5 are marked
    When I export the marked packets as pcapng
    Then the exported capture is a pcapng file with 3 packets
