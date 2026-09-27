@tshark
Feature: Counting for the AI tools
  The language model tools count packets for a display filter without
  changing what the viewer shows.

  Scenario: Counting doesn't replace the viewer's filter
    Given the capture "mixed.pcapng" is open
    And the display filter "icmp" is applied
    When I count the packets matching "dns"
    Then 6 of 26 packets match
    And 2 packets are displayed

  Scenario: An invalid filter is rejected before counting
    Given the capture "mixed.pcapng" is open
    When I count the packets matching "dns.qry.name =="
    Then the filter is rejected with an error
