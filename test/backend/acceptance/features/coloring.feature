@tshark
Feature: Coloring rules
  Coloring rules are display filters evaluated by tshark in one pass; the
  first matching rule colors a packet (brief 4.2 "Color rules").

  Background:
    Given the capture "mixed.pcapng" is open

  Scenario: The first matching rule wins
    When I set the coloring rules "dns", "udp" and "tcp"
    Then the "DNS" packets are colored by rule 1
    And the "UDP" packets are colored by rule 2
    And the "HTTP" packets are colored by rule 3
    And the "ARP" packets are not colored

  Scenario: A rule that does not compile is reported and skipped
    When I set the coloring rules "nosuch.field" and "icmp"
    Then coloring rule 1 is reported as invalid
    And the "ICMP" packets are colored by rule 2

  Scenario: Coloring can be turned off
    Given the coloring rules "tcp" are set
    When I clear the coloring rules
    Then no packet is colored
