@tshark
Feature: Capture editing
  An edited copy of the whole capture (editcap), written as a new pcapng
  file; the open capture is never changed.

  Scenario: Shift every packet's timestamp
    Given the capture "mixed.pcapng" is open
    When I shift the capture's time by "-3600.5"
    Then the edited capture has 26 packets
    And the edited capture starts at 1699996399.5

  Scenario: Keep a range of packets
    Given the capture "mixed.pcapng" is open
    When I keep the packets "1-10, 20-"
    Then the edited capture has 17 packets

  Scenario: Remove duplicate packets
    Given the capture "mixed.pcapng" merged with itself is open
    When I remove the duplicate packets
    Then 26 duplicates were removed
    And the edited capture has 26 packets

  Scenario: Split a capture into pieces
    Given the capture "mixed.pcapng" is open
    When I split the capture every 10 packets
    Then it is split into files of 10, 10 and 6 packets
