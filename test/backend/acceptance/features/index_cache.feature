@tshark
Feature: Saved indexes
  Opening a capture runs one tshark pass over the whole file to build the
  packet list. Reopening an unchanged capture reuses the saved result, unless
  anything that changes dissection changed.

  Background:
    Given saved indexes are kept

  Scenario: Reopening an unchanged capture uses the saved index
    Given the capture "http.pcap" was opened before
    When I open the capture "http.pcap" again
    Then it opens from the saved index
    And the capture has 11 packets
    And applying the display filter "http" displays 2 packets

  Scenario: Changing a preference indexes the capture again
    Given the capture "http.pcap" was opened before
    When I open the capture "http.pcap" again with the preference "tcp.analyze_sequence_numbers" set to "FALSE"
    Then it is indexed again

  Scenario: Without saved indexes every open indexes the capture
    Given saved indexes are not kept
    And the capture "http.pcap" was opened before
    When I open the capture "http.pcap" again
    Then it is indexed again
