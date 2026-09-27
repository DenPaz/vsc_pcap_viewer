@tshark
Feature: Saved indexes
  Opening a capture runs one tshark pass over the whole file to build the
  packet list. Reopening an unchanged capture reuses the saved result, unless
  anything that changes dissection changed. Closing a capture before its pass
  ends keeps the rows indexed so far: the next open shows them at once and
  goes on from there.

  Background:
    Given saved indexes are kept

  Scenario: Reopening an unchanged capture uses the saved index
    Given the capture "http.pcap" was opened before
    When I open the capture "http.pcap" again
    Then it opens from the saved index
    And the capture has 11 packets
    And applying the display filter "http" displays 2 packets

  Scenario: Filter results are saved with the index
    Given the capture "mixed.pcapng" was opened before
    And the display filter "udp" is applied
    When I open the capture "mixed.pcapng" again
    Then it opens from the saved index
    And applying the display filter "udp" uses the saved result and displays 12 packets

  Scenario: A changed key log file indexes the capture again
    Given a TLS capture and the key log file that decrypts it
    And the TLS capture was opened before with its key log file
    When the key log file gets more keys
    And I open the TLS capture with its key log file
    Then it is indexed again

  Scenario: Changing a preference indexes the capture again
    Given the capture "http.pcap" was opened before
    When I open the capture "http.pcap" again with the preference "tcp.analyze_sequence_numbers" set to "FALSE"
    Then it is indexed again

  Scenario: Without saved indexes every open indexes the capture
    Given saved indexes are not kept
    And the capture "http.pcap" was opened before
    When I open the capture "http.pcap" again
    Then it is indexed again

  Scenario: Closing a capture while it is indexed keeps its progress for the next open
    Given the index pass is slow
    And the capture "http.pcap" was closed while it was being indexed
    Then an unfinished index of fewer than 11 packets is saved
    When I open the capture "http.pcap" again as a stream
    Then the packets indexed before are shown at once, while the capture is read again
    When indexing finishes
    Then indexing caught up with the packets shown before, then went on
    And the capture has 11 packets
    And the packet list is the same as after a full index
    And the saved index is finished
