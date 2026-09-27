@tshark
Feature: Live capture
  Packets captured live show up in the packet list as they arrive, and the
  capture is a pcapng file that stays readable while it grows. A stand-in
  dumpcap replays a capture file, so no capture rights are needed.

  Scenario: Capture until stopped
    Given a stand-in dumpcap that replays "mixed.pcapng"
    When I start capturing on "fake0" with the capture filter "ip"
    Then the capture is running
    And packets appear in the list while capturing
    When I stop the capture
    Then the capture stops with a complete file
    And sorting works again

  Scenario: A packet limit stops the capture
    Given a stand-in dumpcap that replays "mixed.pcapng"
    When I start capturing on "fake0" stopping after 5 packets
    Then the capture stops by itself with 5 packets

  Scenario: Capturing without permission explains how to allow it
    Given a stand-in dumpcap without permission to capture
    When I start capturing on "fake0"
    Then the request fails with "don't have permission"
    And no tshark process is left running

  Scenario: Capture filters are checked before capturing
    Given a stand-in dumpcap that replays "mixed.pcapng"
    Then the capture filter "tcp port 80" is valid for "fake0"
    And the capture filter "invalid filter" is invalid for "fake0"
