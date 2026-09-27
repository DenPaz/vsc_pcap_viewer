@tshark
Feature: Name resolution
  The packet list and details can show names instead of addresses and port
  numbers (pcapViewer.nameResolution.*): MAC vendor and well-known names, host
  names from the capture's own DNS answers and hosts files, and service names
  for ports. Cell filters get the addresses behind the names, and statistics
  always show addresses, since their rows become filters.

  Scenario: Host and service names
    Given name resolution of MAC addresses, network addresses, the capture's DNS answers and transport ports
    When I open the capture "mixed.pcapng"
    Then the "Source" column of row 11 is "example.com"
    And the address behind the "Source" column of row 11 is "93.184.216.34"
    And the "Info" column of row 11 starts with "http(80) → 50000"
    And the "Destination" column of row 1 is "Broadcast"
    And the address behind the "Destination" column of row 1 is "ff:ff:ff:ff:ff:ff"
    And no address is sent for row 26
    And the details of packet 11 mention "Src: example.com (93.184.216.34)"

  Scenario: Without name resolution
    Given no name resolution
    When I open the capture "mixed.pcapng"
    Then the "Source" column of row 11 is "93.184.216.34"
    And the "Destination" column of row 1 is "ff:ff:ff:ff:ff:ff"
    And the "Info" column of row 11 starts with "80 → 50000"

  Scenario: Statistics keep the addresses
    Given name resolution of MAC addresses and network addresses
    And the capture "mixed.pcapng" is open
    When I request the "endpoints" statistics for "eth"
    Then the statistics column "Address" includes "ff:ff:ff:ff:ff:ff" but not "Broadcast"
