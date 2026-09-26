@tshark
Feature: Dissector customisation
  Decode As rules and Lua dissectors change how every tshark call dissects
  the capture (brief 4.7, acceptance criteria 7 and 8).

  Scenario: Decode As maps a port to a protocol
    Given the Decode As rule "udp.port==9999,syslog"
    When I open the capture "udp_custom.pcap"
    Then the "Protocol" column of row 1 is "Syslog"

  Scenario: A malformed Decode As rule is refused
    Given the Decode As rule "-Y,x"
    When I open the capture "http.pcap"
    Then the request fails with "invalid Decode As rule"

  @lua
  Scenario: A Lua dissector decodes a custom protocol
    Given the Lua dissector "backend/dissectors/example.lua"
    When I open the capture "udp_custom.pcap"
    Then the "Protocol" column of row 1 is "EXAMPLE"
    And applying the display filter "example.type == 2" displays 2 packets

  Scenario: A missing Lua script is reported
    Given the Lua dissector "backend/dissectors/missing.lua"
    When I open the capture "udp_custom.pcap"
    Then a warning mentions "Lua script not found"
