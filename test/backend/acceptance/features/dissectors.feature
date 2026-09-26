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

  @lua
  Scenario: Lua syntax errors are reported by the dissector check
    Given a Lua dissector with a syntax error
    When I check the dissectors
    Then a dissector error mentions "syntax error" for that script

  Scenario: The dissector check reports missing scripts
    Given the Lua dissector "backend/dissectors/missing.lua"
    When I check the dissectors
    Then there are no dissector errors
    And a dissector warning mentions "Lua script not found"

  Scenario: Decode As offers tshark's layer types
    When I ask which layers can be decoded as another protocol
    Then the choices include "tcp.port" described as "TCP port"
    And the choices include "udp.port"

  Scenario: Decode As offers the protocols valid for a layer
    When I ask which protocols "tcp.port" can be decoded as
    Then the choices include "http" described as "Hypertext Transfer Protocol"

  Scenario: Decode As rejects an unknown layer
    When I ask which protocols "no.such.layer" can be decoded as
    Then the request fails with "unknown layer type"
