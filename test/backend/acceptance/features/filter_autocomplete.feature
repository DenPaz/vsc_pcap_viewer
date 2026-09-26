@tshark
Feature: Display filter autocomplete
  Suggestions come from tshark's own field list (tshark -G fields), including
  fields added by Lua dissectors, and show each field's type and description
  (brief 4.4, acceptance criterion 3).

  Scenario: Fields are suggested for a prefix
    When I ask for filter suggestions for "ip.sr"
    Then the field suggestions include "ip.src" of type "FT_IPv4"
    And the field suggestions include "ip.src_host"
    And every suggestion starts with "ip.sr"
    And the first field suggestion has a description

  Scenario: Protocols are suggested
    When I ask for filter suggestions for "htt"
    Then the protocol suggestions include "http"

  Scenario: Suggestions ignore case
    When I ask for filter suggestions for "IP.SR"
    Then the field suggestions include "ip.src" of type "FT_IPv4"

  Scenario: Long suggestion lists are capped
    When I ask for 10 filter suggestions for "tcp."
    Then there are 10 field suggestions
    And the suggestions are marked as truncated

  Scenario: Nothing matches
    When I ask for filter suggestions for "no.such.prefix"
    Then there are 0 field suggestions

  @lua
  Scenario: Lua dissector fields are suggested
    Given the Lua dissector "backend/dissectors/example.lua"
    And I open the capture "udp_custom.pcap"
    When I ask for filter suggestions for "example."
    Then the field suggestions include "example.type" of type "FT_UINT8"

  Scenario: Suggestions still work when dissection options are configured
    Given the Decode As rule "udp.port==9999,syslog"
    And I open the capture "udp_custom.pcap"
    When I ask for filter suggestions for "ip.sr"
    Then the field suggestions include "ip.src" of type "FT_IPv4"
