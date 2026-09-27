@tshark
Feature: TLS decryption with a key log file
  Browsers and curl write the secrets of their TLS sessions to the file named
  by SSLKEYLOGFILE. Given that file (pcapViewer.tlsKeyLogFile, passed to
  tshark as the tls.keylog_file preference), the viewer shows what the TLS
  sessions carry.

  Background:
    Given a TLS capture and the key log file that decrypts it

  Scenario: Without the key log the traffic stays encrypted
    When I open the TLS capture
    Then applying the display filter "http" displays 0 packets
    And applying the display filter "tls.app_data" displays 2 packets

  Scenario: With the key log the HTTP inside TLS is shown
    When I open the TLS capture with its key log file
    Then there are no warnings
    And applying the display filter "http" displays 2 packets
    And applying the display filter "http.response.code == 200" displays 1 packets

  Scenario: A key log file that doesn't exist is reported
    When I open the TLS capture with the key log file "missing.log"
    Then a warning mentions "Key log file not found"
    And applying the display filter "http" displays 0 packets
