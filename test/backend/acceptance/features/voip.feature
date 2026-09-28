@tshark
Feature: VoIP calls
  The VoIP panel lists a capture's SIP calls and RTP streams, analyses a
  stream packet by packet (jitter, delta, lost packets) and saves or plays
  its G.711 audio.

  Background:
    Given the capture "voip.pcap" is open

  Scenario: SIP calls and their RTP streams
    When I list the VoIP calls
    Then there are 2 SIP calls and 2 RTP streams
    And call 1 goes from "alice@10.0.0.1" to "bob@10.0.0.2" and is Completed
    And call 1 has the messages INVITE (SDP), 100 Trying, 180 Ringing, 200 OK (SDP), ACK, BYE and 200 OK
    And call 1 has both RTP streams
    And call 2 goes from "carol@10.0.0.3" to "bob@10.0.0.2" and is Rejected with "486 Busy Here"
    And the RTP stream from "10.0.0.1:40000" has 49 packets and 1 lost

  Scenario: The analysis of an RTP stream
    When I analyse the RTP stream from "10.0.0.1:40000"
    Then the analysis counts 49 of 50 packets with 1 lost
    And its maximum and mean jitter are those of tshark's RTP streams report
    And packet 48 comes after 1 lost packet

  Scenario: Saving a stream's audio
    When I save the audio of the RTP stream from "10.0.0.2:50000"
    Then the file is 1 second of 8000 Hz WAV audio with a 880 Hz tone

  Scenario: A stream's filter shows its packets
    When I list the VoIP calls
    And I apply the filter of the RTP stream from "10.0.0.2:50000"
    Then 50 packets are displayed
