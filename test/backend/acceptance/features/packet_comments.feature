@tshark
Feature: Packet comments
  pcapng packets can carry comments. The viewer shows them, edits them (the
  edits stay unsaved until the capture is saved) and saves them with editcap,
  into the capture itself when it is pcapng, else as a new pcapng file.

  Scenario: Comments in the file are shown
    Given the capture "comments.pcapng" is open
    Then packet 2 has the comment "SYN-ACK from the server"
    And packet 4 has the comment "The request\nsecond line	with a tab"
    And packet 1 has no comment

  Scenario: Edits are saved into the capture
    Given a copy of the capture "comments.pcapng" is open
    When I set the comment of packet 1 to "first packet"
    And I delete the comment of packet 2
    Then packet 1 has the comment "first packet"
    And packet 2 has no comment
    When I save the comments into the capture
    Then the saved file has comments on packets 1, 4 and 5
    And packet 1 has the comment "first packet"

  Scenario: A pcap capture gets its comments in a new pcapng file
    Given a copy of the capture "http.pcap" is open
    Then saving the comments into the capture is refused with "pcapng"
    When I set the comment of packet 3 to "handshake done"
    And I save the comments as a new file
    Then the saved file has comments on packets 3
