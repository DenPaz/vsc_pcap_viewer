@tshark
Feature: Packet list paging, sorting and custom columns
  The backend serves slices of the current view from its cache, so scrolling
  never re-runs tshark (brief 4.2, acceptance criteria 2 and 8).

  Background:
    Given the capture "http.pcap" is open

  Scenario: Fetch a page from the middle of the list
    When I request 3 packets starting at row 2
    Then the rows are frames 3, 4 and 5
    And the "Protocol" column of row 2 is "HTTP"
    And the "Info" column of row 2 starts with "GET /index.html HTTP/1.1"

  Scenario: A page past the end is empty
    When I request 10 packets starting at row 50
    Then no rows are returned

  Scenario: Sort by a column
    When I sort by "Length" descending
    Then the "Length" column of rows 1 to 3 is 345, 254 and 144

  Scenario: Sorting applies to the filtered view
    Given the display filter "tcp.len == 0" is applied
    When I sort by "No." descending
    Then the rows are frames 11, 10, 9, 8, 5, 3, 2 and 1

  Scenario: Custom columns are extracted on demand
    When I request 1 packet starting at row 3 with the custom columns "http.host" and "tcp.stream"
    Then the custom column values are "example.com" and "0"
