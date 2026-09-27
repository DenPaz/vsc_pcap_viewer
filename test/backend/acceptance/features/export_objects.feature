@tshark
Feature: Export Objects
  Files carried by HTTP, SMB, TFTP, IMF (mail), DICOM and FTP-DATA are listed
  with the packet that carried them, and saved as the files they were.

  Scenario: Objects are listed with the packets that carried them
    Given the capture "objects.pcap" is open
    When I list the exported objects
    Then the objects are logo.png, report, upload, dup.txt, dup(1).txt, config.bin and Test report.eml
    And the object "logo.png" came in packet 6 from "example.com" as "image/png"
    And the object "dup(1).txt" came in packet 22
    And the object "config.bin" came in packet 27
    And the object "Test report.eml" came in packet 53

  Scenario: Saving every object never overwrites a file
    Given the capture "objects.pcap" is open
    And the folder for saved objects already has a file "report"
    When I list the exported objects
    And I save every object into the folder
    Then the folder has logo.png, report, report (1), upload, dup.txt, dup(1).txt, config.bin and Test report.eml

  Scenario: A capture without objects
    Given the capture "dns.pcap" is open
    When I list the exported objects
    Then there are no objects
