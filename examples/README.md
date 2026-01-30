# Examples

This folder contains example scenarios to demostrate *bespokebpv7* in use.

## Process a PCAP file

Wireshark has great capability to dissect bundles, but when there many bundles to parse
 or a bundle block does not yet have a Wireshark dissector, *bespokebpv7* offers a
 method to extract and parse bundles captured in a PCAP file.

*pcap_parse.py* demonstrates how to extract and parse bundles captured in *test.pcap*.
 The example script takes the path to the PCAP file and it prints the time the bundle
 was recorded and quick look information on the bundle. This script can handle bundles
 mixed with non-DTN traffic, but it will only extract bundles sent over UDP. The format
 of the PCAP file is also important. Wireshark defaults to saving captures as PCAP Next
 Generation (PCAPNG) files, but the underlying library that supports the parsing,
 *dpkt*, cannot parse those files, so any captures need to saved as PCAP files.

## Simplify Unit Tests

Some unit tests may just require sending a bundle to verify functionality. Setting up
 an entire DTN network is tedious and really overkill just to verify a sent bundle is
 received and processed correctly. *bespokebpv7* can simplify the setup of these sorts
 of tests by providing the sending portion of the test. Another test may require
 verification of bundle format. Instead of capturing a command line utility's output
 and creating a bash function to parse it, *bespokebpv7* can receive a bundle and look
 at is assorted parameters directly.

*issue-265-bpdriver-ttl-option* is regression test within ION, but it is not run
 currently as it is reliant on finding bytes within captured bundles specific to BPv6.
 This example restores it to the test suite and updates it, so it can easily parse the
 bundle without a bunch of bash commands processing binary data. In limited testing
 with ION 3.7.4 version (last full BPv6), this test took ~25 seconds and with the new
 updated test it took ~11 seconds. Some of this can be attributed to improvements in
 ION cleanup, but using *bespokebpv7* halves the test time. If other tests can be
 improved with *bespokebpv7*, this could drastically cut down the regression suite
 execution time.

*status-rpts* is a regression test within ION that requires a three node setup. This
 example demonstrates reducing the number of ION nodes down to one and having
 *bespokebpv7* send and receive bundles. In limited testing with ION 4.1.4-b.3, this
 test took ~29 seconds and with the updated test it took ~15 seconds. By cutting down
 the number of nodes and eliminating the need for most of the ION receiver utilities,
 the test time has been halved. A note on the test setup, the different status flag
 tests needed to be combined into one for loop due issue with Python networking. If
 each test was run one at a time, it is possible the Python receiver would miss one of
 the status reports because the receive socket had be torn down and created again. One
 loop for all the tests eliminated the issue. Using a JSON file was deemed as the
 simplest method to pass a Python dict to the Python script, though hardcoding it in
 the Python script is another possibility.

## Support Verification and Validation

Most unit and regression tests look for positive success, will the code do what the
 developer says it does. A mission taking an implementation will also want to look for
 a negative success, will the code handle bad data gracefully. This is usually done as
 part of their verification and validation phase and *bespokebpv7* is a good tool to
 have during those tests. It offers the ability to set bundle parameters that are not
 conformant to RFC 9171 or are even malformed, so the implementation can be tested to
 fail gracefully in off-nominal scenarios.

## Simulate Man in the Middle Attack

BPSec offers a method to prevent man-in-the-middle (MITM) attacks, but at least in ION,
 there is no test to verify this is handled properly. *bespokebpv7* allows taking in a
 bundle, modifying it, and sending on to its destination, simulating a MITM attack.

*mitm_test.py* provides a server that help simulate a MITM attack between two nodes by
 modifiy intransit bundles. Only modification that happens is setting the deliv_report
 flag to true and updating the primary block CRC to ensure that the BIB fails. This has
 been tested with *bping/bpecho*, but should work with other bi-directional bundle
 flows. The *modify_bundle* function can be update have different modification logic.
 For the purpose of modification bundle flow if the *--bidirectional* flag is not
 passed, the *--src-node* argument determines which direction to apply the
 modification. Make sure to update the port numbers to reflect what is in the
 configuration files.
