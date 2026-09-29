# Examples

This folder contains example scenarios to demostrate *bespokebpv7* in use.

## Process a PCAP file

Wireshark has great capability to dissect bundles, but when there many bundles to
parse or a bundle block does not yet have a Wireshark dissector, *bespokebpv7*
offers a method to extract and parse bundles captured in a PCAP file.

*pcap_parse.py* demonstrates how to extract and parse bundles captured in
*test.pcap*. The example script takes the path to the PCAP file and it prints the
time the bundle was recorded and quick look information on the bundle. This
script can handle bundles mixed with non-DTN traffic, but it will only extract
bundles sent over UDP. The format of the PCAP file is also important. Wireshark
defaults to saving captures as PCAP Next Generation (PCAPNG) files, but the
underlying library that supports the parsing, *dpkt*, cannot parse those files,
so any captures need to saved as PCAP files.

## Support Verification and Validation

Most unit and regression tests look for positive success, will the code do
what the developer says it does. A mission taking an implementation will also
want to look for a negative success, will the code handle bad data gracefully.
This is usually done as part of their verification and validation phase and
*bespokebpv7* is a good tool to have during those tests. It offers the
ability to set bundle parameters that are not conformant to RFC 9171 or are
even malformed, so the implementation can be tested to fail gracefully in
off-nominal scenarios.

*vnv_test.py* demonstrates how to send both good and bad bundles to a DTN
implementation ensuring they are handled properly. Running this test script with
*bpecho* or some other echo utility adds a feedback mechanism, which speeds up
the test aslog files do not need to be parsed during the test. In a real V&V
setup, assert statements and some sort of test harness, like *pytest*, are
recommended to eliminate manual verification of success/failure. Sending
uncompliant CBOR data is more difficult than sending uncompliant bundle data
with *bespokepv7*, but the malformed Hop Count Extension test shows how one
could do it. *bundle_converter* what handles the final conversion to bytes so
patching in-place is going to be the best method of modifiying data. Another
method would be, assuming the byte location is know, insert or modify the
bundle string directly. This is more difficult because it requires knowledge of
the byte structure and is fragile to changes in other bundle parameters.

## TCPCL Testing

*tcpcl_ion/dotest* and *tcpcl_test.py* demonstrate TCPCL (RFC 7242 / RFC 9174)
interoperability between *bespokebpv7* and ION. The test script sends bundles
over TCPCL to an ION node and verifies the bundles are received correctly. This
exercises the TCPCL framing, stream parsing, and BPv7 extraction logic in
*bespokebpv7* against a real ION deployment.

## Simulate Man in the Middle Attack

BPSec offers a method to prevent man-in-the-middle (MITM) attacks, but there is
no test to verify this is handled properly. *bespokebpv7* allows taking in a
bundle, modifying it, and sending on to its destination, simulating a MITM
attack.

*mitm_test.py* provides a server that help simulate a MITM attack between two
nodes by modifiy intransit bundles. Only modification that happens is setting the
deliv_report flag to true and updating the primary block CRC to ensure that the
BIB fails. This has been tested with *bping/bpecho*, but should work with other
bi-directional bundle flows. The *modify_bundle* function can be update have
different modification logic. For the purpose of modification bundle flow if the
*--bidirectional* flag is not passed, the *--src-node* argument determines which
direction to apply the modification. Make sure to update the port numbers to
reflect what is in the configuration files.
