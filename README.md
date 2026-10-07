# Bespoke BPv7

Create, parse, and modify BPv7 (RFC 9171) bundles and LTP (RFC 5326)
segments in Python.

Supports both RFC-compliant bundles and intentionally non-compliant bundles
for V&V testing of DTN implementations.

## Installation

```bash
pip install bespokebpv7
```

## Quick Start

### Create a Standard Bundle

```python
import cbor2

from bespokebpv7 import BPv7, CRCType, parse_eid_string

# Build payload as CBOR (RFC 9171 encodes all data in CBOR)
payload = cbor2.dumps("Hello, World!")

# Initialize bundle and add payload block
bundle = BPv7()
bundle.add_payload_block(payload)

# Set creation timestamp, routing, and flags
bundle.primary_block.set_creation()
bundle.primary_block.route.source_eid = "ipn:2.1"
bundle.primary_block.route.dest_eid = "ipn:3.1"
bundle.primary_block.no_fragment = True
bundle.primary_block.crc_type = CRCType.CRC16

# Always re-compute CRC after modifying a block
bundle.primary_block.update_crc()

# Serialize
serialized: bytes = bytes(bundle)
```

### V&V Path — Non-Compliant Bundle

```python
from bespokebpv7 import BPv7, BundleFlags, CRCType

bundle = BPv7()
bundle.add_payload_block(b"test")

# Intentionally non-compliant: both IS_FRAGMENT and
# DO_NOT_FRAGMENT are set simultaneously.
bundle.primary_block.flags |= BundleFlags.IS_FRAGMENT
bundle.primary_block.flags |= BundleFlags.DO_NOT_FRAGMENT

bundle.primary_block.set_creation()
bundle.primary_block.route.source_eid = "ipn:2.1"
bundle.primary_block.route.dest_eid = "ipn:3.1"
bundle.primary_block.crc_type = CRCType.CRC16
bundle.primary_block.update_crc()
```

### Parsing from Hex

```python
import binascii
from bespokebpv7 import BPv7, BlockType

hex_bundle = (
    "9f88071844008202820301820100820100821b000000b5998c98"
    "2b011a000493e085060210004582028202008507040100421834"
    "85010101004454455354ff"
)
bundle = BPv7(binascii.unhexlify(hex_bundle))
print(bundle.primary_block.route.source_eid)
print(bundle.get_block_by_type(BlockType.PAYLOAD_BLOCK))
```

### Create and Parse an LTP Segment

```python
from bespokebpv7 import BPv7, LTP
from bespokebpv7.segment_enum import LTPSegmentType
from bespokebpv7.segments import DataSegment

bundle = BPv7()
bundle.primary_block.route.source_eid = "ipn:2.1"
bundle.primary_block.route.dest_eid = "ipn:3.1"
bundle.add_payload_block(b"Hello, World!")
bundle_bytes = bytes(bundle)

data_seg = DataSegment()
data_seg.segment_type = LTPSegmentType.DATA_RED_CP_EORP_EOB
data_seg.session_originator = 1
data_seg.session_number = 1
data_seg.client_service_id = 1  # 1 == Bundle Protocol
data_seg.client_length = len(bundle_bytes)
data_seg.data = bundle_bytes

ltp_packet = LTP()
ltp_packet.segment = data_seg
ltp_packet.bpv7 = bundle

raw: bytes = bytes(ltp_packet)
received = LTP(raw)
print(received.bpv7.primary_block.route.source_eid)
```

### Parse a TCPCL Byte Stream

```python
from bespokebpv7 import TCPCL, TCPCLStreamParser
from bespokebpv7.tcpcl_enum import TCPCLv3MessageType
from bespokebpv7.tcpcl_messages import TCPCLv3Keepalive

keepalive = TCPCL()
keepalive.message = TCPCLv3Keepalive()
keepalive.version = TCPCLv3Keepalive.version
keepalive.message_type = TCPCLv3MessageType.KEEPALIVE
incoming_bytes = bytes(keepalive)

parser = TCPCLStreamParser()
# Feed bytes as they arrive off the socket; a single feed() call may
# return zero, one, or many fully-reassembled TCPCL packets.
packets = parser.feed(incoming_bytes)
for packet in packets:
    print(packet.message)
```

## Documentation

Full API reference and operational guides are available in the
[generated documentation](https://nasa-jpl.github.io/bespokebpv7/).

## Examples

The [`examples/`](examples/) directory contains integration tests and usage
patterns, including PCAP parsing, V&V testing, and MITM BPSec testing.
