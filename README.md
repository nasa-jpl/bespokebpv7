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

## Documentation

Full API reference and operational guides are available in the
[generated documentation](https://nasa-jpl.github.io/bespokebpv7/).

## Examples

The [`examples/`](examples/) directory contains integration tests and usage
patterns, including PCAP parsing, V&V testing, and MITM BPSec testing.
