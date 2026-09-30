# bespokebpv7

Create, parse, and modify BPv7 (RFC 9171) bundles and LTP (RFC 5326)
segments in Python.

Supports both RFC-compliant bundles and intentionally non-compliant bundles
for V&V testing of DTN implementations.

---

## Installation

```bash
pip install bespokebpv7
```

## Quick Start

### Happy Path — Create a Standard Bundle

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

- [API Reference](api/core.md) — Detailed documentation for each module.
- [Guides](guides/lifecycle.md) — Conceptual and workflow guides.
- [Examples](https://github.com/nasa-jpl/bespokebpv7/tree/main/examples/) —
Integration tests and usage patterns.

## Dependencies

- `cbor2` — CBOR encoding/decoding
- `attrs` — Class definition with validation
- `cattrs` — Structure (de)serialization
- `dpkt` — Packet manipulation base class
- `fastcrc` — CRC calculations
