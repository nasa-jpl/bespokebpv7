# Bespoke BPv7 Bundle Creation

Custom created bundles and bundle modifications for whatever DTN purposes you require!

## Usage

This package supports defining RFC 9171 bundles and modifying the parameters to
the extent both supported and unsupported by the RFC. Want to set the do not
fragment and is a fragment flag, we won't stop you! It also supports definition
and modification of standardized Extension Blocks, specifically the Bundle Age
Block, the Hop Count Block, the Previous Node Block, and the Block Integrity
Block. Eventually, it will support the non-standard extension blocks within
ION. It can also take in a hex  representation of bundle and parse out the
parameters, provided it is CBOR conformant. Below are a few examples for using
this package.

### Parse Bundle

```python
import binascii

from bespokebpv7.block_enum import BlockType
from bespokebpv7.bpv7 import BPv7

# Take hex string representation of bundle and convert to bytes
bundle = "9f88071844008202820301820100820100821b000000b5998c982b011a000493e08506021000458202820200850704010042183485010101004454455354ff"
parsed_bundle = BPv7(binascii.unhexlify(test_bundle))
print(parsed_bundle)
print(parsed_bundle.primary_block.route.source_eid)
print(parsed_bundle.primary_block.route.dest_eid)
print(parsed_bundle.primary_block.route.report_to)
print(parsed_bundle.primary_block.flags)
print(parsed_bundle.get_block_by_type(BlockType.PAYLOAD_BLOCK))
```

### Creating a Bundle

```python
import binascii

import cbor2

from bespokebpv7.block_enum import BlockType, CRCType
from bespokebpv7.blocks import CanonicalBlockInit
from bespokebpv7.bpv7 import BPv7

payload = cbor2.dumps("Hello!")
new_bundle = BPv7()
new_bundle.add_payload_block(payload)

# Set Bundle creation time, not automatic
# pass miliseconds to set a different time than current time
new_bundle.primary_block.set_creation()

# Set bundle flags to not fragment & include status time in status reports
new_bundle.primary_block.no_fragment = True
new_bundle.primary_block.status_time = True
new_bundle.primary_block.crc_type = CRCType.CRC16
new_bundle.primary_block.route.source_eid = "ipn:2.1"
new_bundle.primary_block.route.dest_eid = "ipn:3.1"
new_bundle.primary_block.update_crc()  # Sets CRC for primary block, not automatic

# Add Previous Node block
# Convert Endpoint string to list using parsing_eid_string
# then convert to cbor string. Python lists become CBOR arrays
block_parms: CanonicalBlockInit = {"block_type": BlockType.PREVIOUS_NODE}
new_bundle.add_canonical_block(block_parms, cbor2.dumps(parse_eid_string("ipn:2.0")))
print(new_bundle)
```

### Modifying a Bundle

```python
import binascii

import cbor2

from bespokebpv7.block_enum import BlockType, CRCType
from bespokebpv7.bpv7 import BPv7

payload = cbor2.dumps("Hello!")

# Take hex string representation of bundle and convert to bytes
bundle = "9f88070000820282030182028201018202820100821b000000bb0e20b4ea001a000927c08508020100410086010100014d48656c6c6f2c20576f726c64214254b3ff"
mod_bundle = BPv7(binascii.unhexlify(bundle))

# Change the payload and update the payload block CRC
mod_bundle.blocks[BlockType.PAYLOAD_BLOCK].data = payload
mod_bundle.blocks[BlockType.PAYLOAD_BLOCK].update_crc()

# Change the Bundle processing flags
mod_bundle.primary_block.no_fragment = True
mod_bundle.primary_block.status_time = True

# Change the bundle route
mod_bundle.primary_block.route.source_eid = "ipn:2.1"
mod_bundle.primary_block.route.dest_eid = "ipn:3.1"

# Change the creation time
mod_bundle.primary_block.set_creation()

# Update the primary block CRC to reflect the changes
mod_bundle.primary_block.crc_type = CRCType.CRC16
mod_bundle.primary_block.update_crc()
print(mod_bundle)

# Get hex string representation
print(bytes(mod_bundle).hex())
```
