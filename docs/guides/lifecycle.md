# Bundle Lifecycle: Parse → Modify → Serialize

This guide describes the standard workflow for interacting with BPv7 bundles
using the `bespokebpv7` library. Whether you are inspecting a captured bundle,
altering its routing, or creating a new bundle from scratch, you will follow this
cycle.

## Overview

The lifecycle of a bundle in `bespokebpv7` consists of three primary stages:
**Parsing**, **Modifying**, and **Serializing**.

### Data Flow Diagram

```text
  +-------------------+       +-----------------------+       +-----------------------+
  |      INPUT        |       |     INTERNAL STATE    |       |       OUTPUT         |
  |    (Raw Bytes)    | ----> |      BPv7 Object      | ----> |    (Raw Bytes)       |
  +-------------------+       +-----------------------+       +-----------------------+
            |                             |                               |
            |  1. Parsing                 |  2. Modifying                 |  3. Serializing
            |  - BPv7.unpack()            |  - Update attributes         |  - bytes(bundle)
            |  - CBOR Decode              |  - update_crc()              |  - bundle_converter()
            |  - BLOCKFUNCTIONS           |                               |
            +-----------------------------+-------------------------------+
```

---

## 1. Parsing

Parsing converts raw bytes (e.g., from a PCAP file or a network socket) into a
high-level Python object that can be easily manipulated.

### The Process

1. **Initialization**: A `BPv7` object is instantiated.
2. **Unpacking**: The `unpack()` method is called on the raw bytes.
3. **Primary Block**: The library CBOR-decodes the primary block to populate the
   `PrimaryBlock` instance (routing, flags, and lifetime).
4. **Canonical Blocks**: The library iterates through the remaining data:
    - It identifies the block type.
    - It uses the `BLOCKFUNCTIONS` dictionary to map the type to the correct
      extension class (e.g., `BundleAgeExt`, `HopCountExt`).
    - Each block is CBOR-decoded.
5. **Storage**: All decoded blocks are stored in an `ExtensionBlocks`
   `OrderedDict`, preserving the original order of blocks in the bundle.

**Example:**

```python
from bespokebpv7 import BPv7

raw_bytes = b"..."  # Raw BPv7 bundle
bundle = BPv7(raw_bytes)
bundle.unpack()
```

---

## 2. Modifying

Once a bundle is parsed into a `BPv7` object, you can modify its attributes.

### The Process

- **Attribute Modification**: You can change any attribute of the `PrimaryBlock`
  or any block within the `ExtensionBlocks` collection.
- **CRC Update**: **Crucially, CRCs are NOT automatically updated when you
  change a block's data.**

### ⚠️ The CRC Requirement

If you modify any field that is covered by a checksum (CRC), you must explicitly
call the `update_crc()` method on that block. Failure to do so will result in a
bundle that is technically malformed and will be rejected by RFC-compliant DTN
implementations.

**Example:**

```python
# Modify a primary block attribute
bundle.primary_block.flags.do_not_fragment = True
bundle.primary_block.update_crc()

# Modify an extension block attribute
# (Assuming a HopCount block exists)
hop_block = bundle.extension_blocks[BlockType.HOP_COUNT]
hop_block.count += 1
hop_block.update_crc()
```

---

## 3. Serializing

Serialization converts the modified `BPv7` Python object back into raw bytes for
transmission or storage.

### The Process

1. **Conversion**: Calling `bytes(bundle)` triggers the internal serialization
   logic.
2. **Bundle Converter**: The `bundle_converter()` utility is invoked.
3. **CBOR Encoding**: The `PrimaryBlock` and all blocks in the `ExtensionBlocks`
   `OrderedDict` are serialized into CBOR format.
4. **Output**: The resulting bytes are returned as a single contiguous blob.

**Example:**

```python
serialized_bytes = bytes(bundle)
# serialized_bytes now contains the CBOR-encoded bundle
```

---

## Complete Cycle Example

Here is a full example of the Parse $\rightarrow$ Modify $\rightarrow$
Serialize flow:

```python
from bespokebpv7 import BPv7
from bespokebpv7.block_enum import BlockType

# 1. PARSE
raw_data = get_bundle_bytes()
bundle = BPv7(raw_data)
bundle.unpack()

# 2. MODIFY
# Change the destination EID
bundle.primary_block.destination = "ipn:10.1"
bundle.primary_block.update_crc()  # REQUIRED

# Update hop count if present
if BlockType.HOP_COUNT in bundle.extension_blocks:
    hop_block = bundle.extension_blocks[BlockType.HOP_COUNT]
    hop_block.count += 1
    hop_block.update_crc()  # REQUIRED

# 3. SERIALIZE
final_bytes = bytes(bundle)
send_to_network(final_bytes)
```
