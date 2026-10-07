# BPv7

Main class for creating, parsing, and modifying Bundle Protocol version 7
(BPv7) bundles. Inherits from `dpkt.Packet`.

## Attributes

- `primary_block` (PrimaryBlock): The primary block containing routing and
  lifetime information.
- `blocks` (ExtensionBlocks): An ordered collection of canonical blocks
  (payload and extension blocks).
- `debug` (bool): Enable debugging output during unpacking.

## Methods

- `__str__() -> str`: Returns a detailed summary of the bundle.
- `__repr__() -> str`: Returns a concise representation of the bundle.
- `__bytes__() -> bytes`: Serializes the bundle to bytes as an indefinite
  CBOR array.
- `__len__() -> int`: Returns the actual serialized size of the bundle.
- `add_canonical_block(block_parms: CanonicalBlockInit,
  data: bytes) -> None`: Adds an extension block to the bundle.
- `add_payload_block(data: bytes, flags: BlockFlags | None = None,
  crc_type: CRCType = CRCType.NONE) -> None`: Adds a Payload Block with
  optional CRC.
- `get_block_by_type(type_code: BlockType) -> CanonicalBlock | None`: Returns
  the first block matching the specified `BlockType`, or `None` if not found.
- `unpack(buf: bytes) -> None`: Unpacks an indefinite CBOR array from bytes
  into the bundle object.

---

## Core Block Classes

This page documents the core block structure classes used in `bespokebpv7`.

## BaseBlock

Class that contains values required for both primary and canonical blocks.

### Attributes

- `flags` (Any): Block flags.
- `crc_type` (CRCType): The type of CRC algorithm used. Defaults to
  `CRCType.NONE`.
- `crc` (bytes | None): The calculated CRC value.

### Methods

- `__bytes__() -> bytes`: Convert the block structure to bytes using the
  bundle converter.
- `update_crc() -> None`: Manually trigger the calculation and update of the
  CRC based on the current state.
- `set_flag(flag: BundleFlags | BlockFlags) -> None`: Set an individual flag
  bit.
- `clear_flag(flag: BundleFlags | BlockFlags) -> None`: Clear an individual
  flag bit.

---

## CanonicalBlock

Parameter definitions for Canonical blocks. Inherits from `BaseBlock`.

**Structure:** `[block_type, block_number, flags, crc_type, data, crc]`

### Attributes

- `block_type` (BlockType): The type of the canonical block. Defaults to
  `BlockType.UNKNOWN_BLOCK`.
- `block_number` (int): The sequence number of the block. Defaults to 1.
- `flags` (BlockFlags): Canonical block flags.
- `data` (bytes): The block payload data.
- `data_prefix` (bytes): Optional prefix to prepend to data during
  serialization. Defaults to `b""`.
- `data_override` (bytes | None): Optional override for the data during
  serialization.
- `max_array_len` (int): Maximum expected array length for CBOR structure.

### Properties

- `replica_fragment` (bool): Maps to `BlockFlags.REPLICATE_FRAGMENT`.
- `status_report` (bool): Maps to `BlockFlags.STATUS_BUNDLE`.
- `delete_bundle` (bool): Maps to `BlockFlags.DELETE_BUNDLE`.
- `discard_block` (bool): Maps to `BlockFlags.DISCARD_BLOCK`.

### Methods

- `_structure(data: list[Any]) -> Self`: Class method that populates a
  `CanonicalBlock` from a CBOR list.
- `_unstructure() -> list[Any]`: Converts the `CanonicalBlock` instance to a
  CBOR list, applying overrides if present.

---

## PrimaryBlock

Parameter definitions for the Primary Block. Inherits from `BaseBlock`.

### Attributes

- `version` (int): BP version. Defaults to 7.
- `flags` (BundleFlags): Primary block flags.
- `route` (BundleRoute): Routing information (source, destination, report-to).
- `life` (BundleLife): Lifetime information (creation timestamp, sequence,
  lifetime).
- `fragmentation` (BundleFragmentation | None): Fragmentation parameters if
  the bundle is a fragment.
- `list_override` (list[Any] | None): Optional override for the entire
  serialized list layout.
- `extra_elements` (list[Any]): Additional elements to append to the
  serialized list.
- `raw_override` (bytes | None): Optional raw byte override for
  serialization.

### Properties

- `is_fragment` (bool): Maps to `BundleFlags.IS_FRAGMENT`.
- `adu_is_admin` (bool): Maps to `BundleFlags.ADU_IS_ADMIN_RECORD`.
- `no_fragment` (bool): Maps to `BundleFlags.DO_NOT_FRAGMENT`.
- `ack_requested` (bool): Maps to `BundleFlags.ACK_REQUESTED`.
- `status_time` (bool): Maps to `BundleFlags.STATUS_TIME`.
- `deliv_report` (bool): Maps to `BundleFlags.STATUS_REPORT_DELIV`.
- `fwd_report` (bool): Maps to `BundleFlags.STATUS_REPORT_FWD`.
- `recv_report` (bool): Maps to `BundleFlags.STATUS_REPORT_RECV`.
- `del_report` (bool): Maps to `BundleFlags.STATUS_REPORT_DEL`.

### Methods

- `set_creation(ms: int | None = None, seq: int = 0) -> None`: Sets the primary
  block creation time. If `ms` is None, current UTC time is used.
- `_structure(data: list[Any]) -> Self`: Class method that populates a
  `PrimaryBlock` from a CBOR list.
- `_unstructure() -> list[Any]`: Converts the `PrimaryBlock` instance to a
  CBOR list, applying overrides if present.

---

## ExtensionBlocks

A specialized `OrderedDict` that manages `CanonicalBlock` instances keyed by
`BlockType`.

### Methods

- `__setitem__(key: BlockType, value: CanonicalBlock) -> None`: Overrides the
  standard dictionary set item to ensure that the `PAYLOAD_BLOCK` is always
  maintained as the last item in the order.

### Duplicate Block Types

Assigning a `CanonicalBlock` under a `BlockType` key that is already present
(whether via `BPv7.add_canonical_block()`, `BPv7.add_payload_block()`, or
during `BPv7.unpack()` of a wire-format bundle with two canonical blocks of
the same type) does not raise. It emits a `UserWarning` and preserves the
previously-assigned block in the `duplicate_blocks: dict[BlockType,
list[CanonicalBlock]]` instance attribute, appending each successive
collision for that key. `self[key]` lookup is unaffected and continues to
return the most-recently-assigned block. `BPv7.duplicate_blocks` exposes the
same data via `bundle.blocks.duplicate_blocks` for convenience.

This warn-and-preserve design (rather than raising) is deliberate: the
library must remain able to parse intentionally non-RFC-compliant bundles
captured for V&V testing, including bundles with duplicate canonical block
types, without rejecting them outright.
