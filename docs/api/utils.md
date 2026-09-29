# Utilities API Reference

Utility functions for bundle processing.

## Constants

### `DTN_EPOCH`

`datetime.datetime(2000, 1, 1, tzinfo=datetime.timezone.utc)`

The DTN epoch used for timestamping bundles.

## Functions

### `calculate_crc`

```python
calculate_crc(block_list: list[Any], crc_type: CRCType) -> bytes | None
```

Calculate CRC per RFC 9171.
The CRC field (last element) is replaced by an empty byte string for
calculation.

**Returns:**

- CRC as bytes or `None` if an unexpected type or `CRCType.NONE` is provided.

---

### `parse_eid_string`

```python
parse_eid_string(eid_str: str | list[Any]) -> list[Any]
```

Convert 'ipn:allocator.node.service',
 'ipn:node.service' or 'dtn:name' into CBOR list format.

**Returns:**

- A logical 3-element list for IPN `[SchemeCode.IPN, [allocator, node,
  service]]` or a DTN scheme list.

**Raises:**

- `ValueError`: if the given format does not match a valid scheme.

---

### `format_eid`

```python
format_eid(eid: list[Any]) -> str
```

Parse the EID array at `primary_block[eid_index]` into a URI string.

**Returns:**

- A string representation of the endpoint.

---

### `encode_sdnv`

```python
encode_sdnv(value: int) -> bytes
```

Encode a non-negative integer into a Self-Delimiting Numeric Value (SDNV).

**Args:**

- `value`: The integer to encode.

**Returns:**

- The SDNV encoded byte string.

**Raises:**

- `ValueError`: If the integer is negative.

---

### `decode_sdnv`

```python
decode_sdnv(data: bytes) -> tuple[int, int]
```

Decode an SDNV from a byte string.

**Args:**

- `data`: A byte string starting with an SDNV.

**Returns:**

- A tuple containing:
  - The decoded integer value.
  - The number of bytes consumed from the byte string.

**Raises:**

- `ValueError`: If the byte string ends before the SDNV is fully terminated.

---

## Objects

### `bundle_converter`

A `cattrs` converter used for marshaling bundle structures to CBOR bytes.
