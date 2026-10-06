# Extensions API Reference

This module provides implementations for various BPv7 extension blocks.

## Classes

### `BundleAgeExt`

Implementation of the Bundle Age extension block.

**Attributes:**

- `age` (int): Bundle age in milliseconds.

---

### `PreviousNodeExt`

Implementation of the Previous Node extension block.

**Attributes:**

- `previous_node` (property): Get/set the previous node EID.
  Accepts a string or a list representation.

---

### `HopCountExt`

Implementation of the Hop Count extension block (HCB).

**Attributes:**

- `hop_limit` (int): Maximum number of hops allowed.
- `hop_count` (int): Current hop count.

---

### `CustodyTransferExt`

Implementation of the Custody Transfer extension block (CTEB).

**Attributes:**

- `sequence_num` (int): Custody sequence number.
- `block_src_admin_eid` (property): Get/set the source EID for the
  admin block. Accepts a string or a list representation.

---

### `CompressedReportingExt`

Implementation of the Compressed Reporting extension block (CREB).

**Attributes:**

- `sequence_num` (int): Sequence number.
- `sequence_id` (int | None): Sequence identifier.
- `status_report_flags` (`CREBFlags` | None): Flags indicating which
  reports are requested.
- `block_src_admin_eid` (property): Get/set the source EID for the
  admin block. Accepts a string or a list representation.
- `report_to_eid` (property): Get/set the report-to EID.
  Accepts a string or a list representation.

The fields are ordered: `sequence_num`, `sequence_id`,
`status_report_flags`, `block_src_admin_eid`, `report_to_eid`.
Fields may only be omitted from the **end** of the list (trailing omission);
an interior field set to `None` while a later field is set raises
`ValueError` during serialization. Callers wanting to set a later field
must supply explicit values (e.g. `0`) for all earlier ones.

**Report Request Properties (Boolean):**

- `report_recv`: Request for reception report.
- `fwd_report`: Request for forwarding report.
- `deliv_report`: Request for delivery report.
- `del_report`: Request for deletion report.
- `ct_accept_report`: Request for custody acceptance report.
- `ct_reject_report`: Request for custody rejection report.

**Methods:**

- `set_status_flag(status_flag: CREBFlags) -> None`: Sets a
  specific reporting flag.
- `clear_status_flag(status_flag: CREBFlags) -> None`: Clears a
  specific reporting flag.

---

### `BPQExt`

Implementation of the ION Quality of Service (QoS) extension block.

**Attributes:**

- `qos_flags` (int): Quality of Service flags.
- `class_of_service` (int): Class of service identifier.
- `ordinal` (int): Ordinal value for priority.
- `data_label` (int): Data label for traffic identification.

## Constants

### `BLOCKFUNCTIONS` (dict)

Maps `BlockType` to the corresponding extension block class:

- `BlockType.BIB` $\rightarrow$ `BlockIntegrityBlock`
- `BlockType.BCB` $\rightarrow$ `BlockConfidentialityBlock`
- `BlockType.PAYLOAD_BLOCK` $\rightarrow$ `CanonicalBlock`
- `BlockType.PREVIOUS_NODE` $\rightarrow$ `PreviousNodeExt`
- `BlockType.BUNDLE_AGE` $\rightarrow$ `BundleAgeExt`
- `BlockType.HOP_COUNT` $\rightarrow$ `HopCountExt`
- `BlockType.CTEB` $\rightarrow$ `CustodyTransferExt`
- `BlockType.CREB` $\rightarrow$ `CompressedReportingExt`
- `BlockType.QOS` $\rightarrow$ `BPQExt`
- `BlockType.UNKNOWN_BLOCK` $\rightarrow$ `CanonicalBlock`
