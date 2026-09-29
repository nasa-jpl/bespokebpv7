# Bundle Parameters API Reference

This module contains classes used to group related BPv7 bundle parameters
for improved legibility and management.

## Classes

### `BundleRoute`

Routing EIDs for a bundle.

**Attributes:**

- `source_eid` (property): Get/set the source EID. Accepts a string or a list
  representation.
- `dest_eid` (property): Get/set the destination EID. Accepts a string or a
  list representation.
- `report_to` (property): Get/set the report-to EID. Accepts a string or a
  list representation.

---

### `BundleLife`

Parameters for bundle life cycle. Inherits from `CreationTime`.

**Attributes:**

- `lifetime` (int): Bundle lifetime in milliseconds. Defaults to 86,400,000
  (1 day).
- `timestamp_ms` (int): Creation timestamp in milliseconds.
- `sequence` (int): Creation sequence number.

**Methods:**

- `creation_dt` (property): Returns the creation time as a
  `datetime.datetime` object.

---

### `BundleFragmentation`

Parameters used when a bundle is fragmented.

**Attributes:**

- `fragment_offset` (int): Offset of the fragment.
- `total_adu_len` (int): Total length of the Application Data Unit (ADU).

---

### `StatusAssertion`

Structure to report status assertions for bundle transport.

**Attributes:**

- `status_indicator` (bool): Status indicator flag.
- `asserted_time` (int | None): Time the status was asserted (ms).
- `asserted_dt` (property): Returns the asserted time as a
  `datetime.datetime` object or `None`.

**Methods:**

- `set_asserted_time(ms: int | None = None) -> None`: Sets the asserted time.
  If `None` is provided, the current UTC time is used.

---

### `BundleStatusInformation`

Class containing a set of status assertions for a bundle.

**Attributes:**

- `recv_bundle` (`StatusAssertion`): Status assertion for bundle reception.
- `fwd_bundle` (`StatusAssertion`): Status assertion for bundle forwarding.
- `deliv_bundle` (`StatusAssertion`): Status assertion for bundle delivery.
- `del_bundle` (`StatusAssertion`): Status assertion for bundle deletion.

---

### `BaseStatusReport`

Common information contained in all status reports.

**Attributes:**

- `status_info` (`BundleStatusInformation`): Status information assertions.
- `reason_code` (`AdminReasonCode`): Reason code for the status report.
- `status_src_eid` (property): Get/set the status source EID. Accepts a string
  or a list representation.
- `status_creation_time` (`CreationTime`): Creation time of the status report.

---

### `CTBundleSequence`

Bundle sequence definition for Compressed Custody Signal administrative records.

**Attributes:**

- `dest_seq` (int | list): Destination sequence.
- `first_seq_num` (int): First sequence number in the range.
- `seq_range` (int | list[int]): Range of sequence numbers.

---

### `CRBundleSequence`

Bundle sequence definition for Compressed Reporting administrative records.
Inherits from `CTBundleSequence`.

**Attributes:**

- `block_src_admin_eid` (property): Get/set the sequence source EID. Accepts a
  string or a list representation.
- `max_seq_len` (int): Maximum sequence length.
