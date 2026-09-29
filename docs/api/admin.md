# Admin Records API Reference

This module provides data classes for BPv7 administrative records and
helper functions for their management.

## Classes

### `AdminRecord`

Base administrative record structure. Inherits from `CanonicalBlock`.

**Attributes:**

- `record_type` (int): Type of the administrative record.
- `record_len` (int): Length of the record.

---

### `BundleStatusReport`

Bundle status report administrative record.

**Attributes:**

- `base_status` (`BaseStatusReport`): The base status report information.
- `fragmentation` (`BundleFragmentation` | None): Fragmentation parameters, if applicable.
- `max_status_report_len` (int): Maximum expected length of the status report.

---

### `CompressedCustodySignal`

Compressed Custody Signal administrative record.

**Attributes:**

- `custody_signal` (dict): A mapping of `CustodyAcceptanceCode` or
  `CustodyRefusalCode` to a list of `CTBundleSequence` objects.

**Methods:**

- `set_custody_acceptance(seq: CTBundleSequence | list[CTBundleSequence],
  key: CustodyAcceptanceCode = CustodyAcceptanceCode.CT_ACCEPTED) -> None`:
  Adds custody acceptance for the given bundle sequence(s).
- `set_custody_refusal(seq: CTBundleSequence | list[CTBundleSequence],
  key: CustodyRefusalCode = CustodyRefusalCode.CT_REFUSED) -> None`:
  Adds custody refusal for the given bundle sequence(s).

---

### `CompressedReportSignal`

Compressed Reporting Signal administrative record.

**Attributes:**

- `reports` (dict): A mapping of `ReportReason` to a list of
  `CRBundleSequence` objects.

**Methods:**

- `add_report(key: ReportReason, seq: CRBundleSequence |
  list[CRBundleSequence]) -> None`: Adds a report for a given reason and
  sequence(s).

## Constants

### `ADMINFUNCTIONS` (dict)

Maps `AdminRecordType` to the corresponding administrative record class:

- `AdminRecordType.BUNDLE_STATUS_REPORT` $\rightarrow$ `BundleStatusReport`
- `AdminRecordType.COMPRESSED_CUSTODY_SIGNAL` $\rightarrow$ `CompressedCustodySignal`
- `AdminRecordType.COMPRESSED_REPORT_SIGNAL` $\rightarrow$ `CompressedReportSignal`
