# ION Non-Standard Extensions

This document describes several non-standard extension blocks and administrative
records used by NASA JPL's ION (Interplanetary Overlay Network) DTN
implementation. These extensions are defined in a draft CCSDS Orange Book and
provide additional functionality for custody transfer, reporting, and quality of
service that exceeds the baseline RFC 9171 specification. A custom QoS extension
block, based on the BPv6 Standardized ECOS block, is also implemented by ION.

## Integration Context

These extensions are used within the ION DTN implementation to optimize custody
transfer signaling, status reporting, and quality-of-service management in
constrained delay/disruption tolerant networking environments.

## Extension Blocks

### Custody Transfer Enrichment Block (CTEB)

The **Custody Transfer Enrichment Block (CTEB)** provides additional metadata
related to the custody transfer process. It is defined in the draft CCSDS Orange
Book on Bundle Protocol custody transfer.

* **Block Type:** `13`
* **Structure:** The CTEB is represented as a CBOR list containing:
    1. **Sequence Number** (`int`): The sequence number associated with the
       custody transfer.
    1. **Sequence ID** (`int`): The identifier for the sequence.
    1. **Block Source Admin EID** (`EID`): The EID of the administering node.

In `bespokebpv7`, this is implemented in the `CustodyTransferExt` class within
`ext_functions.py`.

### Compressed Reporting Extension Block (CREB)

The **Compressed Reporting Extension Block (CREB)** allows a bundle to request
specific types of status reports in a compressed format. It is defined in the
draft CCSDS Orange Book on Bundle Protocol reporting.

* **Block Type:** `14`
* **Structure:** The CREB is represented as a CBOR list with the following
  optional fields:
    1. **Sequence Number** (`int`)
    1. **Sequence ID** (`int` | `None`)
    1. **Status Report Flags** (`flags`): A bitmask specifying the requested
       reports.
    1. **Block Source Admin EID** (`EID` | `None`)
    1. **Report To EID** (`EID` | `None`)

#### Report Flags

The `status_report_flags` field uses the following bitmask:

| Flag | Bit | Description |
| :--- | :--- | :--- |
| `RECV_REPORT_REQ` | $2^0$ | Request report upon receipt |
| `FWD_REPORT_REQ` | $2^1$ | Request report upon forwarding |
| `DELIV_REPORT_REQ` | $2^2$ | Request report upon delivery |
| `DEL_REPORT_REQ` | $2^3$ | Request report upon deletion |
| `CT_ACCEPT_REQ` | $2^4$ | Request report upon custody acceptance |
| `CT_REJECT_REQ` | $2^5$ | Request report upon custody rejection |

In `bespokebpv7`, this is implemented in the `CompressedReportingExt` class
within `ext_functions.py`.

### Quality of Service Extension (QOS)

The **Quality of Service Extension Block** is a custom ION extension based on the
BPv6 Standardized ECOS (Extended Class of Service) block. It allows for the
specification of class of service parameters that influence bundle scheduling and
forwarding behavior within the ION network.

* **Block Type:** `193`
* **Structure:** The QOS extension block is represented as a CBOR list with the
  following fields:
    1. **QoS Flags** (`int`): Bitmask of QoS control flags.
    1. **Class of Service** (`int`): The ECOS class of service value.
    1. **Ordinal** (`int`): The ECOS ordinal value.
    1. **Data Label** (`int`): An optional data label for extended
       classification.

In `bespokebpv7`, this is implemented in the `BPQExt` class within
`ext_functions.py`.

## Compressed Admin Records

ION utilizes compressed versions of administrative records to reduce bandwidth
consumption for signaling. These are also defined in the draft CCSDS Orange
Book.

### Compressed Custody Signal

The **Compressed Custody Signal** is used to communicate the acceptance or
refusal of custody for one or more bundles in a single record.

* **Admin Record Type:** `13`
* **Structure:** A CBOR list `[type, map]`, where the map keys are disposition
  codes and values are lists of bundle sequences.
* **Disposition Codes:**
  * `CT_ACCEPTED` (1): Custody accepted.
  * `CT_REFUSED` (-1): Custody refused.
* **Bundle Sequence:** Each sequence is represented as
  `[dest_seq, first_seq_num, seq_range]`.

In `bespokebpv7`, this is implemented in the `CompressedCustodySignal` class
within `admin_records.py`.

### Compressed Report Signal

The **Compressed Report Signal** allows for the aggregation of multiple status
reports into a single administrative record.

* **Admin Record Type:** `14`
* **Structure:** A CBOR list `[type, map]`, where the map keys are report reasons
  and values are lists of bundle sequences.
* **Report Reasons:**
  * `RECV_REPORT` (0)
  * `FWD_REPORT` (1)
  * `DELIV_REPORT` (2)
  * `DEL_REPORT` (3)
  * `CT_ACCEPT_REPORT` (4)
  * `CT_REJECT_REPORT` (5)
* **Bundle Sequence:** Each sequence is represented as
  `[dest_seq, first_seq_num, seq_range]`, with an optional fourth element for the
  **Block Source Admin EID**.

In `bespokebpv7`, this is implemented in the `CompressedReportSignal` class
within `admin_records.py`.
