# LTP Segments

This page documents the Licklider Transmission Protocol (LTP) segment
implementations.

## LTPSegment Hierarchy

### `LTPSegment` (Base)

Base class for all LTP Segments handling common header logic.

- `version` (int): 4-bit version field.
- `session_originator` (int): Session originator ID.
- `session_number` (int): Session number.
- `segment_type` (`LTPSegmentType`): The type of LTP segment.
- `header_count` (int): Number of header extensions.
- `trailer_count` (int): Number of trailer extensions.
- `header_mutation` (bytes): Additional header data.

### `DataSegment`

Data Segment (Red or Green).

- `client_service_id` (int): Client service identifier (default: 1 for Bundle Protocol).
- `client_offset` (int): Offset within the client data.
- `client_length` (int): Length of the client data.
- `checkpoint_serial_number` (int): Checkpoint serial number (if checkpoint).
- `report_serial_number` (int): Report serial number (if checkpoint).
- `data` (bytes): The actual data payload.

### `ReportSegment`

Report Segment (RS).

- `report_serial_number` (int): Serial number of the report.
- `checkpoint_serial_number` (int):
  Checkpoint serial number associated with the report.
- `upper_bound` (int): Upper bound of the report scope.
- `lower_bound` (int): Lower bound of the report scope.
- `reception_claims` (list[tuple[int, int]]):
  List of (offset, length) pairs claimed as received.

### `ReportAckSegment`

Report-Acknowledgment Segment (RA).

- `report_serial_number` (int): Serial number of the report being acknowledged.

### `CancelSegment`

Cancel Segment (Cx).

- `reason_code` (`CancelReasonCode`): The reason for cancellation.

## Enumerations

### `LTPSegmentType`

Enumeration for LTP segment types based on RFC 5326.

| Member | Value | Description |
| --- | --- | --- |
| `DATA_RED` | 0x0 | Red data |
| `DATA_RED_CP` | 0x1 | Red data, checkpoint |
| `DATA_RED_CP_EORP` | 0x2 | Red data, checkpoint, End of Red-Part |
| `DATA_RED_CP_EORP_EOB` | 0x3 | Red data, checkpoint, EORP, EOB |
| `DATA_GREEN` | 0x4 | Green data |
| `DATA_GREEN_UNDEF1` | 0x5 | Undefined |
| `DATA_GREEN_UNDEF2` | 0x6 | Undefined |
| `DATA_GREEN_EOB` | 0x7 | Green data, End of Block |
| `REPORT` | 0x8 | Report segment |
| `REPORT_ACK` | 0x9 | Report ACK segment |
| `CS_UNDEF1` | 0xA | Undefined |
| `CS_UNDEF2` | 0xB | Undefined |
| `CANCEL_SENDER` | 0xC | Cancel Sender segment |
| `CANCEL_SENDER_ACK` | 0xD | Cancel Sender ACK |
| `CANCEL_RECV` | 0xE | Cancel Receiver segment |
| `CANCEL_RECV_ACK` | 0xF | Cancel Receiver ACK |

### `CancelReasonCode`

Enumeration for LTP Cancel reason codes (RFC 5326 Section 3.2.4).

| Member | Value | Description |
| --- | --- | --- |
| `CLIENT_CANCELED` | 0x00 | Client canceled |
| `UNREACHABLE` | 0x01 | Unreachable |
| `SYS_CNCLD` | 0x02 | System canceled (e.g., exceeded max serial numbers) |
| `MISCOLORED` | 0x03 | Miscolored |
| `SYS_ERROR` | 0x04 | System error |
| `RETRY_EXCEED` | 0x05 | Retry limit exceeded |

## Segment Dispatch

### `SEGMENTFUNCTIONS`

The `SEGMENTFUNCTIONS` dictionary maps `LTPSegmentType` to the corresponding
segment class for deserialization.

| Segment Type | Class |
| --- | --- |
| `DATA_RED` | `DataSegment` |
| `DATA_GREEN` | `DataSegment` |
| `DATA_RED_CP` | `DataSegment` |
| `DATA_RED_CP_EORP` | `DataSegment` |
| `DATA_RED_CP_EORP_EOB` | `DataSegment` |
| `DATA_GREEN_EOB` | `DataSegment` |
| `REPORT` | `ReportSegment` |
| `REPORT_ACK` | `ReportAckSegment` |
| `CANCEL_SENDER` | `CancelSegment` |
| `CANCEL_RECV` | `CancelSegment` |
