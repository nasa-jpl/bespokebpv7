# TCPCL Messages

This module provides a hierarchy of message classes for the TCP Convergence
Layer (TCPCL), supporting both version 3 and version 4 of the protocol.

## Class Hierarchy

- `TCPCLMessage` (Base)
  - `TCPCLv3Message`
    - `TCPCLv3Contact`
    - `TCPCLv3Keepalive`
    - `TCPCLv3Shutdown`
    - `TCPCLv3DataSegment`
    - `TCPCLv3DataAck`
  - `TCPCLv4Message`
    - `TCPCLv4SessInit`
    - `TCPCLv4Keepalive`
    - `TCPCLv4SessTerm`
    - `TCPCLv4XferSegment`
    - `TCPCLv4XferAck`

---

## Base Classes

### `TCPCLMessage`

Base class for all TCPCL messages. Inherits from `dpkt.Packet`.

**Methods:**

- `update_length()`: Updates the message length field before serialization.

### `TCPCLv3Message`

Base class for TCPCL version 3 messages.

- **Attributes:**
  - `version`: Set to `TCPCLVersion.V3`.

### `TCPCLv4Message`

Base class for TCPCL version 4 messages.

- **Attributes:**
  - `version`: Set to `TCPCLVersion.V4`.

---

## TCPCL v3 Concrete Messages

### `TCPCLv3Contact`

TCPCL v3 Contact message.

- **Attributes:**
  - `payload` (`bytes`): The raw payload of the contact message.

### `TCPCLv3Keepalive`

TCPCL v3 Keepalive message.

- **Attributes:**
  - `payload` (`bytes`): The raw payload of the keepalive message.

### `TCPCLv3Shutdown`

TCPCL v3 Shutdown message.

- **Attributes:**
  - `payload` (`bytes`): The raw payload of the shutdown message.

### `TCPCLv3DataSegment`

TCPCL v3 Data Segment message. Handles the Start (S) and End (E) flags
and encapsulates BPv7 bundles.

- **Attributes:**
  - `s_flag` (`bool`): Start flag.
  - `e_flag` (`bool`): End flag.
  - `sequence_number` (`int`): The sequence number of the segment.
  - `payload` (`bytes`): The raw data payload.
  - `bpv7` (`BPv7 | None`): Extracted BPv7 bundle. Automatically populated during
    `unpack()` if both `s_flag` and `e_flag` are True (single-segment bundle).
    `TCPCLStreamParser.feed()` additionally sets `bpv7` on the terminal
    segment of a multi-segment transfer; see
    [`docs/guides/tcpcl_parsing.md#bpv7-bundle-extraction`](../guides/tcpcl_parsing.md#bpv7-bundle-extraction).

### `TCPCLv3DataAck`

TCPCL v3 Data Acknowledgment message.

- **Attributes:**
  - `sequence_number` (`int`): The sequence number being acknowledged.

---

## TCPCL v4 Concrete Messages

### `TCPCLv4SessInit`

TCPCL v4 Session Initialization message.

- **Attributes:**
  - `payload` (`bytes`): The raw payload of the session initialization message.

### `TCPCLv4Keepalive`

TCPCL v4 Keepalive message.

- **Attributes:**
  - `payload` (`bytes`): The raw payload of the keepalive message.

### `TCPCLv4SessTerm`

TCPCL v4 Session Termination message.

- **Attributes:**
  - `payload` (`bytes`): The raw payload of the session termination message.

### `TCPCLv4XferSegment`

TCPCL v4 Transfer Segment message. Handles the Start (S) and End (E) flags
and encapsulates BPv7 bundles.

- **Attributes:**
  - `s_flag` (`bool`): Start flag.
  - `e_flag` (`bool`): End flag.
  - `sequence_number` (`int`): The sequence number of the segment.
  - `payload` (`bytes`): The raw data payload.
  - `bpv7` (`BPv7 | None`): Extracted BPv7 bundle. Automatically populated during
    `unpack()` if both `s_flag` and `e_flag` are True (single-segment bundle).
    `TCPCLStreamParser.feed()` additionally sets `bpv7` on the terminal
    segment of a multi-segment transfer; see
    [`docs/guides/tcpcl_parsing.md#bpv7-bundle-extraction`](../guides/tcpcl_parsing.md#bpv7-bundle-extraction).

### `TCPCLv4XferAck`

TCPCL v4 Transfer Acknowledgment message.

- **Attributes:**
  - `sequence_number` (`int`): The sequence number being acknowledged.
