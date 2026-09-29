# TCP Convergence Layer (TCPCL)

The `tcpcl` module provides tools for parsing and creating TCP Convergence
Layer packets as defined in RFC 7242 and RFC 9174.

## Constants

### `MAGIC`

A byte string sentinel (`b"dtn!"`) used to identify the start of a TCPCL packet
in a byte stream.

## Data Structures

### `MESSAGE_MAP`

A dictionary used to map a combination of TCPCL version and message type
to its corresponding message class.

**Type:** `dict[tuple[TCPCLVersion, int], type[TCPCLMessage]]`

## Classes

### `TCPCL`

The `TCPCL` class encapsulates a TCPCL packet and handles version-based
dispatch to specific message types. It extends `dpkt.Packet`.

#### Attributes

- `version` (`TCPCLVersion | None`): The version of the TCPCL packet.
- `message_type` (`int | None`): The type identifier of the TCPCL message.
- `message` (`TCPCLMessage | None`): The unpacked message object containing
  the actual payload and semantics.

#### Methods

- `__init__(*args, **kwargs)`: Initializes the TCPCL packet with optional
  version and message attributes.
- `unpack(buf: bytes)`: Unpacks raw bytes into a `TCPCL` packet. Validates the
  `MAGIC` sentinel, version, and length. Raises `ValueError` if the buffer is
  too short or the format is invalid.
- `__bytes__()`: Serializes the `TCPCL` packet back into bytes. Performs a
  reverse lookup in `MESSAGE_MAP` to determine the message type. Raises
  `AttributeError` if the version or type cannot be determined.
- `__str__()`: Returns a human-readable string representation of the packet.
- `__repr__()`: Returns a developer-friendly string representation of the
  packet.

---

### `TCPCLStreamParser`

A helper class designed to extract `TCPCL` packets from a continuous byte
stream, handling partial packets and split-packet recovery.

#### Attributes

- `buffer` (`bytearray`): An internal buffer that stores incoming data until a
  complete packet can be parsed.

#### Methods

- `feed(data: bytes) -> list[TCPCL]`: Appends new data to the internal buffer
  and attempts to extract all complete `TCPCL` packets. It searches for the
  `MAGIC` sentinel and verifies the length header before attempting to unpack.
  Returns a list of successfully parsed `TCPCL` instances.
