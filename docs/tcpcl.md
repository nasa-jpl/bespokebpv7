# TCP Convergence Layer (TCPCL)

This document describes the TCPCL implementation in `bespokebpv7`, covering
the wire protocol framing, version/type dispatch, and BPv7 bundle extraction
invariants.

## Wire Format

A TCPCL packet on the wire has the following fixed header layout (RFC 7242 /
RFC 9174):

```
+--------+----------+----------+-----------+
| Magic  | Version  | Length   | Type      |  Payload ...
| 4 bytes| 1 byte   | 4 bytes  | 1 byte    |
+--------+----------+----------+-----------+
```

- **Magic**: The 4-byte ASCII sequence `dtn!` (`b"dtn!"`). Every valid TCPCL
  packet begins with this sentinel.
- **Version**: A single byte indicating TCPCL version (3 or 4).
- **Length**: A 4-byte big-endian unsigned integer giving the total number of
  bytes from the **type** byte through the end of the payload (i.e., 1 + payload
  length).
- **Type**: A single byte identifying the message type (e.g., Contact, Keepalive,
  Data Segment, etc.).

The payload follows the 10-byte fixed header.

## MESSAGE_MAP and Reverse Lookup

The `MESSAGE_MAP` dictionary in `tcpcl.py` maps `(version, message_type)` tuples
to their corresponding message classes. During **unpacking**, this map is used
to dispatch to the correct message class for the given version and type.

During **serialization** (`__bytes__`), the reverse lookup is needed: given a
message object instance, we must determine its `(version, message_type)` pair.
Since message classes do not store their own `message_type` value (it is only
known at the `TCPCL` packet level), `__bytes__` iterates over `MESSAGE_MAP`
entries and uses `isinstance` to find the matching type. This requires that
strategies and callers construct exact leaf-class instances (e.g.,
`TCPCLv3Contact` rather than `TCPCLv3Message`).

## Magic-String Framing in the Stream Parser

`TCPCLStreamParser` buffers incoming bytes and scans for the `MAGIC` sentinel
(`dtn!`) to find the start of each packet. When `MAGIC` is not found:

- Partial magic bytes are **retained** (up to 3 bytes) at the buffer tail so
  that a `MAGIC` sequence split across `feed()` calls is not lost.
- When the buffer exceeds 3 bytes without a match, older bytes are discarded.

When `MAGIC` is found at a non-zero offset, leading noise bytes are discarded
via `del self.buffer[:start_idx]`.

## BPv7 Bundle Extraction

In TCPCL, a BPv7 bundle can be embedded inside a transfer segment message.
The extraction invariant is:

- **`TCPCLv3DataSegment`** (and **`TCPCLv4XferSegment`**): When both the Start
  flag (`S=1`) and End flag (`E=1`) are set, the message represents a single
  complete transfer segment. In this case, the parser attempts to interpret
  the payload as a BPv7 bundle via `BPv7(payload)`. If the payload is not a
  valid BPv7 bundle, the `ValueError` is silently suppressed and `bpv7`
  remains `None`.

This means `bpv7` is only set for single-segment (S=1, E=1) messages with
valid CBOR-encoded BPv7 bundle payloads. Multi-segment transfers (where S=1
or E=1 but not both) never trigger extraction.

## Stream Parser Error Recovery

When `TCPCLStreamParser.feed()` encounters a buffer that looks like a valid
TCPCL packet (starts with `MAGIC`) but fails to unpack (invalid version,
unknown message type, malformed payload), the error is caught and the bad
packet is silently skipped (`except (ValueError, struct.error): continue`).
This allows the parser to recover and continue extracting subsequent valid
packets from the stream.
