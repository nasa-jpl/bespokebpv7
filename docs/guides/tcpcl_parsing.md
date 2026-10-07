# TCP Convergence Layer (TCPCL)

This document describes the TCPCL implementation in `bespokebpv7`, covering
the wire protocol framing, version/type dispatch, and BPv7 bundle extraction
invariants.

## Wire Format

A TCPCL packet on the wire has the following fixed header layout (RFC 7242 /
RFC 9174):

```text
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

In TCPCL, a BPv7 bundle can be embedded inside a transfer segment message,
and that bundle can be split across multiple segment messages.

- **Single-segment case** (`S=1, E=1`): handled directly in
  `TCPCLv3DataSegment.unpack()`/`TCPCLv4XferSegment.unpack()`. The payload is
  interpreted as a BPv7 bundle via `BPv7(payload)`; on failure the
  `ValueError`/`TypeError` is suppressed and `bpv7` remains `None`.
- **Multi-segment case**: reassembled by `TCPCLStreamParser.feed()`, since
  only the stream parser sees the full sequence of segments. Rules:
  - A start segment (`S=1, E=0`) begins a new reassembly buffer. If a
    transfer is already in progress, it is discarded (implicit abort of a
    stale transfer, e.g. one whose terminal segment was lost).
  - A middle segment (`S=0, E=0`) appends to the in-progress buffer. If no
    transfer is in progress, the segment is an orphan and its payload is
    discarded (`bpv7` stays `None`); there is no way to safely guess at
    reassembly from an orphan continuation.
  - A terminal segment (`S=0, E=1`) appends to the buffer, attempts
    `BPv7(bytes(buffer))`, and assigns the result to that segment's `bpv7`
    (suppressing parse failures), then clears the buffer. If no transfer was
    in progress, the terminal segment is treated as degenerate and its own
    payload is parsed directly.
  - The buffer is capped at `MAX_TRANSFER_BUFFER_SIZE` (64 MiB); exceeding it
    aborts the in-progress transfer rather than growing unbounded.
  - A `TCPCLv3Shutdown`/`TCPCLv4SessTerm` message clears any in-progress
    buffer, since a terminated session cannot continue a transfer.
  - **Known limitation**: neither segment class exposes a transfer/session
    identifier field, so reassembly cannot distinguish between two
    interleaved transfers. This relies on the TCPCL spec's guarantee that a
    connection direction carries only one transfer at a time; the
    stale-transfer-abort rule above is the safety net if that guarantee is
    violated by a non-compliant peer. A single `TCPCLStreamParser` instance
    holds exactly one reassembly buffer, so it must be used for one
    connection direction at a time; feeding it segments interleaved from
    multiple flows (e.g. both directions of a capture) will corrupt
    reassembly.
  - **Asymmetry**: only the terminal segment's `bpv7` attribute carries the
    full reassembled bundle; its `payload` attribute still holds only its
    own final fragment. Re-serializing that message object directly
    (`bytes(message)`) does not round-trip the full multi-segment bundle.

## Stream Parser Error Recovery

When `TCPCLStreamParser.feed()` encounters a buffer that looks like a valid
TCPCL packet (starts with `MAGIC`) but fails to unpack (invalid version,
unknown message type, malformed payload), the error is caught and the bad
packet is silently skipped (`except (ValueError, struct.error): continue`).
This allows the parser to recover and continue extracting subsequent valid
packets from the stream.
