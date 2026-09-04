# Licklider Transmission Protocol (LTP) Implementation

## Bundle Extraction Logic

When parsing an LTP segment, the library attempts to extract an embedded BPv7 bundle if the segment is a `DataSegment` with `client_service_id=1`.

### Offset Zero Constraint

Only the data segment at offset zero is expected to begin with a bundle header. Every other segment carries a slice from the middle of the block, which would not decode as a valid bundle. Attempting to decode these would unnecessarily raise exceptions.

### Exception Handling

Decoding is performed on a "best effort" basis for segments at offset zero. This is because:
- The block may continue into later segments, leaving the current segment as a partial bundle.
- A malformed segment may claim offset zero but contain arbitrary data.

The library suppresses `ValueError` (truncation), `TypeError`, and `IndexError` (arbitrary bytes). Any other exception is treated as a defect in the library and is not silenced.
