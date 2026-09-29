# LTP Integration Guide

The `bespokebpv7` library supports parsing and creating Licklider Transmission
Protocol (LTP) segments per RFC 5326 (CCSDS 734.1-B-1). LTP serves as a reliable
transport layer for BPv7 bundles in Delay/Disruption Tolerant Networking (DTN)
environments.

## Bundle Extraction Logic

When parsing an LTP segment, the library attempts to extract an embedded BPv7
bundle if the segment is a `DataSegment` with `client_service_id=1`. This
follows the DTN convergence-layer mapping where client service identifier 1 is
the well-known value for BPv7.

The extraction logic in `ltp.py` (lines 93-100) works as follows:

```python
if (
    isinstance(self.segment, DataSegment)
    and self.segment.client_service_id == 1
    and self.segment.client_offset == 0
):
    # Only the data segment at offset zero begins with a bundle header.
    with contextlib.suppress(ValueError, TypeError, IndexError):
        self.bpv7 = BPv7(self.segment.data)
```

## Offset Zero Constraint

Only the data segment at offset zero is expected to begin with a bundle
header. Every other segment carries a slice from the middle of the block,
which would not decode as a valid bundle. Attempting to decode these would
unnecessarily raise exceptions.

The `client_offset == 0` check (line 96) ensures that only the first segment
of a potentially multi-segment LTP transfer attempts BPv7 parsing.
Subsequent segments (with non-zero offsets) are treated as raw data slices
of an in-progress bundle.

## Exception Handling Policy

Decoding is performed on a "best effort" basis for segments at offset
zero. This is because:

- The block may continue into later segments, leaving the current segment as
  a partial bundle.
- A malformed segment may claim offset zero but contain arbitrary data.

The library suppresses `ValueError` (truncation), `TypeError`, and
`IndexError` (arbitrary bytes) using `contextlib.suppress` at line 99.
Any other exception is treated as a defect in the library and is not
silenced.

When parsing fails, `self.bpv7` remains `None`, and the `DataSegment`
data is still accessible via `self.segment.data`.

## Creating LTP Segments with Embedded Bundles

When creating an LTP segment with an embedded BPv7 bundle:

1. Instantiate `LTP()` and set `self.segment` to a `DataSegment` instance.
1. Set `client_service_id = 1` and `client_offset = 0`.
1. Set `self.bpv7` to the BPv7 instance.
1. On serialization (`bytes(ltp_packet)`), the embedded bundle is automatically
   re-serialized and the data segment's `data` and `client_length` fields are
   updated.

## Data Flow

```text
Parse:  Bytes → LTP.unpack() → LTPSegment (via bundle_converter.structure)
         → If DataSegment & client_id==1 & offset==0 → BPv7(data) → ltp.bpv7

Serialize:  ltp.bpv7 → bytes() → updates segment.data & client_length
         → bundle_converter.unstructure(segment) → raw bytes
```

## References

- [LTP API Reference](../api/ltp.md)
- [Bundle Lifecycle Guide](lifecycle.md)
