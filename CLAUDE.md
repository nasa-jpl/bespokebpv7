# CLAUDE.md

Last verified: 2026-04-01

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This is **bespokebpv7**, a Python library for creating, parsing, and modifying Bundle Protocol version 7 (BPv7) bundles per RFC 9171 and Licklider Transmission Protocol (LTP) segments per RFC 5326. It supports Delay/Disruption Tolerant Networking (DTN) applications and can create both RFC-compliant and intentionally non-compliant bundles/segments for testing purposes.

## Development Commands

### Testing

```bash
# Run all tests across Python versions 3.10-3.14
tox

# Run tests for specific Python version
tox -e 3.12

# Run tests with coverage
tox -e clean  # Clear previous coverage data first
tox -e 3.10 -e 3.11 -e 3.12 -e 3.13 -e 3.14
tox -e coverage  # Generate coverage report and HTML

# Run pytest directly (must be in virtual environment)
pytest

# Run a single test file
pytest tests/test_bpv7.py

# Run a specific test
pytest tests/test_bpv7.py::test_function_name
```

### Linting and Type Checking

```bash
# Run ruff linting (auto-fixes issues)
tox -e lint

# Run type checking with mypy
tox -e type

# Run ruff directly (must be in virtual environment)
ruff check --fix src/bespokebpv7
ruff format src/bespokebpv7
```

### Building

```bash
# Build uses uv_build backend
uv build
```

### Examples

The `examples/` directory contains integration tests that run against ION DTN implementation:

```bash
# Example tests are run as part of tox test suite
cd examples/pcap_parse && ./dotest
cd examples/unittest_ion/issue-265-bpdriver-ttl-option && ./dotest
cd examples/unittest_ion/status-rpts && ./dotest
cd examples/vnv_ion && ./dotest
cd examples/mitm_test && ./dotest
```

## Architecture

### Core Structure

A BPv7 bundle consists of:

- **Primary Block** (required): Contains routing and lifetime information
- **Canonical Blocks** (1+): Ordered collection including payload and extension blocks

### Key Modules

**bpv7.py** - Main bundle class

- `BPv7` class extends `dpkt.Packet`
- Orchestrates bundle parsing and creation
- Entry point for all bundle operations

**blocks.py** - Block structure classes

- `PrimaryBlock`: Bundle metadata (source, destination, creation time, flags, CRC)
- `CanonicalBlock`: Base class for payload and extension blocks
- `ExtensionBlocks`: OrderedDict managing canonical blocks by type
- `BaseBlock`: Common functionality for CRC calculation and serialization

**bundle_params.py** - Parameter grouping classes

- `BundleRoute`: EID routing (source, destination, report-to)
- `BundleLife`: Creation timestamp and lifetime
- `BundleFragmentation`: Fragment offset and total ADU length
- Status report related classes (`StatusAssertion`, `BundleStatusInformation`, `BaseStatusReport`)
- Custody transfer classes (`CTBundleSequence`, `CRBundleSequence`)

**block_enum.py** - Enumerations

- `BlockType`: Extension block type identifiers (PAYLOAD_BLOCK, PREVIOUS_NODE, HOP_COUNT, BUNDLE_AGE, BIB, etc.)
- `BundleFlags`: Primary block flags (IS_FRAGMENT, DO_NOT_FRAGMENT, STATUS_REPORT_*, etc.)
- `BlockFlags`: Canonical block flags (REPLICATE_FRAGMENT, DELETE_BUNDLE, etc.)
- `CRCType`: CRC algorithms (NONE, CRC16, CRC32)
- Security and admin record enumerations

**ext_functions.py** - Extension block implementations

- `BundleAgeExt`: Tracks bundle age in milliseconds
- `PreviousNodeExt`: Records previous node EID
- `HopCountExt`: Hop count and hop limit tracking
- `CustodyTransferExt`: ION custody transfer extension (non-standard)
- `CompressedReportingExt`: ION compressed reporting extension (non-standard)
- `BLOCKFUNCTIONS` dict maps BlockType to extension class

**bpsec.py** - Bundle Protocol Security blocks

- `AbstractSecurityBlock`: Base for BPSec operations
- `BlockIntegrityBlock`: BIB implementation with SHA variant support
- Security parameter and result handling

**admin_records.py** - Administrative records

- `AdminRecord`: Base class for admin payloads
- `BundleStatusReport`: RFC 9171 status reports
- `CompressedCustodySignal`: ION custody signals (non-standard)
- `CompressedReportSignal`: ION report signals (non-standard)
- `ADMINFUNCTIONS` dict maps AdminRecordType to admin class

**ltp.py** - Licklider Transmission Protocol class

- `LTP` class extends `dpkt.Packet`
- Parses and creates LTP segments per RFC 5326 / CCSDS 734.1-B-1
- Automatically extracts BPv7 bundles from data segments with client_service_id=1
- Entry point for all LTP segment operations

**segments.py** - LTP segment structure classes

- `LTPSegment`: Base class with common header (version, session_originator, session_number, segment_type, header/trailer extension counts)
- `DataSegment`: Red/green data segments with client service ID, offset, length, optional checkpoint fields, and embedded data payload
- `ReportAckSegment`: Report acknowledgment segments
- `CancelSegment`: Cancel segments (sender/receiver) with reason codes
- `SEGMENTFUNCTIONS` dict maps LTPSegmentType to segment class

**segment_enum.py** - LTP enumerations

- `LTPSegmentType`: Segment type identifiers (DATA_RED, DATA_GREEN, DATA_RED_CP, DATA_RED_CP_EORP, DATA_RED_CP_EORP_EOB, DATA_GREEN_EOB, REPORT_ACK, CANCEL_SENDER, CANCEL_RECV, etc.)
- `CancelReasonCode`: Cancel reason codes per RFC 5326 (CLIENT_CANCELED, UNREACHABLE, SYS_CNCLD, MISCOLORED, SYS_ERROR, RETRY_EXCEED)

**utils.py** - Utility functions

- `parse_eid_string()`: Convert EID string to CBOR array
- `format_eid()`: Convert CBOR array to EID string
- `calculate_crc()`: Compute CRC16/CRC32 checksums
- `bundle_converter()`: Marshal bundle structures to CBOR bytes
- `encode_sdnv()`: Encode integers as Self-Delimiting Numeric Values
- `decode_sdnv()`: Decode SDNV bytes, returns (value, bytes_consumed)
- `DTN_EPOCH`: DTN epoch constant (2000-01-01 00:00:00 UTC)

### Data Flow

**Parsing a bundle:**

1. Bytes → `BPv7.__init__()` → `BPv7.unpack()`
2. CBOR decode primary block → populate `PrimaryBlock`
3. CBOR decode canonical blocks → create appropriate block instances via `BLOCKFUNCTIONS`
4. Store blocks in `ExtensionBlocks` OrderedDict keyed by `BlockType`

**Creating a bundle:**

1. Instantiate `BPv7()` → creates empty `PrimaryBlock` and `ExtensionBlocks`
2. Set primary block parameters (route, flags, CRC type)
3. Call `primary_block.set_creation()` to set timestamp
4. Add payload via `add_payload_block(data)`
5. Add extension blocks via `add_canonical_block(block_params, data)`
6. Call `update_crc()` on primary block and modified canonical blocks
7. Convert to bytes: `bytes(bundle)` → `bundle_converter()` serializes to CBOR

**Modifying a bundle:**

1. Parse existing bundle
2. Modify block attributes (data, flags, routing, etc.)
3. Call `update_crc()` on modified blocks to recalculate checksums
4. Serialize modified bundle to bytes

**Parsing an LTP segment:**

1. Bytes → `LTP.__init__()` → `LTP.unpack()`
2. Extract control byte to determine segment type
3. Look up segment class in `SEGMENTFUNCTIONS` dict
4. Deserialize via `bundle_converter.structure()` to appropriate segment class
5. If DataSegment with client_service_id=1, attempt to parse embedded BPv7 bundle
6. Store parsed bundle in `LTP.bpv7` attribute

**Creating an LTP segment:**

1. Instantiate `LTP()` → creates empty `LTPSegment`
2. Create appropriate segment instance (DataSegment, ReportAckSegment, CancelSegment)
3. Set segment parameters (session info, type-specific fields)
4. For DataSegment containing bundles: set `LTP.bpv7` to BPv7 instance
5. Convert to bytes: `bytes(ltp_packet)` → automatically serializes embedded bundle if present

**Modifying an LTP segment with embedded bundle:**

1. Parse existing LTP segment
2. Modify embedded `ltp.bpv7` bundle attributes
3. Serialize LTP packet: embedded bundle is automatically re-serialized and data segment updated

## Important Notes

### CBOR Encoding

All bundle data is CBOR-encoded per RFC 9171. Use `cbor2` library for encoding/decoding extension block data payloads.

### SDNV Encoding

LTP segments use Self-Delimiting Numeric Values (SDNV) for variable-length integer fields. Use `encode_sdnv()` and `decode_sdnv()` from `utils.py` for encoding/decoding. SDNVs are used for session IDs, serial numbers, offsets, lengths, and other numeric fields in LTP headers.

### CRC Handling

CRCs are **not** automatically updated. After modifying any block, explicitly call `block.update_crc()` to recalculate checksums.

### EID Format

EIDs are stored internally as CBOR arrays `[scheme, scheme-specific-part]`:

- `"ipn:2.1"` → `[2, [2, 1]]`
- `"dtn://example/path"` → `[1, "//example/path"]`

Use `parse_eid_string()` and `format_eid()` for conversions.

### Block Ordering

Canonical blocks are stored in an `OrderedDict` and maintain insertion order. The payload block should typically be last.

### BPv7 and dpkt Integration

The `BPv7` class implements `__bool__()` (always returns True) and `__len__()` (returns actual serialized size) to properly integrate with dpkt's packet handling. This ensures truthiness checks work correctly and length calculations reflect CBOR's variable-length encoding rather than fixed header sizes.

### Testing Philosophy

The package supports creating non-RFC-compliant bundles (e.g., setting both DO_NOT_FRAGMENT and IS_FRAGMENT flags simultaneously). This is intentional for V&V testing of DTN implementations.

### ION Integration

Examples in `examples/` demonstrate integration with NASA JPL's ION DTN implementation, including:

- PCAP parsing of captured bundles
- Unit test simplification by replacing multi-node ION setups
- V&V testing with malformed bundles
- MITM attack simulation for BPSec testing

## Code Coverage

Target: 95% branch coverage. HTML coverage reports generated in `htmlcov/`.

## Dependencies

- `cbor2`: CBOR encoding/decoding
- `attrs`: Class definition with validation
- `cattrs`: Structure (de)serialization
- `dpkt`: Packet manipulation base class
- `fastcrc`: CRC calculations
