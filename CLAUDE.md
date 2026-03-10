# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This is **bespokebpv7**, a Python library for creating, parsing, and modifying Bundle Protocol version 7 (BPv7) bundles per RFC 9171. It supports Delay/Disruption Tolerant Networking (DTN) applications and can create both RFC-compliant and intentionally non-compliant bundles for testing purposes.

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

**utils.py** - Utility functions

- `parse_eid_string()`: Convert EID string to CBOR array
- `format_eid()`: Convert CBOR array to EID string
- `calculate_crc()`: Compute CRC16/CRC32 checksums
- `bundle_converter()`: Marshal bundle structures to CBOR bytes
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

## Important Notes

### CBOR Encoding

All bundle data is CBOR-encoded per RFC 9171. Use `cbor2` library for encoding/decoding extension block data payloads.

### CRC Handling

CRCs are **not** automatically updated. After modifying any block, explicitly call `block.update_crc()` to recalculate checksums.

### EID Format

EIDs are stored internally as CBOR arrays `[scheme, scheme-specific-part]`:

- `"ipn:2.1"` → `[2, [2, 1]]`
- `"dtn://example/path"` → `[1, "//example/path"]`

Use `parse_eid_string()` and `format_eid()` for conversions.

### Block Ordering

Canonical blocks are stored in an `OrderedDict` and maintain insertion order. The payload block should typically be last.

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
