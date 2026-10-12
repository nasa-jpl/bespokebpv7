# CLAUDE.md

Last verified: 2026-10-12

This file provides guidance for working with the **bespokebpv7** repository.

## Project Overview

**bespokebpv7** is a Python library for creating, parsing, and modifying BPv7 bundles (RFC 9171) and LTP segments (RFC 5326). It supports DTN applications and allows creation of both RFC-compliant and non-compliant packets for V&V testing.

## Development Commands

### Testing
```bash
tox                # Run all tests (Python 3.10-3.14)
tox -e 3.12        # Run for specific version
tox -e coverage    # Generate coverage report (run `tox -e clean` first)
pytest             # Run pytest directly (in venv)
pytest tests/test_bpv7.py::test_fn  # Run specific test
```

### Linting and Type Checking
```bash
tox -e lint        # Ruff linting and formatting
tox -e markdownlint # Markdown linting
tox -e type        # mypy type checking
tox -e pyright     # Pyright type checking
ruff check --fix . # Fix lint errors directly (in venv)
```

### Building & Examples
```bash
uv build           # Build package
cd examples/<dir> && ./dotest  # Run specific example tests
```

## Architecture

### Core Structure
- **Primary Block**: Routing and lifetime metadata.
- **Canonical Blocks**: Ordered collection of extension blocks and the payload.

### Key Modules

**Bundle Core**
- `bpv7.py`: `BPv7` (main class, extends `dpkt.Packet`).
- `blocks.py`: `PrimaryBlock`, `CanonicalBlock`, `ExtensionBlocks`, `BaseBlock`.
- `bundle_params.py`: Route, Life, Fragmentation, Status Report, and Custody Transfer params.
- `block_enum.py`: `BlockType`, `BundleFlags`, `BlockFlags`, `CRCType`.

**Extensions & Security**
- `ext_functions.py`: `BundleAgeExt`, `PreviousNodeExt`, `HopCountExt`, and ION extensions.
- `bpsec.py`: `AbstractSecurityBlock`, `BlockIntegrityBlock` (BIB).
- `admin_records.py`: `AdminRecord`, `BundleStatusReport`, and ION signals.

**LTP (Licklider Transmission Protocol)**
- `ltp.py`: `LTP` (main class, extracts BPv7 from `client_service_id=1` segments).
- `segments.py`: `LTPSegment`, `DataSegment`, `ReportAckSegment`, `CancelSegment`.
- `segment_enum.py`: `LTPSegmentType`, `CancelReasonCode`.

**TCPCL (TCP Convergence Layer)**
- `tcpcl.py`: `TCPCL` packet and `TCPCLStreamParser`.
- `tcpcl_messages.py`: `TCPCLMessage` hierarchy (v3/v4) and embedded BPv7 extraction.
- `tcpcl_enum.py`: `TCPCLVersion`, `TCPCLv3MessageType`, `TCPCLv4MessageType`.

**Utilities**
- `utils.py`: EID formatting, CRC calculation, CBOR conversion, and SDNV encoding/decoding.

### Data Flow

**Bundle Lifecycle:**
- **Parse**: `BPv7.unpack()` $\rightarrow$ CBOR decode $\rightarrow$ `PrimaryBlock` $\rightarrow$ `ExtensionBlocks`.
- **Create**: `BPv7()` $\rightarrow$ set route/flags $\rightarrow$ `set_creation()` $\rightarrow$ `add_payload_block()` $\rightarrow$ `add_canonical_block()` $\rightarrow$ `update_crc()`.
- **Modify**: Parse $\rightarrow$ modify attributes $\rightarrow$ `update_crc()` $\rightarrow$ serialize to bytes.

**LTP Lifecycle:**
- **Parse**: `LTP.unpack()` $\rightarrow$ `SEGMENTFUNCTIONS` $\rightarrow$ `bundle_converter.structure()` $\rightarrow$ extract `LTP.bpv7`.
- **Create**: `LTP()` $\rightarrow$ set segment type/params $\rightarrow$ assign `LTP.bpv7` $\rightarrow$ serialize.

## Important Notes

### Encoding & Format
- **CBOR**: All bundle data is CBOR-encoded (via `cbor2`) per RFC 9171.
- **SDNV**: LTP uses Self-Delimiting Numeric Values (via `utils.py`) for variable-length integers.
- **EIDs**: Stored as `[scheme, scheme-specific-part]`. Use `parse_eid_string()` / `format_eid()`.

### Implementation Details
- **CRC**: Not automatic. Explicitly call `block.update_crc()` after modifications.
- **Ordering**: Canonical blocks use `OrderedDict`; payload should typically be last.
- **dpkt**: `BPv7` implements `__bool__` and `__len__` for seamless `dpkt` integration.

### Testing Philosophy
- **V&V**: Support for non-RFC-compliant packets is intentional for testing DTN implementations.
- **Property-Based Testing**: Tests should follow property-based testing principles and use the `hypothesis` library wherever possible to ensure robustness across a wide range of inputs.
- **Coverage**: Target 95% branch coverage.

## Dependencies
- `cbor2`, `attrs`, `cattrs`, `dpkt`, `fastcrc`
