# Design Guidance for bespokebpv7

## Project Context

This is a Python library for Bundle Protocol version 7 (BPv7) per RFC 9171 and Licklider Transmission Protocol (LTP) per RFC 5326, supporting DTN applications. The project is maintained by NASA JPL with specific requirements for V&V testing of DTN implementations. LTP segments can contain embedded BPv7 bundles, which are automatically parsed when client_service_id=1.

## Domain Terminology

- **BPv7**: Bundle Protocol version 7 (RFC 9171) - DTN bundle format
- **LTP**: Licklider Transmission Protocol (RFC 5326 / CCSDS 734.1-B-1) - reliable data transfer for DTN
- **DTN**: Delay/Disruption Tolerant Networking - networking for extreme environments
- **BPSec**: Bundle Protocol Security (RFC 9172/9173) - security extension
- **BCB**: Block Confidentiality Block - provides encryption (security context ID = 2)
- **BIB**: Block Integrity Block - provides integrity/authentication (security context ID = 1)
- **Extension block**: Canonical blocks beyond the payload (e.g., Bundle Age, Previous Node, Hop Count)
- **LTP Segment**: LTP data unit (data/report/cancel types) with SDNV-encoded headers
- **SDNV**: Self-Delimiting Numeric Value - variable-length integer encoding used in LTP
- **ION**: NASA JPL's ION DTN implementation - reference implementation for testing
- **CBOR**: Concise Binary Object Representation (RFC 8949) - bundle encoding format
- **EID**: Endpoint Identifier - addressing in DTN (ipn: or dtn: schemes)
- **Primary block**: Required first block containing routing and lifetime metadata
- **Canonical block**: Payload and extension blocks (ordered collection)
- **V&V**: Verification and Validation - includes testing with intentionally malformed bundles

## Architectural Constraints

**REQUIRED patterns:**
- All block classes extend `dpkt.Packet` (for `BPv7`) or `CanonicalBlock` base
- LTP class extends `dpkt.Packet` with segment type detection via control byte
- Use `attrs` classes with `@define` decorator for data structures
- Use `cattrs` (`bundle_converter`) for structure/unstructure to CBOR-encodable lists
- CBOR encoding/decoding via `cbor2` library exclusively for BPv7
- SDNV encoding/decoding via `encode_sdnv()`/`decode_sdnv()` exclusively for LTP
- Extension blocks MUST register in `BLOCKFUNCTIONS` dict (maps `BlockType` → class)
- LTP segments MUST register in `SEGMENTFUNCTIONS` dict (maps `LTPSegmentType` → class)
- Admin records MUST register in `ADMINFUNCTIONS` dict (maps `AdminRecordType` → class)
- CRC updates are MANUAL - must explicitly call `block.update_crc()` after modifications

**BPv7 data flow pattern:**
- **Parse**: bytes → `BPv7.unpack()` → CBOR decode → populate blocks via `BLOCKFUNCTIONS`
- **Create**: instantiate → set parameters → `update_crc()` → `bytes(bundle)` serializes via `bundle_converter`
- **Modify**: parse → modify attributes → `update_crc()` → serialize

**LTP data flow pattern:**
- **Parse**: bytes → `LTP.unpack()` → extract control byte → `SEGMENTFUNCTIONS` lookup → deserialize → auto-parse embedded bundles if client_service_id=1
- **Create**: instantiate `LTP()` → create segment (DataSegment/ReportAckSegment/CancelSegment) → set `LTP.bpv7` for bundles → serialize auto-embeds bundle
- **Modify**: parse → modify `ltp.bpv7` attributes → serialize auto-updates data segment

**EID normalization:**
- `"dtn:0"` normalizes to `"dtn:none"` automatically
- Tests must account for this normalization in assertions
- Internal storage: CBOR arrays `[scheme, scheme-specific-part]`
- Use `parse_eid_string()` and `format_eid()` for conversions

## Technology Stack

**Required dependencies:**
- Python 3.10-3.14 (multi-version support required)
- `cbor2` - CBOR encoding/decoding
- `attrs` - class definitions with validation
- `cattrs` - structure (de)serialization
- `dpkt` - packet manipulation base
- `fastcrc` - CRC16/CRC32 calculations

**Testing stack:**
- `pytest` - test runner
- `hypothesis` - property-based testing (PREFERRED for data structure tests)
- `tox` - multi-version test orchestration
- `ruff` - linting and formatting
- `mypy` - type checking (strict mode)

**Build:**
- `uv` build backend

**Preferences:**
- Property-based testing with Hypothesis for data structures, serialization, and flag operations
- Custom strategies centralized in `tests/strategies.py`
- Roundtrip tests (serialize → deserialize → verify) for all block types

## Testing Philosophy

**CRITICAL**: This project intentionally supports creating non-RFC-compliant bundles for V&V testing.

**Design implications:**
- Do NOT enforce RFC compliance in code (validation is optional)
- Tests must cover BOTH RFC-compliant AND intentionally non-compliant cases
- Example: Setting both `DO_NOT_FRAGMENT` and `IS_FRAGMENT` flags simultaneously is allowed
- Purpose: Test that DTN implementations properly reject malformed bundles

**Coverage requirements:**
- Target: 95% branch coverage minimum
- HTML reports generated in `htmlcov/`
- Hypothesis tests improve coverage by exercising edge cases

## ION Integration

New security/extension/LTP features should include ION integration examples in `examples/`:
- PCAP parsing examples (BPv7 and LTP)
- Unit test simplification (replace multi-node ION setups)
- MITM testing for BPSec features
- LTP segment parsing from ION traffic

Not every feature needs ION examples, but security features and major protocol additions typically do.

## Scope Boundaries

**Typically IN scope:**
- Extension block implementations
- LTP segment type implementations
- Security block enhancements
- Admin record types
- Serialization improvements
- Test coverage improvements
- V&V test capabilities (both BPv7 and LTP)
- Embedded bundle parsing in LTP data segments

**Typically OUT of scope (unless explicitly requested):**
- Network transport (this is bundle/segment format only, not transmission)
- Routing algorithms (bundle creation/parsing only)
- LTP retransmission logic (segment format only, not transmission protocol)
- Performance optimization (correctness > speed)
- CLI tools (library focus)
- GUI/visualization tools
