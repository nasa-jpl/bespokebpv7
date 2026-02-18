# BCB Support Design

## Summary

This design adds Block Confidentiality Block (BCB) support to bespokebpv7, enabling the library to create and parse BCB extension blocks as specified in RFC 9173 section 4. BCB provides confidentiality services for Bundle Protocol v7 using AES-GCM encryption, complementing the existing Block Integrity Block (BIB) implementation that provides integrity services.

The implementation mirrors the proven BIB pattern: BlockConfidentialityBlock extends AbstractSecurityBlock, inheriting common security infrastructure while adding BCB-specific functionality for AAD (Additional Authenticated Data) scope management. The class handles block structure, security parameters (IV, AES variant, wrapped key, AAD scope flags), and security results (authentication tag) but delegates actual cryptographic operations to external tools, matching the library's role as a bundle manipulation toolkit. The design includes enum extensions for BCB-specific identifiers, BLOCKFUNCTIONS registration for automatic parsing, and comprehensive unit tests targeting 95%+ coverage.

## Definition of Done

Add BlockConfidentialityBlock class to bespokebpv7 that mirrors the existing BlockIntegrityBlock implementation for creating and parsing BCB extension blocks per RFC 9173 section 4.

**Success Criteria:**
- BlockConfidentialityBlock class extends AbstractSecurityBlock (matching BIB pattern)
- Supports BCB-AES-GCM security context (context ID = 2) with AES-128 and AES-256 variants
- Implements security parameters: IV, AES variant, wrapped key, AAD scope flags
- Implements security result: authentication tag
- Populates AADScopeFlags enum with appropriate flags (INCLUDE_PRIMARY_BLOCK, INCLUDE_TARGET_HEADER, INCLUDE_SECURITY_HEADER)
- Adds BCBParmEnum and BCBResultEnum to block_enum.py
- Registers BlockConfidentialityBlock in BLOCKFUNCTIONS dictionary
- Unit tests achieve 95% or greater code coverage
- Supports structure/unstructure (CBOR encoding/decoding) for round-trip serialization
- Does NOT perform actual AES-GCM encryption/decryption (just block structure handling)

## Acceptance Criteria

### bcb-support.AC1: BlockConfidentialityBlock class structure
- **bcb-support.AC1.1 Success:** BlockConfidentialityBlock extends AbstractSecurityBlock
- **bcb-support.AC1.2 Success:** BCB instance has block_type = BlockType.BCB (enum value 12)
- **bcb-support.AC1.3 Success:** BCB instance has security_context_id = 2 by default
- **bcb-support.AC1.4 Success:** BCB inherits security_targets, security_context_flags, security_source, security_parameters, security_results from AbstractSecurityBlock
- **bcb-support.AC1.5 Success:** BCB has aad_scope_flags attribute (BCB-specific)
- **bcb-support.AC1.6 Success:** __attrs_post_init__ sets security_context_flags = SecurityContextFlags(1) and aad_scope_flags = AADScopeFlags(7)

### bcb-support.AC2: Security parameters handling
- **bcb-support.AC2.1 Success:** set_aes_variant() adds SecurityParameter with BCBParmEnum.AES_VARIANT and sets parm_present = True
- **bcb-support.AC2.2 Success:** set_aes_variant() defaults to AES_GCM_256 when no variant specified
- **bcb-support.AC2.3 Success:** set_aes_variant(BCBAESVariant.AES_GCM_128) adds AES_GCM_128 parameter
- **bcb-support.AC2.4 Success:** add_wrapped_key(key_bytes) adds SecurityParameter with BCBParmEnum.WRAPPED_KEY
- **bcb-support.AC2.5 Success:** add_aad_scope() adds SecurityParameter with BCBParmEnum.AAD_SCOPE_FLAGS using current aad_scope_flags value
- **bcb-support.AC2.6 Success:** add_aad_scope(explicit_value) adds SecurityParameter with specified value
- **bcb-support.AC2.7 Success:** Multiple parameters can be added to security_parameters list

### bcb-support.AC3: Security results handling
- **bcb-support.AC3.1 Success:** add_security_result(tag_bytes) adds SecurityResult with BCBResultEnum.AUTH_TAG
- **bcb-support.AC3.2 Success:** Multiple results can be added to security_results list

### bcb-support.AC4: AAD scope flag management
- **bcb-support.AC4.1 Success:** include_primary_block property getter returns True when INCLUDE_PRIMARY_BLOCK flag set
- **bcb-support.AC4.2 Success:** include_primary_block property setter sets INCLUDE_PRIMARY_BLOCK flag bit
- **bcb-support.AC4.3 Success:** include_target_header property toggles INCLUDE_TARGET_HEADER flag bit
- **bcb-support.AC4.4 Success:** include_security_header property toggles INCLUDE_SECURITY_HEADER flag bit
- **bcb-support.AC4.5 Success:** set_scope_flag(flag) sets individual AADScopeFlags bit
- **bcb-support.AC4.6 Success:** clear_scope_flag(flag) clears individual AADScopeFlags bit
- **bcb-support.AC4.7 Success:** Flag properties correctly delegate to set_scope_flag/clear_scope_flag

### bcb-support.AC5: CBOR encoding/decoding
- **bcb-support.AC5.1 Success:** _unstructure() produces CBOR-encodable list with inner security data in self.data bytes field
- **bcb-support.AC5.2 Success:** _unstructure() includes parameters array when parm_present is True
- **bcb-support.AC5.3 Success:** _unstructure() wraps results in nested list [[result1, result2, ...]]
- **bcb-support.AC5.4 Success:** _structure() parses CBOR list and populates all BCB attributes
- **bcb-support.AC5.5 Success:** _structure() correctly handles conditional parameters based on parm_present flag
- **bcb-support.AC5.6 Success:** Roundtrip (unstructure → structure) preserves all BCB data
- **bcb-support.AC5.7 Success:** CBOR encoding uses encode_cbor_sequence for inner data
- **bcb-support.AC5.8 Success:** CBOR decoding uses decode_cbor_sequence for inner data
- **bcb-support.AC5.9 Success:** bundle_converter.structure/unstructure correctly handle SecurityParameter and SecurityResult objects

### bcb-support.AC6: Enum definitions
- **bcb-support.AC6.1 Success:** BCBAESVariant enum exists with AES_GCM_128 and AES_GCM_256 values
- **bcb-support.AC6.2 Success:** BCBParmEnum enum exists with IV=1, AES_VARIANT=2, WRAPPED_KEY=3, AAD_SCOPE_FLAGS=4
- **bcb-support.AC6.3 Success:** BCBResultEnum enum exists with AUTH_TAG=1
- **bcb-support.AC6.4 Success:** AADScopeFlags enum has INCLUDE_PRIMARY_BLOCK=1, INCLUDE_TARGET_HEADER=2, INCLUDE_SECURITY_HEADER=4
- **bcb-support.AC6.5 Success:** AADScopeFlags is IntFlag type supporting bitwise operations

### bcb-support.AC7: BLOCKFUNCTIONS integration
- **bcb-support.AC7.1 Success:** BLOCKFUNCTIONS dict in ext_functions.py maps BlockType.BCB to BlockConfidentialityBlock
- **bcb-support.AC7.2 Success:** BlockConfidentialityBlock is imported in ext_functions.py
- **bcb-support.AC7.3 Success:** Bundles with BCB blocks automatically parse to BlockConfidentialityBlock instances

### bcb-support.AC8: Test coverage
- **bcb-support.AC8.1 Success:** Test coverage for bpsec.py BCB code is 95% or greater
- **bcb-support.AC8.2 Success:** Creation test verifies parameter/result addition and flag manipulation
- **bcb-support.AC8.3 Success:** Roundtrip test verifies CBOR encoding/decoding preserves data
- **bcb-support.AC8.4 Success:** Flag test verifies AAD scope flag properties work correctly

### bcb-support.AC9: Scope boundaries
- **bcb-support.AC9.1 Success:** BlockConfidentialityBlock does NOT implement AES-GCM encryption
- **bcb-support.AC9.2 Success:** BlockConfidentialityBlock does NOT implement AES-GCM decryption
- **bcb-support.AC9.3 Success:** BlockConfidentialityBlock does NOT generate initialization vectors
- **bcb-support.AC9.4 Success:** BlockConfidentialityBlock does NOT wrap or unwrap encryption keys
- **bcb-support.AC9.5 Success:** BlockConfidentialityBlock does NOT calculate authentication tags
- **bcb-support.AC9.6 Success:** BCB provides structure only, matching BIB's pattern of delegating cryptographic operations

## Glossary

- **AAD (Additional Authenticated Data)**: Data that is authenticated but not encrypted in AEAD ciphers like AES-GCM. BCB's AAD scope flags determine which bundle components (primary block, target header, security header) are included in AAD.
- **AbstractSecurityBlock**: Base class in bpsec.py that provides common infrastructure for BPSec blocks (BIB and BCB), including security targets, context ID, flags, source, parameters, and results.
- **AES-GCM**: Advanced Encryption Standard in Galois/Counter Mode, an authenticated encryption cipher that provides both confidentiality and integrity. RFC 9173 specifies AES-GCM for BCB with 128-bit or 256-bit keys.
- **BCB (Block Confidentiality Block)**: BPSec extension block type that provides confidentiality services by encrypting bundle data. Defined in RFC 9173 section 4.
- **BIB (Block Integrity Block)**: BPSec extension block type that provides integrity services using HMAC. Existing implementation in bespokebpv7 that BCB mirrors.
- **BLOCKFUNCTIONS**: Dictionary in ext_functions.py that maps BlockType enums to their corresponding class implementations, enabling automatic block parsing.
- **BPSec (Bundle Protocol Security)**: Security framework for Bundle Protocol v7 defined in RFC 9171/9173, providing integrity (BIB) and confidentiality (BCB) services.
- **BPv7 (Bundle Protocol version 7)**: Delay/Disruption Tolerant Networking protocol defined in RFC 9171, designed for networks with intermittent connectivity.
- **CBOR (Concise Binary Object Representation)**: Binary data serialization format (RFC 8949) used by BPv7 for encoding bundle data structures.
- **RFC 9173**: IETF specification for Bundle Protocol Security (BPSec), defining BIB and BCB security blocks.
- **Security Context**: BPSec concept identifying which security operations and parameters apply to a block. BCB uses security context ID 2 for BCB-AES-GCM.
- **attrs**: Python library for class definition with automatic initialization and validation, used throughout bespokebpv7.

## Architecture

BCB support extends the existing BPSec foundation in `src/bespokebpv7/bpsec.py` by mirroring the proven BlockIntegrityBlock pattern. BlockConfidentialityBlock extends AbstractSecurityBlock, inheriting common security block infrastructure (security_targets, security_context_id, security_context_flags, security_source, security_parameters, security_results) while adding BCB-specific AAD scope handling.

The implementation follows RFC 9173 section 4 for BCB-AES-GCM:
- Security context ID = 2 (distinguishes BCB from BIB's context ID 1)
- Block type = BlockType.BCB (enum value 12 already exists)
- Security parameters: initialization vector, AES variant (128-bit or 256-bit), wrapped key, AAD scope flags
- Security result: 128-bit authentication tag

Like BIB, BCB handles block structure only - no cryptographic operations. The class creates and parses BCB blocks but delegates actual AES-GCM encryption/decryption to external tools, matching the library's role as a bundle creation/parsing toolkit.

Enum extensions in `src/bespokebpv7/block_enum.py`:
- BCBAESVariant: AES_GCM_128 and AES_GCM_256 identifiers
- BCBParmEnum: Parameter IDs matching RFC 9173 (IV=1, AES_VARIANT=2, WRAPPED_KEY=3, AAD_SCOPE_FLAGS=4)
- BCBResultEnum: AUTH_TAG result ID (1)
- AADScopeFlags: Populate existing empty enum with INCLUDE_PRIMARY_BLOCK, INCLUDE_TARGET_HEADER, INCLUDE_SECURITY_HEADER

BlockConfidentialityBlock registers in BLOCKFUNCTIONS dictionary (`src/bespokebpv7/ext_functions.py`) mapped to BlockType.BCB, enabling automatic parsing when bundles contain BCB blocks.

## Existing Patterns

Investigation found BlockIntegrityBlock in `src/bespokebpv7/bpsec.py` (lines 192-318) provides the template:

**Class Structure Pattern:**
- Extends AbstractSecurityBlock (lines 167-189)
- Uses @define decorator from attrs
- Implements __attrs_post_init__ to set defaults
- Default security_context_flags = SecurityContextFlags(1) to indicate parameters present
- Block-specific flags (IntegrityScopeFlags for BIB, AADScopeFlags for BCB)

**Property Pattern:**
- Flag property factory functions (integrity_flag_property lines 87-105, will need aad_flag_property parallel)
- Generate boolean properties that manipulate flag bits
- Each property delegates to set_scope_flag/clear_scope_flag methods

**Parameter/Result Pattern:**
- Helper methods to add parameters (set_sha_variant, add_wrapped_key, add_integrity_scope)
- Each sets parm_present = True when adding parameters
- Results added via add_security_result method
- Parameters and results stored as SecurityParameter and SecurityResult objects

**CBOR Encoding Pattern:**
- _structure classmethod parses CBOR list to object
- _unstructure method converts object to CBOR list
- Inner security data encoded separately in self.data bytes field
- Conditional parameter handling based on parm_present flag
- Uses encode_cbor_sequence/decode_cbor_sequence and bundle_converter

**Test Pattern (tests/test_bpsec.py):**
- Creation test: verify parameters and results added correctly
- Roundtrip test: unstructure to CBOR, structure back, verify preservation
- Flag test: verify property setters toggle flag bits correctly

BCB implementation follows these patterns exactly to maintain codebase consistency.

## Implementation Phases

<!-- START_PHASE_1 -->
### Phase 1: Enum Additions

**Goal:** Add BCB-specific enumerations to block_enum.py

**Components:**
- BCBAESVariant enum in `src/bespokebpv7/block_enum.py` — AES_GCM_128 and AES_GCM_256 cipher suite identifiers
- BCBParmEnum enum — parameter IDs (IV=1, AES_VARIANT=2, WRAPPED_KEY=3, AAD_SCOPE_FLAGS=4)
- BCBResultEnum enum — AUTH_TAG result ID (1)
- AADScopeFlags enum — populate existing empty enum with INCLUDE_PRIMARY_BLOCK=1, INCLUDE_TARGET_HEADER=2, INCLUDE_SECURITY_HEADER=4

**Dependencies:** None (first phase)

**Done when:** All enums defined, project builds without errors, enums importable

<!-- END_PHASE_1 -->

<!-- START_PHASE_2 -->
### Phase 2: BlockConfidentialityBlock Class

**Goal:** Implement BCB class structure with parameter/result handling

**Components:**
- aad_flag_property factory function in `src/bespokebpv7/bpsec.py` — generates properties for AAD scope flag manipulation (parallel to integrity_flag_property)
- BlockConfidentialityBlock class in `src/bespokebpv7/bpsec.py` — extends AbstractSecurityBlock with BCB-specific attributes and methods
  - Attributes: block_type, security_context_id, aad_scope_flags
  - Flag properties: include_primary_block, include_target_header, include_security_header
  - Parameter methods: set_aes_variant, add_wrapped_key, add_aad_scope
  - Result method: add_security_result
  - Flag methods: set_scope_flag, clear_scope_flag
  - Initialization: __attrs_post_init__ sets defaults

**Dependencies:** Phase 1 (enums must exist)

**Done when:** BlockConfidentialityBlock instantiates, parameter/result methods work, flag properties toggle correctly, tests pass for bcb-support.AC1 (class creation and parameter handling)

<!-- END_PHASE_2 -->

<!-- START_PHASE_3 -->
### Phase 3: CBOR Encoding/Decoding

**Goal:** Implement structure/unstructure for CBOR serialization

**Components:**
- _structure classmethod in BlockConfidentialityBlock — parses CBOR list to BCB object
- _unstructure method in BlockConfidentialityBlock — converts BCB object to CBOR list
- CBOR encoding/decoding of security parameters and results using SecurityParameter and SecurityResult classes

**Dependencies:** Phase 2 (class structure must exist)

**Done when:** BCB can serialize to CBOR bytes and deserialize back, roundtrip preserves all data, tests pass for bcb-support.AC2 (CBOR encoding/decoding)

<!-- END_PHASE_3 -->

<!-- START_PHASE_4 -->
### Phase 4: Registration and Integration

**Goal:** Register BCB in BLOCKFUNCTIONS for automatic parsing

**Components:**
- BLOCKFUNCTIONS entry in `src/bespokebpv7/ext_functions.py` — add BlockType.BCB: BlockConfidentialityBlock mapping
- Import BlockConfidentialityBlock in ext_functions.py

**Dependencies:** Phase 3 (BCB class must be complete)

**Done when:** BCB automatically parsed when reading bundles with BCB blocks, BLOCKFUNCTIONS lookup returns BlockConfidentialityBlock for BlockType.BCB, tests pass for bcb-support.AC3 (integration)

<!-- END_PHASE_4 -->

## Additional Considerations

**No cryptographic operations:** BCB handles block structure only. IV generation, key wrapping/unwrapping, AES-GCM encryption/decryption, and authentication tag calculation are delegated to external tools. This matches BIB's approach where HMAC calculation happens externally.

**Test coverage target:** 95% branch coverage achieved through three test categories mirroring BIB tests:
1. Creation test: parameter/result addition, flag manipulation
2. Roundtrip test: _structure/_unstructure CBOR encoding paths
3. Flag test: property getters/setters, flag bit manipulation

These tests cover all public methods and both encoding directions.
