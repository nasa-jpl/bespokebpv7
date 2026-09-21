"""------------------------------------
     JET PROPULSION LABORATORY
------------------------------------
         ___  _______  ___
        |   ||       ||   |
        |   ||    _  ||   |
        |   ||   |_| ||   |
     ___|   ||    ___||   |___
    |       ||   |    |       |
    |_______||___|    |_______|

------------------------------------
 CALIFORNIA INSTITUTE OF TECHNOLOGY
------------------------------------

*****************************************************************************
 Title: Bespoke BPv7 test suite for BCB (Block Confidentiality Block)
 Author: Nate Richard
 Modified: 03/10/2026
 Company: JPL
 Date:   02/18/2026

 File: test_bcb
 Description:
           Tests to verify functionality of BlockConfidentialityBlock
           Python 3.12.11

Copyright 2025, by the California Institute of Technology. United States
Government sponsorship acknowledged. Any rights or license to commercial use
must be negotiated with the Office of Technology Transfer at the California
Institute of Technology.

This software may be subject to U.S. export control laws and regulations. By
accepting this software, the user agrees to comply with all applicable U.S.
export laws and regulations. The user has the responsibility to obtain export
licenses, or other export authority as may be required before exporting the
software to foreign countries or providing access to foreign persons.
*****************************************************************************
"""

from hypothesis import given
from hypothesis import strategies as st
from strategies import (
    st_aad_scope_flags,
    st_auth_tag,
    st_bcb_aes_variant,
    st_crypto_key,
    st_security_targets,
)

from bespokebpv7.block_enum import (
    AADScopeFlags,
    BCBAESVariant,
    BCBParmEnum,
    BCBResultEnum,
    BlockType,
)
from bespokebpv7.blocks import CanonicalBlock
from bespokebpv7.bpsec import BlockConfidentialityBlock
from bespokebpv7.ext_functions import BLOCKFUNCTIONS
from bespokebpv7.utils import (
    bundle_converter,
    decode_cbor_sequence,
)


# ==========================================
# Tests for BlockConfidentialityBlock
# ==========================================
@given(
    aes_variant=st_bcb_aes_variant,
    wrapped_key=st_crypto_key,
    auth_tag=st_auth_tag,
    aad_scope=st_aad_scope_flags,
)
def test_block_confidentiality_block_creation(
    aes_variant: BCBAESVariant,
    wrapped_key: bytes,
    auth_tag: bytes,
    aad_scope: int,
) -> None:
    """Verify BCB creation and parameter/result handling with generated data."""
    expected_context = 2
    sec_parms = 3
    sec_results = 2

    bcb = BlockConfidentialityBlock()
    assert hasattr(bcb, "security_targets")
    assert hasattr(bcb, "security_context_id")
    assert hasattr(bcb, "security_context_flags")
    assert hasattr(bcb, "security_source")
    assert hasattr(bcb, "security_parameters")
    assert hasattr(bcb, "security_results")

    assert bcb.block_type == BlockType.BCB

    assert bcb.security_context_id == expected_context

    assert hasattr(bcb, "aad_scope_flags")

    assert bcb.security_context_flags.value == 1
    assert bcb.aad_scope_flags == AADScopeFlags(7)

    bcb.set_aes_variant(aes_variant)
    assert len(bcb.security_parameters) == 1
    assert bcb.security_parameters[0].parm_id == BCBParmEnum.AES_VARIANT
    assert bcb.security_parameters[0].value == aes_variant
    assert bcb.parm_present

    assert (len(bcb.security_parameters) > 0) == bcb.parm_present

    bcb.add_wrapped_key(wrapped_key)
    assert bcb.security_parameters[1].parm_id == BCBParmEnum.WRAPPED_KEY
    assert bcb.security_parameters[1].value == wrapped_key

    bcb.add_aad_scope(aad_scope)
    assert bcb.security_parameters[2].parm_id == BCBParmEnum.AAD_SCOPE_FLAGS
    assert bcb.security_parameters[2].value == aad_scope

    assert len(bcb.security_parameters) == sec_parms

    for param in bcb.security_parameters:
        assert param.parm_id in [e.value for e in BCBParmEnum]

    bcb.add_security_result(auth_tag)
    assert len(bcb.security_results) == 1
    assert bcb.security_results[0].result_id == BCBResultEnum.AUTH_TAG
    assert bcb.security_results[0].value == auth_tag

    for result in bcb.security_results:
        assert result.result_id in [e.value for e in BCBResultEnum]

    bcb.add_security_result(auth_tag)
    assert len(bcb.security_results) == sec_results


@given(initial_flags=st_aad_scope_flags)
def test_bcb_aad_scope_flags(initial_flags: int) -> None:
    """Verify AAD scope flag properties work correctly with generated initial states."""
    bcb = BlockConfidentialityBlock()

    bcb.aad_scope_flags = AADScopeFlags(initial_flags)

    # AC4.1: Getter returns True when flag set
    assert bcb.include_primary_block == bool(
        initial_flags & AADScopeFlags.INCLUDE_PRIMARY_BLOCK
    )
    assert bcb.include_target_header == bool(
        initial_flags & AADScopeFlags.INCLUDE_TARGET_HEADER
    )
    assert bcb.include_security_header == bool(
        initial_flags & AADScopeFlags.INCLUDE_SECURITY_HEADER
    )

    bcb.set_scope_flag(AADScopeFlags.INCLUDE_PRIMARY_BLOCK)
    value_after_first_set = bcb.aad_scope_flags.value
    bcb.set_scope_flag(AADScopeFlags.INCLUDE_PRIMARY_BLOCK)
    value_after_second_set = bcb.aad_scope_flags.value
    assert value_after_first_set == value_after_second_set

    bcb.aad_scope_flags = AADScopeFlags(initial_flags)
    bcb.set_scope_flag(AADScopeFlags.INCLUDE_TARGET_HEADER)
    assert bcb.include_target_header is True
    bcb.clear_scope_flag(AADScopeFlags.INCLUDE_TARGET_HEADER)
    assert bcb.include_target_header is False  # Inverse property

    bcb.aad_scope_flags = AADScopeFlags(initial_flags)
    primary_before = bcb.include_primary_block
    security_before = bcb.include_security_header
    bcb.include_target_header = not bcb.include_target_header
    assert bcb.include_primary_block == primary_before
    assert bcb.include_security_header == security_before

    assert AADScopeFlags(0) <= bcb.aad_scope_flags <= AADScopeFlags(7)

    bcb.include_primary_block = False
    assert bcb.include_primary_block is False
    assert not bcb.aad_scope_flags & AADScopeFlags.INCLUDE_PRIMARY_BLOCK
    assert AADScopeFlags(0) <= bcb.aad_scope_flags <= AADScopeFlags(7)

    bcb.include_primary_block = True
    assert bcb.include_primary_block is True
    assert bcb.aad_scope_flags & AADScopeFlags.INCLUDE_PRIMARY_BLOCK
    assert AADScopeFlags(0) <= bcb.aad_scope_flags <= AADScopeFlags(7)

    bcb.aad_scope_flags = AADScopeFlags(0)
    bcb.set_scope_flag(AADScopeFlags.INCLUDE_PRIMARY_BLOCK)
    assert bcb.aad_scope_flags & AADScopeFlags.INCLUDE_PRIMARY_BLOCK
    assert bcb.aad_scope_flags.value == 1
    assert AADScopeFlags(0) <= bcb.aad_scope_flags <= AADScopeFlags(7)

    bcb.aad_scope_flags = AADScopeFlags(7)  # Set all
    bcb.clear_scope_flag(AADScopeFlags.INCLUDE_TARGET_HEADER)
    assert not bcb.aad_scope_flags & AADScopeFlags.INCLUDE_TARGET_HEADER
    assert bcb.aad_scope_flags == AADScopeFlags(5)  # 0b101
    assert AADScopeFlags(0) <= bcb.aad_scope_flags <= AADScopeFlags(7)


@given(
    security_targets=st_security_targets,
    aes_variant=st_bcb_aes_variant,
    wrapped_key=st_crypto_key,
    auth_tag=st_auth_tag,
    aad_scope=st_aad_scope_flags,
)
def test_bcb_roundtrip(
    security_targets: list[int],
    aes_variant: BCBAESVariant,
    wrapped_key: bytes,
    auth_tag: bytes,
    aad_scope: int,
) -> None:
    """Verify BCB can structure/unstructure with generated configurations."""
    sec_context = 2
    bcb_data_len = 3

    bcb = BlockConfidentialityBlock()
    bcb.security_targets = security_targets
    bcb.set_aes_variant(aes_variant)
    bcb.add_wrapped_key(wrapped_key)
    bcb.add_aad_scope(aad_scope)
    bcb.parm_present = True
    bcb.add_security_result(auth_tag)

    out_list = bundle_converter.unstructure(bcb)
    assert isinstance(out_list, list)
    assert len(out_list) >= bcb.max_array_len

    # 5 elements: block_type, block_number, block_flags, crc_type, data
    # 6 elements if crc_value present (depends on crc_type)
    assert len(out_list) in {bcb.max_array_len, bcb.max_array_len + 1}

    bcb_data_bytes = out_list[4]
    assert isinstance(bcb_data_bytes, bytes)
    bcb_data = decode_cbor_sequence(bcb_data_bytes)

    assert bcb_data[1] == sec_context
    assert len(bcb_data[4]) == bcb_data_len  # Three parameters

    assert isinstance(bcb_data[5], list)
    assert isinstance(bcb_data[5][0], list)

    bcb_new = bundle_converter.structure(out_list, BlockConfidentialityBlock)
    assert bcb_new.security_context_id == sec_context
    assert bcb_new.parm_present
    assert len(bcb_new.security_parameters) == bcb_data_len
    assert len(bcb_new.security_results) == 1

    assert bcb_new.security_targets == security_targets
    assert bcb_new.security_parameters[0].parm_id == BCBParmEnum.AES_VARIANT
    assert bcb_new.security_parameters[0].value == aes_variant
    assert bcb_new.security_parameters[1].parm_id == BCBParmEnum.WRAPPED_KEY
    assert bcb_new.security_parameters[1].value == wrapped_key
    assert bcb_new.security_parameters[2].parm_id == BCBParmEnum.AAD_SCOPE_FLAGS
    assert bcb_new.security_parameters[2].value == aad_scope
    assert bcb_new.security_results[0].result_id == BCBResultEnum.AUTH_TAG
    assert bcb_new.security_results[0].value == auth_tag

    out_list_2 = bundle_converter.unstructure(bcb_new)
    bcb_data_bytes_2 = out_list_2[4]
    bcb_data_2 = decode_cbor_sequence(bcb_data_bytes_2)
    assert bcb_data == bcb_data_2  # Serialization stable


@given(
    security_targets=st_security_targets,
    auth_tag=st_auth_tag,
    parm_present=st.booleans(),
)
def test_bcb_roundtrip_without_parameters(
    security_targets: list[int],
    auth_tag: bytes,
    parm_present: bool,
) -> None:
    """Verify BCB roundtrip when parm_present varies.

    Verifies: bcb-support.AC5.5 (conditional parameter handling)
    Verifies: hypothesis-bcb-bib.AC2.4, AC2.6, AC5.9
    """
    bcb = BlockConfidentialityBlock()
    bcb.security_targets = security_targets
    bcb.parm_present = parm_present
    bcb.add_security_result(auth_tag)

    out_list = bundle_converter.unstructure(bcb)
    bcb_data_bytes = out_list[4]
    bcb_data = decode_cbor_sequence(bcb_data_bytes)

    if parm_present:
        assert len(bcb_data) == bcb.max_array_len + 1
        assert isinstance(bcb_data[4], list)  # Parameters array
        assert isinstance(bcb_data[5], list)  # Results
    else:
        assert len(bcb_data) == bcb.max_array_len
        assert isinstance(bcb_data[4], list)  # Results directly after source

    # 5 or 6 elements depending on CRC presence (not parm_present)
    assert len(out_list) in {bcb.max_array_len, bcb.max_array_len + 1}

    # Roundtrip
    bcb_new = bundle_converter.structure(out_list, BlockConfidentialityBlock)
    assert bcb_new.parm_present == parm_present
    assert len(bcb_new.security_parameters) == 0  # No params added in this test
    assert len(bcb_new.security_results) == 1
    assert bcb_new.security_targets == security_targets
    assert bcb_new.security_results[0].value == auth_tag


@given(
    security_targets=st_security_targets,
    aes_variant=st_bcb_aes_variant,
    auth_tag=st_auth_tag,
)
def test_bcb_blockfunctions_integration(
    security_targets: list[int],
    aes_variant: BCBAESVariant,
    auth_tag: bytes,
) -> None:
    """Verify BCB automatically parses when reading bundles with generated blocks."""
    sec_context = 2
    assert BlockType.BCB in BLOCKFUNCTIONS
    assert BLOCKFUNCTIONS[BlockType.BCB] == BlockConfidentialityBlock

    bcb = BlockConfidentialityBlock()
    bcb.block_number = 2
    bcb.security_targets = security_targets
    bcb.set_aes_variant(aes_variant)
    bcb.add_security_result(auth_tag)

    serialized = bundle_converter.unstructure(bcb)

    block_type = BlockType(serialized[0])
    assert block_type == BlockType.BCB  # STATIC

    block_class = BLOCKFUNCTIONS.get(block_type, CanonicalBlock)
    assert block_class == BlockConfidentialityBlock  # STATIC

    parsed_bcb = bundle_converter.structure(serialized, block_class)
    assert isinstance(parsed_bcb, BlockConfidentialityBlock)
    assert parsed_bcb.block_type == BlockType.BCB  # STATIC
    assert parsed_bcb.security_context_id == sec_context

    assert parsed_bcb.security_targets == security_targets
    assert parsed_bcb.security_parameters[0].value == aes_variant
    assert parsed_bcb.security_results[0].value == auth_tag
