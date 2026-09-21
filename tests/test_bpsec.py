"""
------------------------------------
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
 Title: Bespoke BPv7 test suite for bpsec.py
 Author: Nate Richard
 Modified: 03/10/2026
 Company: JPL
 Date:   01/27/2026

 File: test_bpsec
 Description:
           Tests to verify functionality of bpsec classes & functions
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
from strategies import (
    st_auth_tag,
    st_bib_sha_variant,
    st_crypto_key,
    st_integrity_scope_flags,
    st_security_targets,
)

from bespokebpv7 import BlockType
from bespokebpv7.block_enum import (
    BIBParmEnum,
    BIBResultEnum,
    BIBSHAVariant,
    IntegrityScopeFlags,
)
from bespokebpv7.bpsec import BlockIntegrityBlock
from bespokebpv7.utils import (
    bundle_converter,
    decode_cbor_sequence,
)


# ==========================================
# Tests for bespokebpv7/bpsec.py
# ==========================================
@given(
    security_targets=st_security_targets,
    sha_variant=st_bib_sha_variant,
    wrapped_key=st_crypto_key,
    hmac_value=st_auth_tag,
    integrity_scope=st_integrity_scope_flags,
)
def test_block_integrity_block_creation(
    security_targets: list[int],
    sha_variant: BIBSHAVariant,
    wrapped_key: bytes,
    hmac_value: bytes,
    integrity_scope: int,
) -> None:
    """Verify BIB creation with generated data."""
    bib = BlockIntegrityBlock()

    assert bib.block_type == BlockType.BIB

    assert bib.security_context_id == 1

    bib.security_targets = security_targets
    bib.set_sha_variant(sha_variant)
    assert len(bib.security_parameters) == 1
    assert bib.security_parameters[0].parm_id == BIBParmEnum.SHA_VARIANT
    assert bib.security_parameters[0].value == sha_variant

    bib.add_wrapped_key(wrapped_key)
    assert bib.security_parameters[1].parm_id == BIBParmEnum.WRAPPED_KEY
    assert bib.security_parameters[1].value == wrapped_key

    bib.add_security_result(hmac_value)
    assert len(bib.security_results) == 1
    assert bib.security_results[0].result_id == BIBResultEnum.EXPECTED_HMAC
    assert bib.security_results[0].value == hmac_value

    bib.add_integrity_scope(integrity_scope)
    assert bib.security_parameters[2].parm_id == BIBParmEnum.INTEGRITY_SCOPE_FLAGS
    assert bib.security_parameters[2].value == integrity_scope

    assert bib.parm_present

    for param in bib.security_parameters:
        assert param.parm_id in [e.value for e in BIBParmEnum]

    for result in bib.security_results:
        assert result.result_id in [e.value for e in BIBResultEnum]


@given(
    security_targets=st_security_targets,
    sha_variant=st_bib_sha_variant,
    hmac_value=st_auth_tag,
)
def test_bib_roundtrip(
    security_targets: list[int],
    sha_variant: BIBSHAVariant,
    hmac_value: bytes,
) -> None:
    """Verify BIB can structure/unstructure with generated configurations."""
    bib = BlockIntegrityBlock()
    bib.security_targets = security_targets
    bib.set_sha_variant(sha_variant)
    bib.parm_present = True
    bib.add_security_result(hmac_value)

    out_list = bundle_converter.unstructure(bib)
    bib_data_bytes = out_list[4]
    bib_data = decode_cbor_sequence(bib_data_bytes)

    assert bib_data[1] == 1

    bib_new = bundle_converter.structure(out_list, BlockIntegrityBlock)

    assert bib_new.block_type == BlockType.BIB

    assert bib_new.security_context_id == 1

    assert len(bib_new.security_parameters) == 1
    assert len(bib_new.security_results) == 1
    assert bib_new.parm_present

    assert bib_new.security_targets == security_targets
    assert bib_new.security_parameters[0].value == sha_variant
    assert bib_new.security_results[0].value == hmac_value


@given(initial_flags=st_integrity_scope_flags)
def test_bib_additional_flags(initial_flags: int) -> None:
    """Verify BlockIntegrityBlock flag properties with generated initial states."""
    bib = BlockIntegrityBlock()

    # Set initial flag state (generated 0-7)
    bib.integrity_scope_flags = IntegrityScopeFlags(initial_flags)

    flags_to_test = [
        ("include_primary_block", IntegrityScopeFlags.INCLUDE_PRIMARY_BLOCK),
        ("include_target_header", IntegrityScopeFlags.INCLUDE_TARGET_HEADER),
        ("include_security_header", IntegrityScopeFlags.INCLUDE_SECURITY_HEADER),
    ]

    for prop_name, flag_enum in flags_to_test:
        # Get current state
        original_state = getattr(bib, prop_name)

        # Verify getter matches flag state
        assert original_state == bool(bib.integrity_scope_flags & flag_enum)

        # Toggle
        setattr(bib, prop_name, not original_state)
        assert getattr(bib, prop_name) != original_state
        if getattr(bib, prop_name):
            assert bib.integrity_scope_flags & flag_enum
        else:
            assert not bib.integrity_scope_flags & flag_enum

    assert IntegrityScopeFlags(0) <= bib.integrity_scope_flags <= IntegrityScopeFlags(7)
