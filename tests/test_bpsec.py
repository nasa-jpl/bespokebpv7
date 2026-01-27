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
 Modified: 01/27/2026
 Company: JPL
 Date:   01/27/2026

 File: test_utils
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

import cbor2

from bespokebpv7.block_enum import (  # type: ignore[import-untyped]
    BIBParmEnum,
    BIBResultEnum,
    BIBSHAVariant,
    IntegrityScopeFlags,
)
from bespokebpv7.bpsec import BlockIntegrityBlock  # type: ignore[import-untyped]
from bespokebpv7.utils import bundle_converter  # type: ignore[import-untyped]


# ==========================================
# Tests for bespokebpv7/bpsec.py
# ==========================================
def test_block_integrity_block_creation() -> None:
    """Verify BIB creation"""
    bib = BlockIntegrityBlock()
    bib.security_context_id = 1

    bib.set_sha_variant()
    assert len(bib.security_parameters) == 1
    assert bib.security_parameters[0].parm_id == BIBParmEnum.SHA_VARIANT

    bib.add_wrapped_key(b"key")
    assert bib.security_parameters[1].parm_id == BIBParmEnum.WRAPPED_KEY

    bib.add_security_result(b"hash")
    assert len(bib.security_results) == 1
    assert bib.security_results[0].result_id == BIBResultEnum.EXPECTED_HMAC

    bib.include_primary_block = True
    bib.add_integrity_scope()
    assert bib.security_parameters[2].parm_id == BIBParmEnum.INTEGRITY_SCOPE_FLAGS
    assert bib.integrity_scope_flags & IntegrityScopeFlags.INCLUDE_PRIMARY_BLOCK

    assert bib.parm_present


def test_bib_roundtrip() -> None:
    """Verify BIB can structure/unstructure."""
    sha_variant = b"res"
    bib = BlockIntegrityBlock()
    bib.set_sha_variant(BIBSHAVariant.HMAC_256_256)
    bib.parm_present = True
    bib.add_security_result(sha_variant)

    out_list = bundle_converter.unstructure(bib)
    bib_data_bytes = out_list[4]
    bib_data = cbor2.loads(bib_data_bytes)

    assert bib_data[1] == 1
    assert len(bib_data) >= len(sha_variant)

    bib_new = bundle_converter.structure(out_list, BlockIntegrityBlock)
    assert len(bib_new.security_parameters) == 1
    assert len(bib_new.security_results) == 1
    assert bib_new.parm_present


def test_bib_additional_flags() -> None:
    """Verify BlockIntegrityBlock specific flag properties."""
    bib = BlockIntegrityBlock()

    flags_to_test = [
        ("include_target_header", IntegrityScopeFlags.INCLUDE_TARGET_HEADER),
        ("include_security_header", IntegrityScopeFlags.INCLUDE_SECURITY_HEADER),
    ]

    for prop_name, flag_enum in flags_to_test:
        # Default for BIB might vary, but we test toggling
        original_state = getattr(bib, prop_name)

        # Toggle
        setattr(bib, prop_name, not original_state)
        assert getattr(bib, prop_name) != original_state
        if getattr(bib, prop_name):
            assert bib.integrity_scope_flags & flag_enum
        else:
            assert not bib.integrity_scope_flags & flag_enum
