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
 Title: Bespoke BPv7 test suite for blocks.py
 Author: Nate Richard
 Modified: 01/27/2026
 Company: JPL
 Date:   01/27/2026

 File: test_blocks
 Description:
           Tests to verify functionality of blocks classes & functions
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
from hypothesis import given
from hypothesis import strategies as st
from strategies import st_eid

from bespokebpv7 import (
    BlockFlags,
    BlockType,
    BundleFlags,
    BPv7,
)
from bespokebpv7.blocks import ( 
    CanonicalBlock,
    CanonicalBlockInit,
    PrimaryBlock,
)
from bespokebpv7.utils import bundle_converter


# ==========================================
# Tests for bespokebpv7/blocks.py
# ==========================================
def test_primary_block_flags() -> None:
    """Verify Primary block flags are set correctly."""
    pb = PrimaryBlock()
    assert not pb.is_fragment

    pb.is_fragment = True
    assert pb.flags & BundleFlags.IS_FRAGMENT
    assert pb.is_fragment

    pb.is_fragment = False
    assert not pb.is_fragment


def test_primary_block_creation_time() -> None:
    """Verify primary block creation time works."""
    btimestamp = 12345
    bseq = 1
    pb = PrimaryBlock()

    pb.set_creation(btimestamp, bseq)
    assert pb.life.timestamp_ms == btimestamp
    assert pb.life.sequence == bseq

    pb.set_creation()
    assert pb.life.timestamp_ms > 0


@given(st_eid, st_eid, st.integers(min_value=0, max_value=100))
def test_primary_block_serialization_roundtrip(
    src: str, dst: str, lifetime: int
) -> None:
    """Verify primary block encodes and decodes correctly."""
    expected_src = src
    expected_dest = dst
    if src == "dtn:0":
        expected_src = "dtn:none"

    if dst == "dtn:0":
        expected_dest = "dtn:none"

    pb = PrimaryBlock()
    pb.route.source_eid = src
    pb.route.dest_eid = dst
    pb.life.lifetime = lifetime

    serialized_list = bundle_converter.unstructure(pb)

    pb_new = bundle_converter.structure(serialized_list, PrimaryBlock)

    assert pb_new.route.source_eid == expected_src
    assert pb_new.route.dest_eid == expected_dest
    assert pb_new.life.lifetime == lifetime


def test_canonical_block_logic() -> None:
    """Verify canonical block creation"""
    cb = CanonicalBlock()
    cb.block_type = BlockType.UNKNOWN_BLOCK
    cb.data = b"some_data"

    assert cb.block_type == BlockType.UNKNOWN_BLOCK

    cb.delete_bundle = True
    assert cb.flags & BlockFlags.DELETE_BUNDLE

    out_list = bundle_converter.unstructure(cb)
    assert out_list[0] == int(BlockType.UNKNOWN_BLOCK)
    assert out_list[4] == b"some_data"


def test_primary_block_additional_flags() -> None:
    """Verify all PrimaryBlock flag properties toggle correctly."""
    pb = PrimaryBlock()

    # Test toggling individual flags
    flags_to_test = [
        ("adu_is_admin", BundleFlags.ADU_IS_ADMIN_RECORD),
        ("no_fragment", BundleFlags.DO_NOT_FRAGMENT),
        ("ack_requested", BundleFlags.ACK_REQUESTED),
        ("status_time", BundleFlags.STATUS_TIME),
        ("deliv_report", BundleFlags.STATUS_REPORT_DELIV),
        ("fwd_report", BundleFlags.STATUS_REPORT_FWD),
        ("recv_report", BundleFlags.STATUS_REPORT_RECV),
        ("del_report", BundleFlags.STATUS_REPORT_DEL),
    ]

    for prop_name, flag_enum in flags_to_test:
        # Should be False by default
        assert not getattr(pb, prop_name)
        assert not pb.flags & flag_enum

        # Set True
        setattr(pb, prop_name, True)
        assert getattr(pb, prop_name)
        assert pb.flags & flag_enum

        # Set False
        setattr(pb, prop_name, False)
        assert not getattr(pb, prop_name)
        assert not pb.flags & flag_enum


def test_canonical_block_additional_flags() -> None:
    """Verify all CanonicalBlock flag properties toggle correctly."""
    cb = CanonicalBlock()

    flags_to_test = [
        ("replica_fragment", BlockFlags.REPLICATE_FRAGMENT),
        ("status_report", BlockFlags.STATUS_BUNDLE),
        ("delete_bundle", BlockFlags.DELETE_BUNDLE),
        ("discard_block", BlockFlags.DISCARD_BLOCK),
    ]

    for prop_name, flag_enum in flags_to_test:
        assert not getattr(cb, prop_name)

        setattr(cb, prop_name, True)
        assert getattr(cb, prop_name)
        assert cb.flags & flag_enum

        setattr(cb, prop_name, False)
        assert not getattr(cb, prop_name)


def test_extension_blocks_ordering() -> None:
    """Verify that adding a block after Payload block moves Payload to the end."""
    bundle = BPv7()

    bundle.add_payload_block(b"payload")

    hcb_parms: CanonicalBlockInit = {"block_type": BlockType.HOP_COUNT}
    bundle.add_canonical_block(hcb_parms, cbor2.dumps([10, 5]))

    keys = list(bundle.blocks.keys())
    assert keys[-1] == BlockType.PAYLOAD_BLOCK
    assert BlockType.HOP_COUNT in keys

    raw = bytes(bundle)
    decoded = cbor2.loads(raw)
    assert decoded[1][0] == int(BlockType.HOP_COUNT)
    assert decoded[2][0] == int(BlockType.PAYLOAD_BLOCK)
