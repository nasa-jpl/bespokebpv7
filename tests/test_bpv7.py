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
 Title: Bespoke BPv7 test suite for bpv7.py
 Author: Nate Richard
 Modified: 01/27/2026
 Company: JPL
 Date:   01/14/2026

 File: test_bpv7
 Description:
           Tests to verify functionality of bpv7 classes & functions
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
import pytest
from hypothesis import given
from strategies import st_data, st_eid

from bespokebpv7 import (
    BPv7,
    BlockType,
    BundleFlags,
    CRCType,
)
from bespokebpv7.blocks import ( 
    CanonicalBlock,
    CanonicalBlockInit,
    PrimaryBlock,
)
from bespokebpv7.bundle_params import ( 
    BundleFragmentation,
)
from bespokebpv7.ext_functions import BundleAgeExt 
from bespokebpv7.utils import bundle_converter



# ==========================================
# Tests for bespokebpv7/bpv7.py (Integration)
# ==========================================
def test_bpv7_structure() -> None:
    """Verify bundle display works."""
    bundle = BPv7()
    assert str(bundle)
    assert "BPv7 BUNDLE SUMMARY" in str(bundle)
    assert repr(bundle).startswith("BPv7")


def test_bpv7_add_blocks() -> None:
    """Verify adding blocks works correctly."""
    age = 500
    bundle = BPv7()
    bundle.add_payload_block(b"payload")
    block_parms: CanonicalBlockInit = {"block_type": BlockType.BUNDLE_AGE}
    bundle.add_canonical_block(block_parms, cbor2.dumps(age))

    assert BlockType.PAYLOAD_BLOCK in bundle.blocks
    assert BlockType.BUNDLE_AGE in bundle.blocks

    p_blk = bundle.get_block_by_type(BlockType.PAYLOAD_BLOCK)
    assert isinstance(p_blk, CanonicalBlock)

    a_blk = bundle.get_block_by_type(BlockType.BUNDLE_AGE)
    assert isinstance(a_blk, BundleAgeExt)
    assert a_blk.age == age

    # Verify returns None on non-existing block
    no_blk = bundle.get_block_by_type(BlockType.BCB)
    assert no_blk is None


@given(st_eid, st_eid, st_data)
def test_bpv7_pack_unpack_roundtrip(src: str, dst: str, payload: bytes) -> None:
    """Full serialization round trip."""
    expected_src = src
    expected_dest = dst
    if src == "dtn:0":
        expected_src = "dtn:none"

    if dst == "dtn:0":
        expected_dest = "dtn:none"

    age = 300
    b1 = BPv7()
    b1.primary_block.route.source_eid = src
    b1.primary_block.route.dest_eid = dst
    b1.primary_block.set_creation(1000, 0)

    b1.add_payload_block(payload)
    block_parms: CanonicalBlockInit = {"block_type": BlockType.BUNDLE_AGE}
    b1.add_canonical_block(block_parms, cbor2.dumps(age))
    raw_bytes = bytes(b1)

    b2 = BPv7(raw_bytes)
    assert b2.primary_block.route.source_eid == expected_src
    assert b2.primary_block.route.dest_eid == expected_dest

    p_blk = b2.get_block_by_type(BlockType.PAYLOAD_BLOCK)
    assert p_blk
    assert p_blk.data == payload

    bae_blk = b2.get_block_by_type(BlockType.BUNDLE_AGE)
    assert isinstance(bae_blk, BundleAgeExt)
    assert bae_blk.age == age


def test_bpv7_unpack_crc_check() -> None:
    """Test that unpacking checks CRC and captures the specific mismatch warning."""
    b1 = BPv7()
    b1.primary_block.crc_type = CRCType.CRC16
    b1.primary_block.update_crc()

    raw = bytes(b1)
    tampered = bytearray(raw)
    tampered[-2] ^= 0xFF

    with pytest.warns(UserWarning, match="Primary Block CRC mismatch!"):
        BPv7(tampered)


def test_unpack_decode_errors() -> None:
    """Test robustness against bad data."""
    with pytest.raises(ValueError, match="CBOR decoding issue"):
        # Unclosed indefinite array
        BPv7(b"\x9f\x01\x00\x00")


def test_bpv7_crc_setting() -> None:
    """Test setting CRC type for payload and canonical blocks."""
    bundle = BPv7()

    payload_data = b"payload_with_crc"
    bundle.add_payload_block(payload_data, crc_type=CRCType.CRC16)

    p_blk = bundle.get_block_by_type(BlockType.PAYLOAD_BLOCK)
    assert p_blk
    assert p_blk.crc_type == CRCType.CRC16
    assert p_blk.crc is not None
    assert len(p_blk.crc) == len(CRCType.CRC16.fill_value)

    age_data = cbor2.dumps(100)
    block_parms: CanonicalBlockInit = {
        "block_type": BlockType.BUNDLE_AGE,
        "block_num": 88,
        "crc_type": CRCType.CRC32,
    }
    bundle.add_canonical_block(block_parms, age_data)

    a_blk = bundle.get_block_by_type(BlockType.BUNDLE_AGE)
    assert a_blk
    assert a_blk.crc_type == CRCType.CRC32
    assert a_blk.crc is not None
    assert len(a_blk.crc) == len(CRCType.CRC32.fill_value)


def test_fragmentation_settings() -> None:
    """Test that fragmentation fields are handled correctly based on flags.

    Raises:
        ValueError: If there is an issue defining fragmentation.

    """
    errmsg = "Fragmentation error"
    frag_offset = 1024
    total_adu_len = 5000
    frag = BundleFragmentation(fragment_offset=frag_offset, total_adu_len=total_adu_len)
    pb = PrimaryBlock(fragmentation=frag)
    pb.is_fragment = True

    assert pb.flags & BundleFlags.IS_FRAGMENT

    out_list = bundle_converter.unstructure(pb)
    assert frag_offset in out_list
    assert total_adu_len in out_list

    pb_new = bundle_converter.structure(out_list, PrimaryBlock)
    if not pb_new.fragmentation:
        raise ValueError(errmsg)
    assert pb_new.is_fragment
    assert pb_new.fragmentation.fragment_offset == frag_offset
    assert pb_new.fragmentation.total_adu_len == total_adu_len

    pb.is_fragment = False
    out_list_no_frag = bundle_converter.unstructure(pb)

    assert frag_offset not in out_list_no_frag
    assert total_adu_len not in out_list_no_frag


def test_bpv7_debug_mode(capsys: pytest.CaptureFixture[str]) -> None:
    """Verify that debug mode prints output during parsing."""
    # Create a simple bundle
    b_src = BPv7()
    b_src.add_payload_block(b"test_debug")
    raw_data = bytes(b_src)

    # Unpack with debug=True
    BPv7(raw_data, debug=True)

    # Check stdout for debug messages
    captured = capsys.readouterr()
    assert "received:  9f" in captured.out
    assert "processed: 9f" in captured.out
    assert "header  in" in captured.out
