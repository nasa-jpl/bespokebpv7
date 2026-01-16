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
 Title: Bespoke BPv7 test suite
 Author: Nate Richard
 Modified: 01/16/2026
 Company: JPL
 Date:   01/14/2026

 File: test_bespokebpv7
 Description:
           Tests to verify functionality of code
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

import datetime
import pytest
from hypothesis import given, strategies as st
import cbor2

from bespokebpv7.utils import parse_eid_string, format_eid, calculate_crc, DTN_EPOCH
from bespokebpv7.block_enum import (
    BlockType,
    BundleFlags,
    BlockFlags,
    CRCType,
    IntegrityScopeFlags,
    BIBParmEnum,
    BIBResultEnum,
    BIBSHAVariant,
)
from bespokebpv7.bundle_params import BundleRoute, BundleLife
from bespokebpv7.blocks import CanonicalBlock, PrimaryBlock, block_converter
from bespokebpv7.bpsec import BlockIntegrityBlock
from bespokebpv7.ext_functions import (
    BundleAgeExt,
    PreviousNodeExt,
    HopCountExt,
    ext_converter,
)
from bespokebpv7.bpv7 import BPv7


# --- Strategies for Hypothesis ---
st_ipn_eid = st.builds(
    lambda n, s: f"ipn:{n}.{s}",
    st.integers(min_value=1, max_value=2**32 - 1),
    st.integers(min_value=0, max_value=2**32 - 1),
)
st_dtn_eid = st.from_regex(r"^dtn:[a-zA-Z0-9]+$", fullmatch=True)
st_eid = st.one_of(st_ipn_eid, st_dtn_eid)

st_data = st.binary(max_size=1024)


# ==========================================
# Tests for bespokebpv7/utils.py
# ==========================================
@given(st_eid)
def test_eid_roundtrip(eid_str):
    """Test that parsing and then formatting an EID returns the original string."""
    parsed = parse_eid_string(eid_str)
    formatted = format_eid(parsed)
    # Note: dtn:none edge case handling might result in dtn:0 -> dtn:none
    if eid_str == "dtn:none":
        assert formatted == "dtn:none"
    elif eid_str == "dtn:0":
        assert formatted == "dtn:none"
    else:
        assert formatted == eid_str


def test_parse_eid_defaults():
    """Test parsing edge cases."""
    parsed = parse_eid_string("node1")
    assert parsed == [1, "node1"]

    parsed_none = parse_eid_string("dtn:none")
    assert parsed_none == [1, 0]

    parsed_0 = parse_eid_string("dtn:0")
    assert parsed_0 == [1, 0]


def test_calculate_crc():
    """Test CRC calculation."""
    data = [1, 2, b""]

    crc16 = calculate_crc(data, CRCType.CRC16)
    assert crc16 and len(crc16) == 2

    crc32 = calculate_crc(data, CRCType.CRC32)
    assert crc32 and len(crc32) == 4

    assert calculate_crc(data, CRCType.NONE) is None


# ==========================================
# Tests for bespokebpv7/bundle_params.py
# ==========================================
@given(st_eid, st_eid)
def test_bundle_route(src, dst):
    """Verify values are stored correctly in BundleRoute class."""
    expected_src = src
    expected_dest = dst
    if src == "dtn:0":
        expected_src = "dtn:none"

    if dst == "dtn:0":
        expected_dest = "dtn:none"

    route = BundleRoute()
    route.source_eid = src
    route.dest_eid = dst

    assert route.source_eid == expected_src
    assert route.dest_eid == expected_dest

    raw_list = [1, "test"]
    route.report_to = raw_list
    assert route.report_to == "dtn:test"


def test_bundle_life():
    """Verify bundle lifetime information is stored correctly in BundleLife."""
    life = BundleLife()
    life.timestamp_ms = 1000
    expected_dt = DTN_EPOCH + datetime.timedelta(milliseconds=1000)
    assert life.creation_dt == expected_dt


# ==========================================
# Tests for bespokebpv7/blocks.py
# ==========================================
def test_primary_block_flags():
    """Verify Primary block flags are set correctly."""
    pb = PrimaryBlock()
    assert not pb.is_fragment

    pb.is_fragment = True
    assert pb.flags & BundleFlags.IS_FRAGMENT
    assert pb.is_fragment

    pb.is_fragment = False
    assert not pb.is_fragment


def test_primary_block_creation_time():
    """Verify primary block creation time works."""
    pb = PrimaryBlock()

    pb.set_creation(12345, 1)
    assert pb.life.timestamp_ms == 12345
    assert pb.life.sequence == 1

    pb.set_creation()
    assert pb.life.timestamp_ms > 0


@given(st_eid, st_eid, st.integers(min_value=0, max_value=100))
def test_primary_block_serialization_roundtrip(src, dst, lifetime):
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

    serialized_list = block_converter.unstructure(pb)

    pb_new = block_converter.structure(serialized_list, PrimaryBlock)

    assert pb_new.route.source_eid == expected_src
    assert pb_new.route.dest_eid == expected_dest
    assert pb_new.life.lifetime == lifetime


def test_canonical_block_logic():
    """Verify canonical block creation"""
    cb = CanonicalBlock()
    cb.block_type = BlockType.UNKNOWN_BLOCK
    cb.data = b"some_data"

    assert cb.block_type == BlockType.UNKNOWN_BLOCK

    cb.delete_bundle = True
    assert cb.flags & BlockFlags.DELETE_BUNDLE

    out_list = block_converter.unstructure(cb)
    assert out_list[0] == int(BlockType.UNKNOWN_BLOCK)
    assert out_list[4] == b"some_data"


# ==========================================
# Tests for bespokebpv7/ext_functions.py
# ==========================================
def test_bundle_age_ext():
    """Verify bundle age creation"""
    age = 5000

    bae = BundleAgeExt()
    bae.block_type = BlockType.BUNDLE_AGE
    bae.age = age

    out_list = ext_converter.unstructure(bae)
    assert cbor2.loads(out_list[4]) == age

    data_bytes = cbor2.dumps(5000)
    in_list = [7, 2, 0, 0, data_bytes]

    bae_new = ext_converter.structure(in_list, BundleAgeExt)
    assert bae_new.age == age
    assert bae_new.block_type == BlockType.BUNDLE_AGE


def test_previous_node_ext():
    """Verify previous node creation"""
    previous_node = "ipn:1.0"
    cbor_pn = parse_eid_string(previous_node)

    pnb = PreviousNodeExt()
    pnb.block_type = BlockType.PREVIOUS_NODE
    pnb.previous_node = previous_node

    out_list = ext_converter.unstructure(pnb)
    assert cbor2.loads(out_list[4]) == cbor_pn

    pnb_new = ext_converter.structure(out_list, PreviousNodeExt)
    assert pnb_new.previous_node == previous_node


def test_hop_count_ext():
    """Verify hop count creation"""
    hop_limit = 10
    hop_count = 5

    hcb = HopCountExt()
    hcb.block_type = BlockType.HOP_COUNT
    hcb.hop_limit = hop_limit
    hcb.hop_count = hop_count

    out_list = ext_converter.unstructure(hcb)
    assert cbor2.loads(out_list[4]) == [hop_limit, hop_count]

    hcb_new = ext_converter.structure(out_list, HopCountExt)
    assert hcb_new.hop_limit == hop_limit
    assert hcb_new.hop_count == hop_count


# ==========================================
# Tests for bespokebpv7/bpsec.py
# ==========================================
def test_block_integrity_block_creation():
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


def test_bib_roundtrip():
    """Verify BIB can structure/unstructure."""
    bib = BlockIntegrityBlock()
    bib.set_sha_variant(BIBSHAVariant.HMAC_256_256)
    bib.parm_present = True
    bib.add_security_result(b"res")

    out_list = ext_converter.unstructure(bib)
    bib_data_bytes = out_list[4]
    bib_data = cbor2.loads(bib_data_bytes)

    assert bib_data[1] == 1
    assert len(bib_data) >= 4

    bib_new = ext_converter.structure(out_list, BlockIntegrityBlock)
    assert len(bib_new.security_parameters) == 1
    assert len(bib_new.security_results) == 1
    assert bib_new.parm_present


# ==========================================
# Tests for bespokebpv7/bpv7.py (Integration)
# ==========================================
def test_bpv7_structure():
    """Verify bundle display works."""
    bundle = BPv7()
    assert str(bundle) != ""
    assert "BPv7 BUNDLE SUMMARY" in str(bundle)
    assert repr(bundle).startswith("BPv7")


def test_bpv7_add_blocks():
    """Verify adding blocks works correctly."""
    age = 500
    bundle = BPv7()
    bundle.add_payload_block(b"payload")
    bundle.add_canonical_block(BlockType.BUNDLE_AGE, cbor2.dumps(age))

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
def test_bpv7_pack_unpack_roundtrip(src, dst, payload):
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
    b1.add_canonical_block(BlockType.BUNDLE_AGE, cbor2.dumps(age))
    raw_bytes = bytes(b1)

    b2 = BPv7(raw_bytes)
    assert b2.primary_block.route.source_eid == expected_src
    assert b2.primary_block.route.dest_eid == expected_dest

    p_blk = b2.get_block_by_type(BlockType.PAYLOAD_BLOCK)
    assert p_blk and p_blk.data == payload

    bae_blk = b2.get_block_by_type(BlockType.BUNDLE_AGE)
    assert isinstance(bae_blk, BundleAgeExt)
    assert bae_blk.age == age


def test_bpv7_unpack_crc_check():
    """Test that unpacking checks CRC and captures the specific mismatch warning."""
    b1 = BPv7()
    b1.primary_block.crc_type = CRCType.CRC16
    b1.primary_block.update_crc()

    raw = bytes(b1)
    tampered = bytearray(raw)
    tampered[-2] = tampered[-2] ^ 0xFF

    with pytest.warns(UserWarning, match="Primary Block CRC mismatch!"):
        BPv7(tampered)


def test_unpack_decode_errors():
    """Test robustness against bad data."""
    with pytest.raises(ValueError, match="Unable to decode cbor array."):
        # Unclosed indefinite array
        BPv7(b"\x9f\x01\x00\x00")


def test_bpv7_crc_setting():
    """Test setting CRC type for payload and canonical blocks."""
    bundle = BPv7()

    payload_data = b"payload_with_crc"
    bundle.add_payload_block(payload_data, crc_type=CRCType.CRC16)

    p_blk = bundle.get_block_by_type(BlockType.PAYLOAD_BLOCK)
    assert p_blk and p_blk.crc_type == CRCType.CRC16
    assert p_blk.crc is not None
    assert len(p_blk.crc) == 2

    age_data = cbor2.dumps(100)
    bundle.add_canonical_block(BlockType.BUNDLE_AGE, age_data, block_num=88, crc_type=CRCType.CRC32)

    a_blk = bundle.get_block_by_type(BlockType.BUNDLE_AGE)
    assert a_blk and a_blk.crc_type == CRCType.CRC32
    assert a_blk.crc is not None
    assert len(a_blk.crc) == 4


def test_fragmentation_settings():
    """Test that fragmentation fields are handled correctly based on flags."""
    frag_offet = 1024
    total_adu_len = 5000
    pb = PrimaryBlock()
    pb.is_fragment = True
    if pb.fragmentation:
        pb.fragmentation.fragment_offset = frag_offet
        pb.fragmentation.total_adu_len = total_adu_len
    else:
        raise ValueError("Fragmentation not created")

    assert pb.flags & BundleFlags.IS_FRAGMENT

    out_list = block_converter.unstructure(pb)
    assert frag_offet in out_list
    assert total_adu_len in out_list

    pb_new = block_converter.structure(out_list, PrimaryBlock)
    if not pb_new.fragmentation:
        raise ValueError("Fragmentation parsing Error")
    assert pb_new.is_fragment
    assert pb_new.fragmentation.fragment_offset == frag_offet
    assert pb_new.fragmentation.total_adu_len == total_adu_len

    pb.is_fragment = False
    out_list_no_frag = block_converter.unstructure(pb)

    assert frag_offet not in out_list_no_frag
    assert total_adu_len not in out_list_no_frag
