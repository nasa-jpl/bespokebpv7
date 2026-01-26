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
 Modified: 01/26/2026
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

import cbor2
import pytest
from hypothesis import given
from hypothesis import strategies as st

from bespokebpv7.block_enum import (
    BIBParmEnum,
    BIBResultEnum,
    BIBSHAVariant,
    BlockFlags,
    BlockType,
    BundleFlags,
    CRCType,
    CREBFlags,
    IntegrityScopeFlags,
)
from bespokebpv7.blocks import (
    CanonicalBlock,
    CanonicalBlockInit,
    PrimaryBlock,
)
from bespokebpv7.bpsec import BlockIntegrityBlock
from bespokebpv7.bpv7 import BPv7
from bespokebpv7.bundle_params import BundleFragmentation, BundleLife, BundleRoute
from bespokebpv7.ext_functions import (
    BundleAgeExt,
    CompressedReportingExt,
    CustodyTransferExt,
    HopCountExt,
    PreviousNodeExt,
)
from bespokebpv7.utils import (
    DTN_EPOCH,
    bundle_converter,
    calculate_crc,
    format_eid,
    parse_eid_string,
)

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
def test_eid_roundtrip(eid_str: str) -> None:
    """Test that parsing and then formatting an EID returns the original string."""
    parsed = parse_eid_string(eid_str)
    formatted = format_eid(parsed)
    # Note: dtn:none edge case handling might result in dtn:0 -> dtn:none
    if eid_str in {"dtn:none", "dtn:0"}:
        assert formatted == "dtn:none"
    else:
        assert formatted == eid_str


def test_parse_eid_defaults() -> None:
    """Test parsing edge cases."""
    parsed = parse_eid_string("node1")
    assert parsed == [1, "node1"]

    parsed_none = parse_eid_string("dtn:none")
    assert parsed_none == [1, 0]

    parsed_0 = parse_eid_string("dtn:0")
    assert parsed_0 == [1, 0]


def test_calculate_crc() -> None:
    """Test CRC calculation."""
    data = [1, 2, b""]

    crc16 = calculate_crc(data, CRCType.CRC16)
    assert crc16
    assert len(crc16) == len(CRCType.CRC16.fill_value)

    crc32 = calculate_crc(data, CRCType.CRC32)
    assert crc32
    assert len(crc32) == len(CRCType.CRC32.fill_value)

    assert calculate_crc(data, CRCType.NONE) is None


# ==========================================
# Tests for bespokebpv7/bundle_params.py
# ==========================================
@given(st_eid, st_eid)
def test_bundle_route(src: str, dst: str) -> None:
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


def test_bundle_life() -> None:
    """Verify bundle lifetime information is stored correctly in BundleLife."""
    life = BundleLife()
    life.timestamp_ms = 1000
    expected_dt = DTN_EPOCH + datetime.timedelta(milliseconds=1000)
    assert life.creation_dt == expected_dt


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


# ==========================================
# Tests for bespokebpv7/ext_functions.py
# ==========================================
def test_bundle_age_ext() -> None:
    """Verify bundle age creation"""
    age = 5000

    bae = BundleAgeExt()
    bae.block_type = BlockType.BUNDLE_AGE
    bae.age = age

    out_list = bundle_converter.unstructure(bae)
    assert cbor2.loads(out_list[4]) == age

    data_bytes = cbor2.dumps(5000)
    in_list = [7, 2, 0, 0, data_bytes]

    bae_new = bundle_converter.structure(in_list, BundleAgeExt)
    assert bae_new.age == age
    assert bae_new.block_type == BlockType.BUNDLE_AGE


@given(st_eid)
def test_previous_node_ext(prev_eid: str) -> None:
    """Verify previous node creation"""
    expected_prev = prev_eid
    if prev_eid == "dtn:0":
        expected_prev = "dtn:none"
    cbor_pn = parse_eid_string(expected_prev)

    pnb = PreviousNodeExt()
    pnb.block_type = BlockType.PREVIOUS_NODE
    pnb.previous_node = expected_prev

    out_list = bundle_converter.unstructure(pnb)
    assert cbor2.loads(out_list[4]) == cbor_pn

    pnb_new = bundle_converter.structure(out_list, PreviousNodeExt)
    assert pnb_new.previous_node == expected_prev


@given(st.integers(min_value=0), st.integers(min_value=0))
def test_hop_count_ext(hop_limit: int, hop_count: int) -> None:
    """Verify hop count creation"""
    hcb = HopCountExt()
    hcb.block_type = BlockType.HOP_COUNT
    hcb.hop_limit = hop_limit
    hcb.hop_count = hop_count

    out_list = bundle_converter.unstructure(hcb)
    assert cbor2.loads(out_list[4]) == [hop_limit, hop_count]

    hcb_new = bundle_converter.structure(out_list, HopCountExt)
    assert hcb_new.hop_limit == hop_limit
    assert hcb_new.hop_count == hop_count


@given(st.integers(min_value=0), st.integers(min_value=0), st_eid)
def test_ct_ext(seq_num: int, seq_id: int, admin_eid: str) -> None:
    """Verify custody transfer creation"""
    expected_admin = admin_eid
    if admin_eid == "dtn:0":
        expected_admin = "dtn:none"

    cteb = CustodyTransferExt(block_type=BlockType.CTEB)
    cteb.sequence_num = seq_num
    cteb.sequence_id = seq_id
    cteb.block_src_admin_eid = expected_admin

    out_list = bundle_converter.unstructure(cteb)
    assert cbor2.loads(out_list[4]) == [seq_num, seq_id, parse_eid_string(admin_eid)]

    cteb_new = bundle_converter.structure(out_list, CustodyTransferExt)
    assert cteb_new.sequence_num == seq_num
    assert cteb_new.sequence_id == seq_id
    assert cteb_new.block_src_admin_eid == expected_admin


@given(
    st.integers(min_value=0),
    st.integers(min_value=0),
    st.integers(min_value=0, max_value=63),
    st_eid,
    st_eid,
    st.integers(min_value=1, max_value=5),
)
def test_cr_ext(
    seq_num: int,
    seq_id: int,
    int_flag: int,
    admin_eid: str,
    report_eid: str,
    array_len: int,
) -> None:
    """Verify custody report creation"""
    expected_admin = admin_eid
    expected_report = report_eid
    if admin_eid == "dtn:0":
        expected_admin = "dtn:none"

    if report_eid == "dtn:0":
        expected_report = "dtn:none"

    # since length can vary we'll truncate after the fact based on array_len value
    inputs_total = [seq_num, seq_id, int_flag, expected_admin, expected_report]
    inputs = inputs_total[:array_len]

    creb = CompressedReportingExt(block_type=BlockType.CREB)
    for idx, val in enumerate(inputs):
        key = creb.__slots__[idx]  # pyright: ignore[reportAttributeAccessIssue] pylint: disable=E1101
        setattr(creb, key, val)

    out_list = bundle_converter.unstructure(creb)
    assert cbor2.loads(out_list[4]) == inputs

    creb_new = bundle_converter.structure(out_list, CompressedReportingExt)
    for idx, val in enumerate(inputs):
        key = creb_new.__slots__[idx]  # pyright: ignore[reportAttributeAccessIssue] pylint: disable=E1101
        assert getattr(creb_new, key) == val


def test_cr_ext_flags() -> None:
    """Verify CREB flag setting"""
    creb = CompressedReportingExt(block_type=BlockType.CREB)
    creb.ct_accept_report = True
    assert creb.status_report_flags
    assert creb.status_report_flags & CREBFlags.CT_ACCEPT_REQ

    creb.ct_accept_report = False
    assert not creb.ct_accept_report


@given(st_eid, st_eid)
def test_cr_ext_eids(admin_eid: str, report_eid: str) -> None:
    """Verify CREB EIDs are set correctly."""
    expected_admin = admin_eid
    expected_report = report_eid
    if admin_eid == "dtn:0":
        expected_admin = "dtn:none"

    if report_eid == "dtn:0":
        expected_report = "dtn:none"

    # need to fill rest of array
    seq_id = 0
    flags = 0

    creb = CompressedReportingExt(block_type=BlockType.CREB)
    creb.block_src_admin_eid = expected_admin
    creb.report_to_eid = expected_report
    creb.sequence_id = seq_id
    creb.status_report_flags = flags

    out_list = bundle_converter.unstructure(creb)
    creb_new = bundle_converter.structure(out_list, CompressedReportingExt)
    assert creb_new.block_src_admin_eid == expected_admin
    assert creb_new.report_to_eid == expected_report


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
