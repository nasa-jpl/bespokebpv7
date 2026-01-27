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
 Modified: 01/27/2026
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

from bespokebpv7.admin_records import (  # type: ignore[import-untyped]
    BundleStatusReport,
    CompressedCustodySignal,
    CompressedReportSignal,
)
from bespokebpv7.block_enum import (  # type: ignore[import-untyped]
    AdminReasonCode,
    AdminRecordType,
    BIBParmEnum,
    BIBResultEnum,
    BIBSHAVariant,
    BlockFlags,
    BlockType,
    BundleFlags,
    CRCType,
    CREBFlags,
    CustodyAcceptanceCode,
    CustodyRefusalCode,
    IntegrityScopeFlags,
    ReportReason,
)
from bespokebpv7.blocks import (  # type: ignore[import-untyped]
    CanonicalBlock,
    CanonicalBlockInit,
    PrimaryBlock,
)
from bespokebpv7.bpsec import BlockIntegrityBlock  # type: ignore[import-untyped]
from bespokebpv7.bpv7 import BPv7  # type: ignore[import-untyped]
from bespokebpv7.bundle_params import (  # type: ignore[import-untyped]
    BaseStatusReport,
    BundleFragmentation,
    BundleLife,
    BundleRoute,
    BundleStatusInformation,
    CRBundleSequence,
    CreationTime,
    CTBundleSequence,
    StatusAssertion,
)
from bespokebpv7.ext_functions import (  # type: ignore[import-untyped]
    BundleAgeExt,
    CompressedReportingExt,
    CustodyTransferExt,
    HopCountExt,
    PreviousNodeExt,
)
from bespokebpv7.utils import (  # type: ignore[import-untyped]
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


def ct_sequence_strategy() -> st.SearchStrategy:
    """Generate CTBundleSequence objects.

    Returns:
        Custom Custody Transfer sequence

    """
    return st.builds(
        CTBundleSequence,
        dest_seq=st.integers(min_value=0),
        first_seq_num=st.integers(min_value=0),
        seq_range=st.one_of(
            st.integers(min_value=0), st.lists(st.integers(min_value=0), min_size=1)
        ),
    )


def cr_sequence_strategy() -> st.SearchStrategy:
    """Generate CRBundleSequence objects.

    Returns:
        Custom Compressed Reporting sequence

    """
    return st.builds(
        CRBundleSequence,
        dest_seq=st.integers(min_value=0),
        first_seq_num=st.integers(min_value=0),
        seq_range=st.one_of(
            st.integers(min_value=0), st.lists(st.integers(min_value=0), min_size=1)
        ),
        block_src_admin_eid=st.one_of(st.none(), st_eid),
    )


def creation_time_strategy() -> st.SearchStrategy:
    """Generate CreationTime objects.

    Returns:
        Custom creationtime

    """
    return st.builds(
        CreationTime,
        timestamp_ms=st.integers(min_value=0),
        sequence=st.integers(min_value=0),
    )


def status_assertion_strategy() -> st.SearchStrategy:
    """Generate StatusAssertion objects.

    Returns:
        Custom statusassertion

    """
    return st.builds(
        StatusAssertion,
        status_indicator=st.booleans(),
        asserted_time=st.one_of(st.none(), st.integers(min_value=0)),
    )


def bundle_status_info_strategy() -> st.SearchStrategy:
    """Generate BundleStatusInformation objects.

    Returns:
        Custom BundleStatusInformation

    """
    return st.builds(
        BundleStatusInformation,
        recv_bundle=status_assertion_strategy(),
        fwd_bundle=status_assertion_strategy(),
        deliv_bundle=status_assertion_strategy(),
        del_bundle=status_assertion_strategy(),
    )


def base_status_report_strategy() -> st.SearchStrategy:
    """Generate BaseStatusReport objects.

    Returns:
        Custom basestatusreport

    """
    return st.builds(
        BaseStatusReport,
        status_info=bundle_status_info_strategy(),
        reason_code=st.sampled_from(AdminReasonCode),
        status_src_eid=st_eid,
        status_creation_time=creation_time_strategy(),
    )


def fragmentation_strategy() -> st.SearchStrategy:
    """Generate BundleFragmentation objects.

    Returns:
        Custom bundlefragementation

    """
    return st.builds(
        BundleFragmentation,
        fragment_offset=st.integers(min_value=0),
        total_adu_len=st.integers(min_value=0),
    )


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


def test_status_assertion_methods() -> None:
    """Test helper methods in StatusAssertion."""
    sa = StatusAssertion()

    # Default state
    assert sa.asserted_time is None
    assert sa.asserted_dt is None

    # Set explicit time
    ms = 1000
    sa.set_asserted_time(ms)
    assert sa.asserted_time == ms
    assert sa.asserted_dt == DTN_EPOCH + datetime.timedelta(milliseconds=ms)

    # Set current time (auto)
    sa.set_asserted_time()
    assert sa.asserted_time is not None
    assert sa.asserted_time > ms


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
    inputs_total = [
        seq_num,
        seq_id,
        int_flag,
        parse_eid_string(expected_admin),
        parse_eid_string(expected_report),
    ]
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


def test_creb_additional_flags() -> None:
    """Verify CompressedReportingExt specific flag properties."""
    creb = CompressedReportingExt(block_type=BlockType.CREB)

    flags_to_test = [
        ("report_recv", CREBFlags.RECV_REPORT_REQ),
        ("fwd_report", CREBFlags.FWD_REPORT_REQ),
        ("deliv_report", CREBFlags.DELIV_REPORT_REQ),
        ("del_report", CREBFlags.DEL_REPORT_REQ),
        ("ct_reject_report", CREBFlags.CT_REJECT_REQ),
    ]

    for prop_name, flag_enum in flags_to_test:
        setattr(creb, prop_name, True)
        assert getattr(creb, prop_name)
        assert creb.status_report_flags
        assert creb.status_report_flags & flag_enum

        setattr(creb, prop_name, False)
        assert not getattr(creb, prop_name)


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


# ==========================================
# Tests for bespokebpv7/admin_record.py
# ==========================================
@given(st.lists(ct_sequence_strategy(), min_size=1))
def test_ccs_acceptance_api(sequences: list[CTBundleSequence]) -> None:
    """Test the set_custody_acceptance helper method."""
    ccs = CompressedCustodySignal()

    ccs.set_custody_acceptance(sequences[0])
    key = CustodyAcceptanceCode.CT_ACCEPTED
    assert key in ccs.custody_signal
    assert len(ccs.custody_signal[key]) == 1
    assert ccs.custody_signal[key][0] == sequences[0]

    if len(sequences) > 1:
        ccs.set_custody_acceptance(sequences[1:])
        assert len(ccs.custody_signal[key]) == len(sequences)


@given(st.lists(ct_sequence_strategy(), min_size=1))
def test_ccs_refusal_api(sequences: list[CTBundleSequence]) -> None:
    """Test the set_custody_refusal helper method."""
    ccs = CompressedCustodySignal()

    ccs.set_custody_refusal(sequences[0])
    key = CustodyRefusalCode.CT_REFUSED
    assert key in ccs.custody_signal
    assert len(ccs.custody_signal[key]) == 1

    if len(sequences) > 1:
        ccs.set_custody_refusal(sequences[1:])
        assert len(ccs.custody_signal[key]) == len(sequences)


@given(
    st.lists(ct_sequence_strategy(), min_size=0),
    st.lists(ct_sequence_strategy(), min_size=0),
)
def test_ccs_roundtrip(
    accept_seqs: list[CTBundleSequence], refuse_seqs: list[CTBundleSequence]
) -> None:
    """Test serialization and deserialization of CompressedCustodySignal."""
    ccs = CompressedCustodySignal()
    if accept_seqs:
        ccs.set_custody_acceptance(accept_seqs)
    if refuse_seqs:
        ccs.set_custody_refusal(refuse_seqs)

    ccs.record_type = AdminRecordType.COMPRESSED_CUSTODY_SIGNAL

    cbor_list = bundle_converter.unstructure(ccs)
    cc_cbor_list = cbor2.loads(cbor_list[-1])

    assert isinstance(cbor_list, list)
    assert len(cbor_list) == ccs.max_array_len
    assert cc_cbor_list[0] == int(AdminRecordType.COMPRESSED_CUSTODY_SIGNAL)
    assert isinstance(cc_cbor_list[1], dict)

    reconstructed = bundle_converter.structure(cbor_list, CompressedCustodySignal)

    assert reconstructed.record_type == ccs.record_type

    if accept_seqs:
        key = CustodyAcceptanceCode.CT_ACCEPTED
        assert key in reconstructed.custody_signal
        assert len(reconstructed.custody_signal[key]) == len(accept_seqs)
        assert reconstructed.custody_signal[key][0].dest_seq == accept_seqs[0].dest_seq

    if refuse_seqs:
        key = CustodyRefusalCode.CT_REFUSED
        assert key in reconstructed.custody_signal
        assert len(reconstructed.custody_signal[key]) == len(refuse_seqs)


@given(st.lists(cr_sequence_strategy(), min_size=1))
def test_crs_add_report_api(sequences: list[CRBundleSequence]) -> None:
    """Test adding reports to CompressedReportSignal."""
    crs = CompressedReportSignal()

    crs.add_report(ReportReason.RECV_REPORT, sequences[0])
    key = ReportReason.RECV_REPORT
    assert key in crs.reports
    assert len(crs.reports[key]) == 1
    assert crs.reports[key][0] == sequences[0]

    if len(sequences) > 1:
        crs.add_report(ReportReason.DELIV_REPORT, sequences[1:])
        key_del = ReportReason.DELIV_REPORT
        assert key_del in crs.reports
        assert len(crs.reports[key_del]) == len(sequences) - 1


@given(
    st.lists(cr_sequence_strategy(), min_size=0),
    st.lists(cr_sequence_strategy(), min_size=0),
)
def test_crs_roundtrip(
    recv_seqs: list[CRBundleSequence], fwd_seqs: list[CRBundleSequence]
) -> None:
    """Test serialization and deserialization of CompressedReportSignal."""
    crs = CompressedReportSignal()
    if recv_seqs:
        crs.add_report(ReportReason.RECV_REPORT, recv_seqs)
    if fwd_seqs:
        crs.add_report(ReportReason.FWD_REPORT, fwd_seqs)

    crs.record_type = AdminRecordType.COMPRESSED_REPORT_SIGNAL

    cbor_list = bundle_converter.unstructure(crs)
    cr_cbor_list = cbor2.loads(cbor_list[-1])

    assert isinstance(cbor_list, list)
    assert len(cbor_list) == crs.max_array_len
    assert cr_cbor_list[0] == int(AdminRecordType.COMPRESSED_REPORT_SIGNAL)
    assert isinstance(cr_cbor_list[1], dict)

    reconstructed = bundle_converter.structure(cbor_list, CompressedReportSignal)
    assert reconstructed.record_type == crs.record_type

    if recv_seqs:
        key = ReportReason.RECV_REPORT
        assert key in reconstructed.reports
        assert len(reconstructed.reports[key]) == len(recv_seqs)
        assert reconstructed.reports[key][0].dest_seq == recv_seqs[0].dest_seq

        # Check Optional field (block_src_admin_eid) logic
        recon_src_eid = reconstructed.reports[key][0].block_src_admin_eid
        if recv_seqs[0].block_src_admin_eid is not None and recon_src_eid is not None:
            orig_eid = recv_seqs[0].block_src_admin_eid
            assert orig_eid == recon_src_eid

    if fwd_seqs:
        key = ReportReason.FWD_REPORT
        assert key in reconstructed.reports
        assert len(reconstructed.reports[key]) == len(fwd_seqs)


@given(
    base_status_report_strategy(),
    st.one_of(st.none(), fragmentation_strategy()),
)
def test_bundle_status_report_roundtrip(
    base_status: BaseStatusReport, fragmentation: BundleFragmentation
) -> None:
    """Test serialization and deserialization of BundleStatusReport.

    Verifies:
    1. Correct handling of the fragmentation field (present vs None).
    2. Correct length of the status report list (6 elements with frag, 4 without).
    3. Data integrity after roundtrip.
    """
    report = BundleStatusReport(
        base_status=base_status,
        fragmentation=fragmentation,
        record_type=AdminRecordType.BUNDLE_STATUS_REPORT,
    )

    cbor_list = bundle_converter.unstructure(report)

    assert isinstance(cbor_list, list)
    assert len(cbor_list) == report.max_array_len

    admin_record = cbor2.loads(cbor_list[-1])
    assert admin_record[0] == int(AdminRecordType.BUNDLE_STATUS_REPORT)
    status_report = admin_record[1]

    if fragmentation is not None:
        assert len(status_report) == report.max_status_report_len
        assert status_report[4] == fragmentation.fragment_offset
        assert status_report[5] == fragmentation.total_adu_len
    else:
        assert len(status_report) == report.max_status_report_len - 2

    reconstructed = bundle_converter.structure(cbor_list, BundleStatusReport)

    assert reconstructed.record_type == report.record_type

    assert reconstructed.base_status.reason_code == base_status.reason_code
    assert reconstructed.base_status.status_src_eid == base_status.status_src_eid
    assert (
        reconstructed.base_status.status_creation_time.timestamp_ms
        == base_status.status_creation_time.timestamp_ms
    )

    assert (
        reconstructed.base_status.status_info.recv_bundle.status_indicator
        == base_status.status_info.recv_bundle.status_indicator
    )

    if fragmentation is not None:
        assert reconstructed.fragmentation is not None
        assert (
            reconstructed.fragmentation.fragment_offset == fragmentation.fragment_offset
        )
        assert reconstructed.fragmentation.total_adu_len == fragmentation.total_adu_len
    else:
        assert reconstructed.fragmentation is None
