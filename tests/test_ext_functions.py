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
 Title: Bespoke BPv7 test suite for ext_functions.py
 Author: Nate Richard
 Modified: 01/27/2026
 Company: JPL
 Date:   01/27/2026

 File: test_ext_functions
 Description:
           Tests to verify functionality of ext_functions classes & functions
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
from strategies import st_creb_params, st_eid

from bespokebpv7 import (
    BlockType,
)
from bespokebpv7.block_enum import CREBFlags
from bespokebpv7.ext_functions import ( 
    BPQExt,
    BundleAgeExt,
    CompressedReportingExt,
    CustodyTransferExt,
    HopCountExt,
    PreviousNodeExt,
)
from bespokebpv7.utils import ( 
    bundle_converter,
    parse_eid_string,
)


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


@given(st_creb_params)
def test_cr_ext(params: tuple[int, int, int, str, str, int]) -> None:
    """Verify custody report creation"""
    seq_num, seq_id, int_flag, admin_eid, report_eid, array_len = params

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


@given(
    st.integers(min_value=0, max_value=255),  # qos_flags
    st.integers(min_value=0, max_value=255),  # class_of_service
    st.integers(min_value=0),  # ordinal
    st.integers(min_value=0),  # data_label
)
def test_qos_ext(
    qos_flags: int, class_of_service: int, ordinal: int, data_label: int
) -> None:
    """Verify Quality of Service (QoS) extension creation and roundtrip."""
    qos_block = BPQExt(block_type=BlockType.QOS)
    qos_block.qos_flags = qos_flags
    qos_block.class_of_service = class_of_service
    qos_block.ordinal = ordinal
    qos_block.data_label = data_label

    out_list = bundle_converter.unstructure(qos_block)

    assert cbor2.loads(out_list[4]) == [
        qos_flags,
        class_of_service,
        ordinal,
        data_label,
    ]

    qos_new = bundle_converter.structure(out_list, BPQExt)

    assert qos_new.block_type == BlockType.QOS
    assert qos_new.qos_flags == qos_flags
    assert qos_new.class_of_service == class_of_service
    assert qos_new.ordinal == ordinal
    assert qos_new.data_label == data_label
