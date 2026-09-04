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
 Title: Bespoke BPv7 test suite for ltp.py
 Author: Nate Richard
 Modified: 07/13/2026
 Company: JPL
 Date:   03/25/2026

 File: test_ltp
 Description:
           Tests to verify functionality of LTP segment parsing
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

import pytest
from hypothesis import given
from hypothesis import strategies as st
from strategies import st_data, st_eid

from bespokebpv7 import LTP, BPv7
from bespokebpv7.segment_enum import CancelReasonCode, LTPSegmentType
from bespokebpv7.segments import CancelSegment, DataSegment, ReportAckSegment
from bespokebpv7.utils import (  # type: ignore[import-untyped]
    format_eid,
    parse_eid_string,
)


@given(
    st.integers(min_value=0, max_value=2**32 - 1),
    st.integers(min_value=0, max_value=2**32 - 1),
    st.integers(min_value=0, max_value=2**32 - 1),
)
def test_ltp_report_ack_roundtrip(orig: int, num: int, rsn: int) -> None:
    """Verify that the LTP wrapper can pack and unpack a ReportAckSegment."""
    ra_seg = ReportAckSegment(
        session_originator=orig, session_number=num, report_serial_number=rsn
    )

    ltp_pkt = LTP()
    ltp_pkt.segment = ra_seg

    raw_bytes = bytes(ltp_pkt)

    parsed_pkt = LTP(raw_bytes)

    assert isinstance(parsed_pkt.segment, ReportAckSegment)
    assert parsed_pkt.segment.session_originator == orig
    assert parsed_pkt.segment.session_number == num
    assert parsed_pkt.segment.report_serial_number == rsn


@given(
    st.integers(min_value=0, max_value=2**32 - 1),
    st.integers(min_value=0, max_value=2**32 - 1),
    st.sampled_from(CancelReasonCode),
)
def test_ltp_cancel_roundtrip(orig: int, num: int, reason: CancelReasonCode) -> None:
    """Verify that the LTP wrapper can pack and unpack a CancelSegment."""
    cx_seg = CancelSegment(
        session_originator=orig,
        session_number=num,
        reason_code=reason,
        segment_type=LTPSegmentType.CANCEL_SENDER,
    )

    ltp_pkt = LTP()
    ltp_pkt.segment = cx_seg

    raw_bytes = bytes(ltp_pkt)
    parsed_pkt = LTP(raw_bytes)

    assert isinstance(parsed_pkt.segment, CancelSegment)
    assert parsed_pkt.segment.session_originator == orig
    assert parsed_pkt.segment.session_number == num
    assert parsed_pkt.segment.reason_code == reason


def test_ltp_wrapper_empty_buffer() -> None:
    """Verify that unpacking an empty buffer raises an appropriate error."""
    with pytest.raises(ValueError, match=r"Empty buffer provided for LTP unpacking."):
        LTP(b"")


@given(
    src_eid=st_eid,
    dst_eid=st_eid,
    payload=st_data,
    session_orig=st.integers(min_value=0, max_value=10000),
    session_num=st.integers(min_value=0, max_value=10000),
)
def test_ltp_bpv7_integration(
    src_eid: str, dst_eid: str, payload: bytes, session_orig: int, session_num: int
) -> None:
    """Verify that LTP automatically parses embedded BPv7 bundles."""
    expected_src = format_eid(parse_eid_string(src_eid))
    expected_dst = format_eid(parse_eid_string(dst_eid))

    bundle = BPv7()
    bundle.primary_block.route.source_eid = src_eid
    bundle.primary_block.route.dest_eid = dst_eid
    bundle.add_payload_block(payload)

    bundle_bytes = bytes(bundle)

    data_seg = DataSegment()
    data_seg.segment_type = LTPSegmentType.DATA_RED_CP_EORP_EOB
    data_seg.session_originator = session_orig
    data_seg.session_number = session_num
    data_seg.client_service_id = 1  # 1 == Bundle Protocol
    data_seg.client_length = len(bundle_bytes)
    data_seg.data = bundle_bytes

    ltp_packet = LTP()
    ltp_packet.segment = data_seg
    ltp_packet.data = bundle  # Link the bundle object
    ltp_packet.bpv7 = bundle

    raw_udp_payload = bytes(ltp_packet)

    received_packet = LTP(raw_udp_payload)

    assert isinstance(received_packet.segment, DataSegment)
    assert received_packet.segment.session_originator == session_orig
    assert received_packet.segment.session_number == session_num
    assert received_packet.segment.is_checkpoint is True
    assert received_packet.segment.is_eorp is True
    assert received_packet.segment.is_eob is True

    assert received_packet.bpv7 is not None
    assert isinstance(received_packet.bpv7, BPv7)
    assert received_packet.bpv7.primary_block.route.source_eid == expected_src
    assert received_packet.bpv7.primary_block.route.dest_eid == expected_dst

    received_packet.bpv7.primary_block.route.dest_eid = "ipn:9.9"
    modified_bytes = bytes(received_packet)

    final_packet = LTP(modified_bytes)
    assert final_packet.bpv7 is not None
    assert final_packet.bpv7.primary_block.route.dest_eid == "ipn:9.9"


def test_ltp_unpack_tolerates_unparsable_carried_bundle() -> None:
    """A data segment holding a bundle fragment must still unpack.

    Only the first data segment of a block begins with a bundle header;
    the rest carry fragments that cannot decode as bundles. Unpacking
    such a segment must yield the segment, with no bundle attached,
    rather than raising.
    """
    uparsable_len = 1200
    seg = DataSegment(
        session_number=1,
        client_service_id=1,
        client_offset=uparsable_len,
        client_length=200,
        data=b"x" * 200,
    )
    seg.segment_type = LTPSegmentType.DATA_RED

    packet = LTP(seg._unstructure())

    assert isinstance(packet.segment, DataSegment)
    assert packet.segment.client_offset == uparsable_len
    assert packet.bpv7 is None


def test_ltp_unpack_tolerates_undecodable_bundle_at_offset_zero() -> None:
    """A segment at offset zero that will not decode must still unpack.

    The block may continue into later segments, leaving this one a
    partial bundle, and a malformed segment may claim offset zero and
    carry anything at all. Either way the segment stays usable and no
    bundle is attached.
    """
    seg = DataSegment(
        session_number=1,
        client_service_id=1,
        client_offset=0,
        client_length=200,
        data=b"x" * 200,
    )
    seg.segment_type = LTPSegmentType.DATA_RED

    packet = LTP(seg._unstructure())

    assert isinstance(packet.segment, DataSegment)
    assert packet.segment.client_offset == 0
    assert packet.bpv7 is None


def test_ltp_unpack_does_not_swallow_unexpected_errors(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A defect in bundle decoding must reach the caller.

    The suppression around the carried bundle covers what undecodable
    input actually produces and nothing else, so that a genuine bug is
    not mistaken for a bundle that merely would not parse.
    """

    def boom(*_args: object, **_kwargs: object) -> None:
        msg = "simulated defect"
        raise AttributeError(msg)

    monkeypatch.setattr("bespokebpv7.ltp.BPv7", boom)

    seg = DataSegment(
        session_number=1,
        client_service_id=1,
        client_offset=0,
        client_length=4,
        data=b"data",
    )
    seg.segment_type = LTPSegmentType.DATA_RED

    with pytest.raises(AttributeError, match="simulated defect"):
        LTP(seg._unstructure())
