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
 Title: Bespoke BPv7 test suite for ltp_segments.py
 Author: Nate Richard
 Modified: 03/31/2026
 Company: JPL
 Date:   03/24/2026

 File: test_segments
 Description:
           Tests to verify functionality of LTP segments
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
from strategies import st_data_segment_types

from bespokebpv7 import (
    CancelReasonCode,
    LTPSegmentType,
)
from bespokebpv7.segments import (
    CancelSegment,
    DataSegment,
    ReportAckSegment,
)
from bespokebpv7.utils import encode_sdnv


# ==========================================
# Tests for LTP Segments
# ==========================================
@given(
    st.integers(min_value=0, max_value=2**32 - 1),
    st.integers(min_value=0, max_value=2**32 - 1),
    st.integers(min_value=0, max_value=2**32 - 1),
)
def test_report_ack_segment_roundtrip(orig: int, num: int, rsn: int) -> None:
    """Verify ReportAckSegment serializes and deserializes correctly."""
    ra_seg = ReportAckSegment(
        session_originator=orig, session_number=num, report_serial_number=rsn
    )

    raw_bytes = ra_seg._unstructure()

    parsed_seg = ReportAckSegment._structure(raw_bytes)

    assert parsed_seg.segment_type == LTPSegmentType.REPORT_ACK
    assert parsed_seg.session_originator == orig
    assert parsed_seg.session_number == num
    assert parsed_seg.report_serial_number == rsn


@given(
    st.integers(min_value=0, max_value=2**32 - 1),
    st.integers(min_value=0, max_value=2**32 - 1),
    st.sampled_from(CancelReasonCode),
)
def test_cancel_segment_roundtrip(
    orig: int, num: int, reason: CancelReasonCode
) -> None:
    """Verify CancelSegment serializes and deserializes correctly."""
    cx_seg = CancelSegment(
        session_originator=orig,
        session_number=num,
        reason_code=reason,
        segment_type=LTPSegmentType.CANCEL_SENDER,
    )

    raw_bytes = cx_seg._unstructure()
    parsed_seg = CancelSegment._structure(raw_bytes)

    assert parsed_seg.segment_type == LTPSegmentType.CANCEL_SENDER
    assert parsed_seg.session_originator == orig
    assert parsed_seg.session_number == num
    assert parsed_seg.reason_code == reason


def test_invalid_segment_type() -> None:
    """Verify that parsing a byte array with the wrong segment type raises an error."""
    # Manually build a header for a DATA segment (0x00)
    # segment type 0x0 + flags 0x0 = 0x00
    bad_header = bytearray([0x00])
    bad_header.extend(encode_sdnv(1))  # orig
    bad_header.extend(encode_sdnv(1))  # num
    bad_header.extend(encode_sdnv(0))  # ext
    bad_header.extend(encode_sdnv(0))  # ext

    with pytest.raises(ValueError, match=r"Expected CANCEL"):
        CancelSegment._structure(bytes(bad_header))


@given(
    seg_type=st_data_segment_types,
    sdnv_params=st.tuples(
        st.integers(min_value=0, max_value=1000),  # client_service_id
        st.integers(min_value=0, max_value=10000),  # client_offset
        st.integers(min_value=0, max_value=10000),  # cp_serial
        st.integers(min_value=0, max_value=10000),  # report_serial
    ),
    payload=st.binary(max_size=256),
)
def test_data_segment_roundtrip(
    seg_type: LTPSegmentType,
    sdnv_params: tuple[int, int, int, int],
    payload: bytes,
) -> None:
    """Verify DataSegment de/serialization with all valid data segment types."""
    client_service_id, client_offset, cp_serial, report_serial = sdnv_params

    seg = DataSegment()
    seg.segment_type = seg_type

    seg.client_service_id = client_service_id
    seg.client_offset = client_offset
    seg.client_length = len(payload)
    seg.checkpoint_serial_number = cp_serial
    seg.report_serial_number = report_serial
    seg.data = payload

    raw_bytes = seg._unstructure()

    parsed_seg = DataSegment._structure(raw_bytes)

    assert parsed_seg.segment_type == seg_type

    expected_is_cp = seg_type in {
        LTPSegmentType.DATA_RED_CP,
        LTPSegmentType.DATA_RED_CP_EORP,
        LTPSegmentType.DATA_RED_CP_EORP_EOB,
    }

    assert parsed_seg.is_checkpoint == expected_is_cp
    assert parsed_seg.client_service_id == client_service_id
    assert parsed_seg.client_offset == client_offset
    assert parsed_seg.client_length == len(payload)

    if expected_is_cp:
        assert parsed_seg.checkpoint_serial_number == cp_serial
        assert parsed_seg.report_serial_number == report_serial

    assert parsed_seg.data == payload


def test_data_segment_invalid_type() -> None:
    """Verify DataSegment raises an error if parsed with a control segment type."""
    # Build a raw byte array starting with a Report Segment type (0x08)
    # The segment type lives in the lower 4 bits of the first byte.
    bad_data = b"\x08\x00\x00\x00\x00"

    with pytest.raises(ValueError, match="Expected a Data Segment type"):
        DataSegment._structure(bad_data)
