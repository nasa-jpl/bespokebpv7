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
 Modified: 03/25/2026
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

from bespokebpv7.segment_enum import (  # type: ignore[import-untyped]
    CancelReasonCode,
    LTPSegmentType,
)
from bespokebpv7.segments import (  # type: ignore[import-untyped]
    CancelSegment,
    ReportAckSegment,
)
from bespokebpv7.utils import encode_sdnv  # type: ignore[import-untyped]


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
