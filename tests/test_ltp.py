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
 Modified: 03/25/2026
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

from bespokebpv7.ltp import LTP  # type: ignore[import-untyped]
from bespokebpv7.segments import (  # type: ignore[import-untyped]
    CancelReasonCode,
    CancelSegment,
    LTPSegmentType,
    ReportAckSegment,
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
