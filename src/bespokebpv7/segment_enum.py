"""------------------------------------
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
 Title: LTP Segment Enumerations
 Author: Nate Richard
 Modified: 03/31/2026
 Company: JPL
 Date:   03/24/2026

 File: ext_functions
 Description:
           Classes defining LTP segment types and cancel reason codes

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

from enum import IntEnum

__all__ = ["CancelReasonCode", "LTPSegmentType"]


class LTPSegmentType(IntEnum):
    """Enumeration for LTP segment types based on RFC 5326."""

    DATA_RED = 0x0
    DATA_RED_CP = 0x1  # Red data, checkpoint
    DATA_RED_CP_EORP = 0x2  # Red data, checkpoint, End of Red-Part
    DATA_RED_CP_EORP_EOB = 0x3  # Red data, checkpoint, EORP, EOB
    DATA_GREEN = 0x4
    DATA_GREEN_UNDEF1 = 0x5
    DATA_GREEN_UNDEF2 = 0x6
    DATA_GREEN_EOB = 0x7  # Green data, End of Block
    REPORT = 0x8
    REPORT_ACK = 0x9
    CS_UNDEF1 = 0xA
    CS_UNDEF2 = 0xB
    CANCEL_SENDER = 0xC
    CANCEL_SENDER_ACK = 0xD
    CANCEL_RECV = 0xE
    CANCEL_RECV_ACK = 0xF


class CancelReasonCode(IntEnum):
    """Enumeration for LTP Cancel reason codes (RFC 5326 Section 3.2.4)."""

    CLIENT_CANCELED = 0x00
    UNREACHABLE = 0x01
    SYS_CNCLD = 0x02  # E.g., Exceeded max serial numbers
    MISCOLORED = 0x03
    SYS_ERROR = 0x04
    RETRY_EXCEED = 0x05
