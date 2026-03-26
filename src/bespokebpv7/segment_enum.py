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
 Modified: 03/24/2026
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


class LTPSegmentType(IntEnum):
    """Enumeration for LTP segment types based on RFC 5326."""

    DATA_RED = 0x0
    DATA_GREEN = 0x1
    REPORT = 0x8
    REPORT_ACK = 0x9
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
