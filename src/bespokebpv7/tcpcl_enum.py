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
 Title: TCP Convergence Layer Enumerations
 Author: Nate Richard
 Modified: 09/22/2026
 Company: JPL
 Date:   09/22/2026

 File: tcpcl_enum.py
 Description:
           Enumerations for TCPCL versions and message types for v3 and v4.
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

from enum import IntEnum


class TCPCLVersion(IntEnum):
    """TCPCL Versions (RFC 7242 / RFC 9174)."""

    V3 = 3
    V4 = 4


class TCPCLv3MessageType(IntEnum):
    """TCPCL v3 Message Types (RFC 7242)."""

    CONTACT = 1
    KEEPALIVE = 2
    SHUTDOWN = 3
    DATA_SEGMENT = 4
    DATA_ACK = 5


class TCPCLv4MessageType(IntEnum):
    """TCPCL v4 Message Types (RFC 9174)."""

    SESS_INIT = 1
    KEEPALIVE = 2
    SESS_TERM = 3
    XFER_SEGMENT = 4
    XFER_ACK = 5
