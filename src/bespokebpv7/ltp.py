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
 Title: Licklider Transmission Protocol Class
 Author: Nate Richard
 Modified: 03/25/2026
 Company: JPL
 Date:   03/25/2026

 File: bpv7
 Description:
           Class that can dissect and create LTP segments.
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

import dpkt  # type: ignore[import-untyped]

from bespokebpv7.segment_enum import LTPSegmentType
from bespokebpv7.segments import (
    SEGMENTFUNCTIONS,
    LTPSegment,
)
from bespokebpv7.utils import bundle_converter


class LTP(dpkt.Packet):
    """
    Licklider Transmission Protocol (RFC 5326 / CCSDS 734.1-B-1).
    Encapsulates a single LTP segment and interfaces with dpkt.
    """

    def __init__(self, *args, **kwargs) -> None:
        """Initialize segment parameters."""
        self.segment = LTPSegment()
        super().__init__(*args, **kwargs)

    def unpack(self, buf: bytes) -> None:
        """Unpack raw bytes into the appropriate LTP segment.

        Raises:
            ValueError: Empty buffer

        """
        if not buf:
            msg = "Empty buffer provided for LTP unpacking."
            raise ValueError(msg)

        ctrl_byte = buf[0]
        seg_type_val = ctrl_byte >> 0

        segment = SEGMENTFUNCTIONS.get(LTPSegmentType(seg_type_val), LTPSegment)
        self.segment = bundle_converter.structure(buf, segment)

    def __bytes__(self) -> bytes:
        """Serialize the LTP packet back into bytes.

        Returns:
            byte string of LTP segment

        """
        if self.segment is None:
            return b""

        return bundle_converter.unstructure(self.segment)

    def __str__(self) -> str:
        """Friendly display for debugging.

        Returns:
            String representation of LTP segment

        """
        if not self.segment:
            return "LTP Packet (Empty)"

        seg_name = self.segment.segment_type.name
        orig = self.segment.session_originator
        num = self.segment.session_number

        return f"LTP Packet - Type: {seg_name}, Session: {orig}:{num}"

    def __repr__(self) -> str:
        """Output for Python REPR.

        Returns:
            string representation of segment

        """
        return f"LTP(segment={self.segment!r})"
