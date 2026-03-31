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
 Modified: 03/31/2026
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

import contextlib

import dpkt  # type: ignore[import-untyped]

from bespokebpv7.bpv7 import BPv7
from bespokebpv7.segment_enum import LTPSegmentType
from bespokebpv7.segments import (
    SEGMENTFUNCTIONS,
    DataSegment,
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
        self.bpv7: BPv7 | None = None
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

        segment_cls = SEGMENTFUNCTIONS.get(LTPSegmentType(seg_type_val), LTPSegment)
        self.segment = bundle_converter.structure(buf, segment_cls)

        if (
            isinstance(self.segment, DataSegment)
            and self.segment.client_service_id == 1
        ):
            with contextlib.suppress(ValueError):
                self.bpv7 = BPv7(self.segment.data)

    def __bytes__(self) -> bytes:
        """Serialize the LTP packet back into bytes.

        Returns:
            byte string of LTP segment

        """
        if self.segment is None:
            return b""

        if isinstance(self.segment, DataSegment) and self.bpv7 is not None:
            updated_bundle_bytes = bytes(self.bpv7)

            self.segment.data = updated_bundle_bytes
            self.segment.client_length = len(updated_bundle_bytes)

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

        base_str = f"LTP Packet - Type: {seg_name}, Session: {orig}:{num}"

        if self.bpv7:
            base_str += f"\n  -> Contains {self.bpv7!r}"

        return base_str

    def __repr__(self) -> str:
        """Output for Python REPR.

        Returns:
            string representation of segment

        """
        return f"LTP(segment={self.segment!r})"
