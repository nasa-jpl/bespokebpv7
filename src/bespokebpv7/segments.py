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
 Title: LTP Segment Definitions
 Author: Nate Richard
 Modified: 03/24/2026
 Company: JPL
 Date:   03/24/2026

 File: ext_functions
 Description:
           Classes to handle Licklider Transmission Protocol (LTP) segments,
           specifically focusing on Acknowledgment and Cancel segments.
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

import sys

from attrs import define, field

from bespokebpv7.segment_enum import CancelReasonCode, LTPSegmentType
from bespokebpv7.utils import decode_sdnv, encode_sdnv

if sys.version_info >= (3, 11):
    from typing import Self
else:
    from typing_extensions import Self


@define
class LTPSegment:
    """Base class for all LTP Segments handling common header logic."""

    session_originator: int = field(default=0)
    session_number: int = field(default=0)
    segment_type: LTPSegmentType = field(default=LTPSegmentType.DATA_RED)
    header_count: int = field(default=0)
    trailer_count: int = field(default=0)

    # Internal tracker for deserialization
    _offset: int = field(default=0, init=False, repr=False)

    def _unstructure(self) -> bytes:
        """Serialize the common LTP header into bytes.

        Returns:
            Segment as a byte string.

        """
        buf = bytearray()

        ctrl_byte = self.segment_type.value << 0
        buf.append(ctrl_byte)

        buf.extend(encode_sdnv(self.session_originator))
        buf.extend(encode_sdnv(self.session_number))

        # Header and Trailer Extensions counts (assuming 0 for now)
        buf.extend(encode_sdnv(0))

        return bytes(buf)

    @classmethod
    def _structure(cls, data: bytes) -> Self:
        """
        Parse the common LTP header.

        Returns:
            Populated LTPSegment (or subclass instance) with _offset set to
            the start of the payload data.

        """
        block = cls()

        ctrl_byte = data[0]
        block.segment_type = LTPSegmentType(ctrl_byte >> 0)
        offset = 1

        block.session_originator, consumed = decode_sdnv(data[offset:])
        offset += consumed

        block.session_number, consumed = decode_sdnv(data[offset:])
        offset += consumed

        # Skip header/trailer extensions counts for now (assume 0)
        _, consumed = decode_sdnv(data[offset:])
        offset += consumed

        # Store offset so the subclass knows where to pick up parsing
        block._offset = offset

        return block


@define
class ReportAckSegment(LTPSegment):
    """Report-Acknowledgment Segment (RA)."""

    report_serial_number: int = field(default=0)

    def __attrs_post_init__(self) -> None:
        """Set segment type to Report ACK."""
        self.segment_type = LTPSegmentType.REPORT_ACK

    def _unstructure(self) -> bytes:
        """Serialize the RA segment.

        Returns:
            Segment as a byte string.

        """
        return super()._unstructure() + encode_sdnv(self.report_serial_number)

    @classmethod
    def _structure(cls, data: bytes) -> Self:
        """Deserialize an RA segment.

        Returns:
            Segment as class.

        Raises:
             ValueError: segement type is not Report ACK.

        """
        block = super()._structure(data)

        if block.segment_type != LTPSegmentType.REPORT_ACK:
            msg = f"Expected REPORT_ACK (0x9), got {block.segment_type}"
            raise ValueError(msg)

        block.report_serial_number, consumed = decode_sdnv(data[block._offset :])
        block._offset += consumed

        return block


@define
class CancelSegment(LTPSegment):
    """Cancel Segment (Cx)."""

    reason_code: CancelReasonCode = field(default=CancelReasonCode.CLIENT_CANCELED)

    def _unstructure(self) -> bytes:
        """Serialize the Cancel segment.

        Returns:
            Segment as a byte string.

        """
        return super()._unstructure() + encode_sdnv(self.reason_code.value)

    @classmethod
    def _structure(cls, data: bytes) -> Self:
        """Deserialize a Cancel segment.

        Returns:
            Segment as class.

        Raises:
            ValueError: segment type is not CANCEL.

        """
        block = super()._structure(data)

        if block.segment_type not in {
            LTPSegmentType.CANCEL_SENDER,
            LTPSegmentType.CANCEL_RECV,
        }:
            msg = f"Expected CANCEL (0xC), got {block.segment_type}"
            raise ValueError(msg)

        reason_val, consumed = decode_sdnv(data[block._offset :])
        block._offset += consumed
        block.reason_code = CancelReasonCode(reason_val)

        return block


SEGMENTFUNCTIONS = {
    LTPSegmentType.REPORT_ACK: ReportAckSegment,
    LTPSegmentType.CANCEL_SENDER: CancelSegment,
    LTPSegmentType.CANCEL_RECV: CancelSegment,
}
