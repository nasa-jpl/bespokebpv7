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
 Modified: 03/31/2026
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

    version: int = field(default=0)  # Added the 4-bit version field
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

        # Shift version to the high 4 bits and combine with the 4-bit segment type
        ctrl_byte = ((self.version & 0x0F) << 4) | (self.segment_type.value & 0x0F)
        buf.append(ctrl_byte)

        buf.extend(encode_sdnv(self.session_originator))
        buf.extend(encode_sdnv(self.session_number))

        ext_counts = ((self.header_count & 0x0F) << 4) | (self.trailer_count & 0x0F)
        buf.append(ext_counts)

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

        # Extract the high 4 bits for version and low 4 bits for segment type
        block.version = (ctrl_byte >> 4) & 0x0F
        block.segment_type = LTPSegmentType(ctrl_byte & 0x0F)

        offset = 1

        block.session_originator, consumed = decode_sdnv(data[offset:])
        offset += consumed

        block.session_number, consumed = decode_sdnv(data[offset:])
        offset += consumed

        # Extract header extensions count
        ext_counts = data[offset]
        block.header_count = (ext_counts >> 4) & 0x0F
        block.trailer_count = ext_counts & 0x0F
        offset += 1

        # Store offset so the subclass knows where to pick up parsing
        block.increment_offset(offset)

        return block

    def increment_offset(self, num_bytes: int) -> None:
        """Update SDNV offset tracking."""
        self._offset += num_bytes

    def get_offset(self) -> int:
        """Use offset to help with decoding.

        Returns:
            Latest offset value

        """
        return self._offset


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

        offset = block.get_offset()
        block.report_serial_number, consumed = decode_sdnv(data[offset:])
        block.increment_offset(consumed)

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

        offset = block.get_offset()
        reason_val, consumed = decode_sdnv(data[offset:])
        block.increment_offset(consumed)
        block.reason_code = CancelReasonCode(reason_val)

        return block


@define
class DataSegment(LTPSegment):
    """Data Segment (Red or Green)."""

    client_service_id: int = field(default=1)  # 1 is typical for Bundle Protocol
    client_offset: int = field(default=0)
    client_length: int = field(default=0)
    checkpoint_serial_number: int = field(default=0)
    report_serial_number: int = field(default=0)
    data: bytes = field(factory=bytes)

    @property
    def is_checkpoint(self) -> bool:
        """Whether segment is a checkpoint or not."""
        return self.segment_type in {
            LTPSegmentType.DATA_RED_CP,
            LTPSegmentType.DATA_RED_CP_EORP,
            LTPSegmentType.DATA_RED_CP_EORP_EOB,
        }

    @property
    def is_eorp(self) -> bool:
        """Whether segment is end of red part or not."""
        return self.segment_type in {
            LTPSegmentType.DATA_RED_CP_EORP,
            LTPSegmentType.DATA_RED_CP_EORP_EOB,
        }

    @property
    def is_eob(self) -> bool:
        """Whether segment is end of block or not."""
        return self.segment_type in {
            LTPSegmentType.DATA_RED_CP_EORP_EOB,
            LTPSegmentType.DATA_GREEN_EOB,
        }

    def _unstructure(self) -> bytes:
        """Serialize the Data segment.

        Returns:
            Class a byte string

        """
        buf = bytearray(super()._unstructure())

        buf.extend(encode_sdnv(self.client_service_id))
        buf.extend(encode_sdnv(self.client_offset))
        buf.extend(encode_sdnv(self.client_length))

        if self.is_checkpoint:
            buf.extend(encode_sdnv(self.checkpoint_serial_number))
            buf.extend(encode_sdnv(self.report_serial_number))

        buf.extend(self.data)
        return bytes(buf)

    @classmethod
    def _structure(cls, data: bytes) -> Self:
        """Deserialize a Data segment.

        Returns:
            Data structured as a class

        Raises:
            ValueError: if segment type does not fall in segment range

        """
        block = super()._structure(data)

        if block.segment_type > LTPSegmentType.DATA_GREEN_EOB:
            msg = f"Expected a Data Segment type (0x0-0x6), got {block.segment_type}"
            raise ValueError(msg)

        offset = block.get_offset()

        block.client_service_id, consumed = decode_sdnv(data[offset:])
        offset += consumed

        block.client_offset, consumed = decode_sdnv(data[offset:])
        offset += consumed

        block.client_length, consumed = decode_sdnv(data[offset:])
        offset += consumed

        if block.is_checkpoint:
            block.checkpoint_serial_number, consumed = decode_sdnv(data[offset:])
            offset += consumed

            block.report_serial_number, consumed = decode_sdnv(data[offset:])
            offset += consumed

        block.data = data[offset : offset + block.client_length]
        block.increment_offset(offset + len(block.data))

        return block


SEGMENTFUNCTIONS = {
    LTPSegmentType.DATA_RED: DataSegment,
    LTPSegmentType.DATA_GREEN: DataSegment,
    LTPSegmentType.DATA_RED_CP: DataSegment,
    LTPSegmentType.DATA_RED_CP_EORP: DataSegment,
    LTPSegmentType.DATA_RED_CP_EORP_EOB: DataSegment,
    LTPSegmentType.DATA_GREEN_EOB: DataSegment,
    LTPSegmentType.REPORT_ACK: ReportAckSegment,
    LTPSegmentType.CANCEL_SENDER: CancelSegment,
    LTPSegmentType.CANCEL_RECV: CancelSegment,
}
