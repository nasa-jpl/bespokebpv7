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
 Title: Bundle Extension Block functions
 Author: Nate Richard
 Modified: 01/26/2026
 Company: JPL
 Date:   12/19/2025

 File: ext_functions
 Description:
           Functions to help with creation and reading of extension blocks
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

from typing import Self

from attrs import Converter, define, field
from attrs.converters import optional

from bespokebpv7.block_enum import BlockType, CREBFlags
from bespokebpv7.blocks import CanonicalBlock
from bespokebpv7.bpsec import BlockIntegrityBlock
from bespokebpv7.utils import bundle_converter, format_eid, parse_eid_string


@define
class BundleAgeExt(CanonicalBlock):
    """Class definition for Bundle Age extension block"""

    age: int = field(default=0)

    def __attrs_post_init__(self) -> None:
        """Set block type"""
        self.block_type = BlockType.BUNDLE_AGE

    @classmethod
    def _structure(cls, data: list) -> Self:
        """Structure BundleAgeExt from CBOR list.

        Returns:
            Populated Bundle Age extension

        """
        block = super()._structure(data)
        block.age = bundle_converter.loads(block.data, int)
        return block

    def _unstructure(self) -> list:
        """Unstructure BundleAgeExt to CBOR list.

        Returns:
            COnverted class as list

        """
        self.data = bundle_converter.dumps(self.age)
        return super()._unstructure()


@define
class PreviousNodeExt(CanonicalBlock):
    """Class definition for Previous Node extension block."""

    _previous_node: list = field(factory=lambda: [1, "none"])

    def __attrs_post_init__(self) -> None:
        """Set block type"""
        self.block_type = BlockType.PREVIOUS_NODE

    @property
    def previous_node(self) -> str:
        """Return source EID"""
        return format_eid(self._previous_node)

    @previous_node.setter
    def previous_node(self, value: str | list) -> None:
        if isinstance(value, list):
            self._previous_node = value
        else:
            self._previous_node = parse_eid_string(value)

    @classmethod
    def _structure(cls, data: list) -> Self:
        """Structure PreviousNodeExt from CBOR list.

        Returns:
            Populated Previous Node Extension

        """
        block = super()._structure(data)
        block.previous_node = bundle_converter.loads(block.data, list)
        return block

    def _unstructure(self) -> list:
        """Unstructure PreviousNodeExt to CBOR list.

        Returns:
            Converted class as list

        """
        self.data = bundle_converter.dumps(self._previous_node)
        return super()._unstructure()


@define
class HopCountExt(CanonicalBlock):
    """Class definition for Hop Count extension block (HCB)."""

    hop_limit: int = field(default=0)
    hop_count: int = field(default=0)
    hcb_array_len = 2

    def __attrs_post_init__(self) -> None:
        """Set block type"""
        self.block_type = BlockType.HOP_COUNT

    @classmethod
    def _structure(cls, data: list) -> Self:
        """Structure HopCountExt from CBOR list.

        Returns:
            Populated Hop Count Extension

        """
        block = super()._structure(data)
        hcb_data = bundle_converter.loads(block.data, list)
        if len(hcb_data) == block.hcb_array_len:  # pylint: disable=E1101
            block.hop_limit = hcb_data[0]
            block.hop_count = hcb_data[1]
        return block

    def _unstructure(self) -> list:
        """Unstructure HopCountExt to CBOR list.

        Returns:
            Converted class as list

        """
        self.data = bundle_converter.dumps([self.hop_limit, self.hop_count])
        return super()._unstructure()


@define
class CustodyTransferExt(CanonicalBlock):
    """Class definition for Custody Transfer extension block (CTEB)."""

    sequence_num: int = field(default=0)
    sequence_id: int = field(default=0)
    _block_src_admin_eid: list = field(
        factory=lambda: [1, "none"],
        converter=Converter(parse_eid_string),  # type: ignore[misc]
    )
    cteb_array_len = 3

    def __attrs_post_init__(self) -> None:
        """Set block type"""
        self.block_type = BlockType.CTEB

    @property
    def block_src_admin_eid(self) -> str:
        """Return source EID"""
        return format_eid(self._block_src_admin_eid)

    @block_src_admin_eid.setter
    def block_src_admin_eid(self, value: str | list) -> None:
        if isinstance(value, list):
            self._block_src_admin_eid = value
        else:
            self._block_src_admin_eid = parse_eid_string(value)

    @classmethod
    def _structure(cls, data: list) -> Self:
        """Structure CustodyTransferExt from CBOR list.

        Returns:
            Populated Custody Transfer Extension

        """
        block = super()._structure(data)
        cteb_data = bundle_converter.loads(block.data, list)
        if len(cteb_data) == block.cteb_array_len:  # pylint: disable=E1101
            block.sequence_num = cteb_data[0]
            block.sequence_id = cteb_data[1]
            block.block_src_admin_eid = cteb_data[2]
        return block

    def _unstructure(self) -> list:
        """Unstructure CustodyTransferExt to CBOR list.

        Returns:
            Converted class to list

        """
        self.data = bundle_converter.dumps(
            [self.sequence_num, self.sequence_id, self._block_src_admin_eid]
        )
        return super()._unstructure()


def creb_flag_property(flag_bit: CREBFlags) -> property:
    """Generate a property that gets/sets a bit in the instance's CREB status
    report flags attribute.

    Returns:
        Property to get/set flag

    """

    def getter(self) -> bool:  # noqa: ANN001
        return bool(self.status_report_flags & flag_bit)

    def setter(self, value: bool) -> None:  # noqa: ANN001, FBT001
        if value:
            self.set_status_flag(flag_bit)
        else:
            self.clear_status_flag(flag_bit)

    return property(getter, setter)


@define
class CompressedReportingExt(CanonicalBlock):
    """Class definition for Compressed Reporting extension block (CREB)."""

    sequence_num: int = field(default=0)
    sequence_id: int | None = field(default=None)
    status_report_flags: CREBFlags | None = field(
        default=None, converter=optional(CREBFlags)
    )
    _block_src_admin_eid: list | None = field(
        default=None, converter=optional(parse_eid_string)
    )
    _report_to_eid: list | None = field(default=None)

    report_recv = creb_flag_property(CREBFlags.RECV_REPORT_REQ)
    fwd_report = creb_flag_property(CREBFlags.FWD_REPORT_REQ)
    deliv_report = creb_flag_property(CREBFlags.DELIV_REPORT_REQ)
    del_report = creb_flag_property(CREBFlags.DEL_REPORT_REQ)
    ct_accept_report = creb_flag_property(CREBFlags.CT_ACCEPT_REQ)
    ct_reject_report = creb_flag_property(CREBFlags.CT_REJECT_REQ)

    def __attrs_post_init__(self) -> None:
        """Set block type"""
        self.block_type = BlockType.CREB

    @property
    def block_src_admin_eid(self) -> str | None:
        """Return source EID

        Returns:
            Block source admin EID as string if exists

        """
        if self._block_src_admin_eid:
            return format_eid(self._block_src_admin_eid)
        return None

    @block_src_admin_eid.setter
    def block_src_admin_eid(self, value: str | list) -> None:
        if isinstance(value, list):
            self._block_src_admin_eid = value
        else:
            self._block_src_admin_eid = parse_eid_string(value)

    @property
    def report_to_eid(self) -> str | None:
        """Return report to EID

        Returns:
            Report to EID as string if exists

        """
        if self._report_to_eid:
            return format_eid(self._report_to_eid)
        return None

    @report_to_eid.setter
    def report_to_eid(self, value: str | list) -> None:
        if isinstance(value, list):
            self._report_to_eid = value
        else:
            self._report_to_eid = parse_eid_string(value)

    def set_status_flag(self, status_flag: CREBFlags) -> None:
        """Set an individual security context flag."""
        if not self.status_report_flags:
            self.status_report_flags = CREBFlags(0)
        self.status_report_flags |= int(status_flag)

    def clear_status_flag(self, status_flag: CREBFlags) -> None:
        """Clear an individual security context flag."""
        if not self.status_report_flags:
            self.status_report_flags = CREBFlags(0)
        self.status_report_flags &= ~int(status_flag)

    @classmethod
    def _structure(cls, data: list) -> Self:
        """Structure CompressedReportingExt from CBOR list.

        Returns:
            Populated Compressed Reporting Extension

        """
        block = super()._structure(data)
        creb_data = bundle_converter.loads(block.data, list)
        # NOTE: linting tools do not recognize attrs __slots__ so disabling warnings
        for idx, value in enumerate(creb_data):
            key = cls.__slots__[idx]  # pyright: ignore[reportAttributeAccessIssue] pylint: disable=E1101
            setattr(block, key, value)
        return block

    def _unstructure(self) -> list:
        """Unstructure CompressedReportingExt to CBOR list.

        Returns:
            Converted class to list

        """
        # NOTE: linting tools do not recognize attrs __slots__ so disabling warnings
        block_data = []
        for key in self.__slots__:  # pyright: ignore[reportAttributeAccessIssue] pylint: disable=E1101
            val = getattr(self, key)
            if val is not None:
                block_data.append(val)
        self.data = bundle_converter.dumps(block_data)
        return super()._unstructure()


BLOCKFUNCTIONS = {
    BlockType.BIB: BlockIntegrityBlock,
    BlockType.PAYLOAD_BLOCK: CanonicalBlock,
    BlockType.PREVIOUS_NODE: PreviousNodeExt,
    BlockType.BUNDLE_AGE: BundleAgeExt,
    BlockType.HOP_COUNT: HopCountExt,
    BlockType.CTEB: CustodyTransferExt,
    BlockType.CREB: CompressedReportingExt,
    BlockType.UNKNOWN_BLOCK: CanonicalBlock,
}
