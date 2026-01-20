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
 Modified: 01/16/2025
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

import cbor2
from attrs import define, field
from attrs.converters import optional
from cattrs.preconf.cbor2 import make_converter
from cattrs.strategies import use_class_methods

from bespokebpv7.block_enum import BlockType, CREBFlags
from bespokebpv7.blocks import CanonicalBlock
from bespokebpv7.bpsec import BlockIntegrityBlock
from bespokebpv7.utils import format_eid, parse_eid_string


@define
class BundleAgeExt(CanonicalBlock):
    """Class definition for Bundle Age extension block"""

    age: int = field(default=0)

    def _proc_out_data(self) -> bytes:
        """Convert age to a CBOR unsigned int

        Returns:
            age as cbor bytes

        """
        return cbor2.dumps(self.age)

    def _proc_in_data(self, block_data: bytes) -> None:
        """Load CBOR data into age."""
        self.data = block_data
        self.age = cbor2.loads(block_data)


@define
class PreviousNodeExt(CanonicalBlock):
    """Class definition for Previous Node extension block."""

    _previous_node: list = field(factory=lambda: [1, "none"])

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

    def _proc_out_data(self) -> bytes:
        """Convert previous node into CBOR string.

        Returns:
            cbor string as bytes

        """
        return cbor2.dumps(self._previous_node)

    def _proc_in_data(self, block_data: bytes) -> None:
        """Any conversions required to meet RFC 9171 requirements for block data."""
        self.data = block_data
        self.previous_node = cbor2.loads(block_data)


@define
class HopCountExt(CanonicalBlock):
    """Class definition for Hop Count extension block (HCB)."""

    hop_limit: int = field(default=0)
    hop_count: int = field(default=0)
    _hcb_array_len = 2

    def _proc_out_data(self) -> bytes:
        """Dump Hop Count parameters as CBOR definite array.

        Returns:
            hop count cbor array as bytes

        """
        return cbor2.dumps([self.hop_limit, self.hop_count])

    def _proc_in_data(self, block_data: bytes) -> None:
        """Convert CBOR data into hop count parameters."""
        self.data = block_data
        hcb_data = cbor2.loads(block_data)
        if len(hcb_data) == self._hcb_array_len:
            self.hop_limit = hcb_data[0]
            self.hop_count = hcb_data[1]


@define
class CustodyTransferExt(CanonicalBlock):
    """Class definition for Custody Transfer extension block (CTEB)."""

    sequence_num: int = field(default=0)
    sequence_id: int = field(default=0)
    _block_src_admin_eid: list = field(factory=lambda: [1, "none"])
    _cteb_array_len = 3

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

    def _proc_out_data(self) -> bytes:
        """Dump CTEB parameters as CBOR definite array.

        Returns:
            CTEB cbor array as bytes

        """
        return cbor2.dumps(
            [self.sequence_num, self.sequence_id, self._block_src_admin_eid]
        )

    def _proc_in_data(self, block_data: bytes) -> None:
        """Convert CBOR data into CTEB parameters."""
        self.data = block_data
        cteb_data = cbor2.loads(block_data)
        if len(cteb_data) == self._cteb_array_len:
            self.sequence_num = cteb_data[0]
            self.sequence_id = cteb_data[1]
            self._block_src_admin_eid = cteb_data[2]


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
    _block_src_admin_eid: list | None = field(default=None)
    _report_to_eid: list | None = field(default=None)

    report_recv = creb_flag_property(CREBFlags.RECV_REPORT_REQ)
    fwd_report = creb_flag_property(CREBFlags.FWD_REPORT_REQ)
    deliv_report = creb_flag_property(CREBFlags.DELIV_REPORT_REQ)
    del_report = creb_flag_property(CREBFlags.DEL_REPORT_REQ)
    ct_accept_report = creb_flag_property(CREBFlags.CT_ACCEPT_REQ)
    ct_reject_report = creb_flag_property(CREBFlags.CT_REJECT_REQ)

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

    def _proc_out_data(self) -> bytes:
        """Dump CREB parameters as CBOR definite array.

        Returns:
            CTEB cbor array as bytes

        """
        # NOTE: linting tools do not recognize attrs __slots__ so disabling warnings
        block_data = []
        for key in self.__slots__:  # pyright: ignore[reportAttributeAccessIssue] pylint: disable=E1101
            val = getattr(self, key)
            if val is not None:
                block_data.append(val)
        return cbor2.dumps(block_data)

    def _proc_in_data(self, block_data: bytes) -> None:
        """Convert CBOR data into CREB parameters."""
        # NOTE: linting tools do not recognize attrs __slots__ so disabling warnings
        self.data = block_data
        creb_data = cbor2.loads(block_data)
        for idx, value in enumerate(creb_data):
            key = self.__slots__[idx]  # pyright: ignore[reportAttributeAccessIssue] pylint: disable=E1101
            setattr(self, key, value)


ext_converter = make_converter()
use_class_methods(ext_converter, "_structure", "_unstructure")
BLOCKFUNCTIONS = {
    BlockType.BIB: BlockIntegrityBlock,
    BlockType.PAYLOAD_BLOCK: CanonicalBlock,
    BlockType.PREVIOUS_NODE: PreviousNodeExt,
    BlockType.BUNDLE_AGE: BundleAgeExt,
    BlockType.HOP_COUNT: HopCountExt,
    BlockType.UNKNOWN_BLOCK: CanonicalBlock,
}
