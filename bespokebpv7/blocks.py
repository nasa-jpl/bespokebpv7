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
 Title: BPv7 Block Classes & helper functions
 Author: Nate Richard
 Modified: 01/14/2026
 Company: JPL
 Date:   12/19/2025

 File: blocks
 Description:
           Dataclasses for BPv7 blocks and helper functions directly related
           to the blocks.
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

import datetime
from collections import OrderedDict
from dataclasses import dataclass, field
from typing import Any, Optional, Union

import cbor2

from bespokebpv7.block_enum import BlockFlags, BlockType, BundleFlags, CRCType
from bespokebpv7.bundle_params import BundleFragmentation, BundleLife, BundleRoute
from bespokebpv7.utils import DTN_EPOCH, calculate_crc
from bespokebpv7.converter import converter

BPVERSION = 7


def flag_property(flag_bit):
    """Generates a property that gets/sets a bit in the instance's _flags attribute."""
    def getter(self):
        return bool(self.flags & flag_bit)

    def setter(self, value: bool):
        self.set_flag(flag_bit, value)
    return property(getter, setter)


class ExtensionBlocks(OrderedDict):
    "Store items in the order the keys were last added"

    def __setitem__(self, key, value):
        super().__setitem__(key, value)
        if BlockType.PAYLOAD_BLOCK in self.keys():
            self.move_to_end(BlockType.PAYLOAD_BLOCK)


@dataclass
class BaseBlock:
    """
    Dataclass that contains values required for both across primary and
    canonical blocks.
    """

    _flags: Any = 0
    _crc_type: CRCType = CRCType.NONE
    crc: Optional[bytes] = CRCType.NONE.fill_value

    def __bytes__(self):
        return cbor2.dumps(converter.unstructure(self))

    def update_crc(self):
        """Manual trigger to update CRC based on current state."""
        if self.crc_type != CRCType.NONE:
            self.crc = self.crc_type.fill_value
            list_data = converter.unstructure(self)
            self.crc = calculate_crc(list_data, self.crc_type)

    def set_flag(self, flag: Union[BundleFlags, BlockFlags], state=True) -> None:
        """Sets or clears an individual flag."""
        if state:
            self.flags |= int(flag)
        else:
            self.flags &= ~int(flag)

    @property
    def crc_type(self) -> CRCType:
        """Returns CRC type set for block."""
        return self._crc_type

    @crc_type.setter
    def crc_type(self, value: int) -> None:
        self._crc_type = CRCType(value)

    @property
    def flags(self) -> Union[BundleFlags, BlockFlags]:
        """Returns flags as set for block."""
        return self._flags

    @flags.setter
    def flags(self, value: Union[BundleFlags, BlockFlags]) -> None:
        self._flags = value


@dataclass
class CanonicalBlock(BaseBlock):
    """
    Parameter definitions for Canonical blocks.
    """

    _flags: BlockFlags = BlockFlags(0)
    _block_type: BlockType = BlockType.UNKNOWN_BLOCK
    _block_number: int = 2  # cannot be 0 (primary) or 1 (payload)
    _data: bytes = field(default_factory=bytes)

    replica_fragment = flag_property(BlockFlags.REPLICATE_FRAGMENT)
    status_report = flag_property(BlockFlags.STATUS_BUNDLE)
    delete_bundle = flag_property(BlockFlags.DELETE_BUNDLE)
    discard_block = flag_property(BlockFlags.DISCARD_BLOCK)

    @property
    def block_number(self) -> int:
        """Return block number set for block."""
        return self._block_number

    @block_number.setter
    def block_number(self, value: int):
        self._block_number = value

    @property
    def data(self) -> Any:
        """Return underlying data."""
        return self._data

    @data.setter
    def data(self, value: Any):
        self._data = value

    @property
    def flags(self) -> BlockFlags:
        """Return set Block flags"""
        return self._flags

    @flags.setter
    def flags(self, value: int) -> None:
        self._flags = BlockFlags(value)

    @property
    def block_type(self) -> BlockType:
        """Return set block type, cannot be 1 or 0."""
        return self._block_type

    @block_type.setter
    def block_type(self, value: int) -> None:
        self._block_type = BlockType(value)


@dataclass
class PrimaryBlock(BaseBlock):
    """Parameter definitions for Primary Block."""

    version: int = field(default=BPVERSION)
    _flags: BundleFlags = BundleFlags(0)
    route: BundleRoute = field(default_factory=BundleRoute)
    life: BundleLife = field(default_factory=BundleLife)
    fragmentation: BundleFragmentation = field(default_factory=BundleFragmentation)

    is_fragment = flag_property(BundleFlags.IS_FRAGMENT)
    adu_is_admin = flag_property(BundleFlags.ADU_IS_ADMIN_RECORD)
    no_fragment = flag_property(BundleFlags.DO_NOT_FRAGMENT)
    ack_requested = flag_property(BundleFlags.ACK_REQUESTED)
    status_time = flag_property(BundleFlags.STATUS_TIME)
    deliv_report = flag_property(BundleFlags.STATUS_REPORT_DELIV)
    fwd_report = flag_property(BundleFlags.STATUS_REPORT_FWD)
    recv_report = flag_property(BundleFlags.STATUS_REPORT_RECV)
    del_report = flag_property(BundleFlags.STATUS_REPORT_DEL)

    def set_creation(self, ms: Union[int, None] = None, seq: int = 0) -> None:
        """Set primary block creation time."""
        if not ms:
            dt = datetime.datetime.now(datetime.timezone.utc)
            dt_now = int((dt - DTN_EPOCH).total_seconds() * 1000)
            self.life.timestamp_ms = dt_now
        else:
            self.life.timestamp_ms = ms
        self.life.sequence = seq

    @property
    def flags(self) -> BundleFlags:
        return self._flags

    @flags.setter
    def flags(self, value: int) -> None:
        self._flags = BundleFlags(value)


@dataclass
class PayloadBlock(CanonicalBlock):
    """Modification of Canonical block to ensure ADU is stored correctly."""
    _block_type: BlockType = BlockType.PAYLOAD_BLOCK
    _block_number: int = 1
