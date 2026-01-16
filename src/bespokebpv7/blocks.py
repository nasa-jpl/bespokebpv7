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
 Modified: 01/16/2026
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
from typing import Any, NotRequired, Optional, TypedDict, Union

import cbor2
from attrs import define, field
from cattrs.preconf.cbor2 import make_converter
from cattrs.strategies import use_class_methods

from bespokebpv7.block_enum import BlockFlags, BlockType, BundleFlags, CRCType
from bespokebpv7.bundle_params import BundleFragmentation, BundleLife, BundleRoute
from bespokebpv7.utils import DTN_EPOCH, calculate_crc, parse_eid_string

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


class CanonicalBlockInit(TypedDict):
    """Parameters needed to initialize a Canonical Block."""

    block_type: BlockType
    block_num: NotRequired[int]
    block_flags: NotRequired[BlockFlags]
    crc_type: NotRequired[CRCType]


@define
class BaseBlock:
    """
    Class that contains values required for both across primary and
    canonical blocks.
    """

    flags: Any = 0
    crc_type: CRCType = field(default=CRCType.NONE, converter=CRCType)
    crc: Optional[bytes] = CRCType.NONE.fill_value

    def __bytes__(self):
        return cbor2.dumps(self._unstructure())

    def update_crc(self):
        """Manual trigger to update CRC based on current state."""
        if self.crc_type != CRCType.NONE:
            self.crc = self.crc_type.fill_value
            self.crc = calculate_crc(self._unstructure(), self.crc_type)

    def set_flag(self, flag: Union[BundleFlags, BlockFlags], state=True) -> None:
        """Sets or clears an individual flag."""
        if state:
            self.flags |= int(flag)
        else:
            self.flags &= ~int(flag)

    def _unstructure(self) -> list:
        """Base unstructure method, should be overridden."""
        raise NotImplementedError


@define
class CanonicalBlock(BaseBlock):
    """
    Parameter definitions for Canonical blocks.
    Structure: [block_type, block_number, flags, crc_type, data, crc]
    """

    flags: BlockFlags = field(default=BlockFlags(0), converter=BlockFlags)
    block_type: BlockType = field(default=BlockType.UNKNOWN_BLOCK, converter=BlockType)
    block_number: int = field(default=1, converter=int)  # cannot be 0 (primary)
    data: bytes = field(factory=bytes)

    replica_fragment = flag_property(BlockFlags.REPLICATE_FRAGMENT)
    status_report = flag_property(BlockFlags.STATUS_BUNDLE)
    delete_bundle = flag_property(BlockFlags.DELETE_BUNDLE)
    discard_block = flag_property(BlockFlags.DISCARD_BLOCK)

    @classmethod
    def _structure(cls, data: list) -> "CanonicalBlock":
        """Class-specific structure method."""
        block = cls()
        block.block_type = BlockType(data[0])
        block.block_number = data[1]
        block.flags = BlockFlags(data[2])
        block.crc_type = CRCType(data[3])
        block._proc_in_data(data[4])

        if len(data) > 5:
            block.crc = data[5]
        else:
            block.crc = block.crc_type.fill_value
        return block

    def _unstructure(self) -> list:
        """Class-specific unstructure method."""
        out: list[Union[int, bytes]] = [
            int(self.block_type),
            self.block_number,
            int(self.flags),
            int(self.crc_type),
        ]

        out.append(self._proc_out_data())

        if self.crc_type != CRCType.NONE and self.crc:
            out.append(self.crc)
        return out

    def _proc_out_data(self) -> bytes:
        """Any conversions required to meet RFC 9171 requirements for block data."""
        if not isinstance(self.data, bytes):
            return cbor2.dumps(self.data)
        return self.data

    def _proc_in_data(self, block_data: bytes) -> None:
        """Any conversions required to meet RFC 9171 requirements for block data."""
        self.data = block_data


@define
class PrimaryBlock(BaseBlock):
    """Parameter definitions for Primary Block."""

    version: int = field(default=BPVERSION)
    flags: BundleFlags = field(default=BundleFlags(0), converter=BundleFlags)
    route: BundleRoute = field(factory=BundleRoute)
    life: BundleLife = field(factory=BundleLife)
    fragmentation: Optional[BundleFragmentation] = field(factory=BundleFragmentation)

    is_fragment = flag_property(BundleFlags.IS_FRAGMENT)
    adu_is_admin = flag_property(BundleFlags.ADU_IS_ADMIN_RECORD)
    no_fragment = flag_property(BundleFlags.DO_NOT_FRAGMENT)
    ack_requested = flag_property(BundleFlags.ACK_REQUESTED)
    status_time = flag_property(BundleFlags.STATUS_TIME)
    deliv_report = flag_property(BundleFlags.STATUS_REPORT_DELIV)
    fwd_report = flag_property(BundleFlags.STATUS_REPORT_FWD)
    recv_report = flag_property(BundleFlags.STATUS_REPORT_RECV)
    del_report = flag_property(BundleFlags.STATUS_REPORT_DEL)

    def set_creation(self, ms: Optional[int] = None, seq: int = 0) -> None:
        """Set primary block creation time."""
        if not ms:
            dt = datetime.datetime.now(datetime.timezone.utc)
            dt_now = int((dt - DTN_EPOCH).total_seconds() * 1000)
            self.life.timestamp_ms = dt_now
        else:
            self.life.timestamp_ms = ms
        self.life.sequence = seq

    @classmethod
    def _structure(cls, data: list) -> "PrimaryBlock":
        """Structure CBOR List as Primary Block."""
        block = cls()
        block.version = data[0]
        block.flags = BundleFlags(data[1])
        block.crc_type = CRCType(data[2])

        # Route
        block.route.dest_eid = data[3]
        block.route.source_eid = data[4]
        block.route.report_to = data[5]

        # Life (creation is [ms, seq])
        creation = data[6]
        block.life.timestamp_ms = creation[0]
        block.life.sequence = creation[1]
        block.life.lifetime = data[7]

        # Fragmentation
        idx = 8
        if block.is_fragment and block.fragmentation:
            block.fragmentation.fragment_offset = data[idx]
            block.fragmentation.total_adu_len = data[idx + 1]
            idx += 2

        if idx < len(data):
            block.crc = data[idx]
        else:
            block.crc = block.crc_type.fill_value

        return block

    def _unstructure(self) -> list:
        """Convert PrimaryBlock to CBOR list."""
        out: list[Union[int, list, bytes]] = [
            self.version,
            int(self.flags),
            int(self.crc_type),
            parse_eid_string(self.route.dest_eid),
            parse_eid_string(self.route.source_eid),
            parse_eid_string(self.route.report_to),
            [self.life.timestamp_ms, self.life.sequence],
            self.life.lifetime,
        ]

        if self.is_fragment and self.fragmentation:
            out.append(self.fragmentation.fragment_offset)
            out.append(self.fragmentation.total_adu_len)

        if self.crc_type != CRCType.NONE and self.crc:
            out.append(self.crc)

        return out


block_converter = make_converter()
use_class_methods(block_converter, "_structure", "_unstructure")
