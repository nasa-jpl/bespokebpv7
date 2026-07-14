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
 Title: BPv7 Block Classes & helper functions
 Author: Nate Richard
 Modified: 07/14/2026
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
import sys
from collections import OrderedDict
from typing import Any, TypedDict

from attrs import define, field

from bespokebpv7.block_enum import (
    BlockFlags,
    BlockType,
    BundleFlags,
    CRCType,
)
from bespokebpv7.bundle_params import (
    BundleFragmentation,
    BundleLife,
    BundleRoute,
)
from bespokebpv7.utils import (
    DTN_EPOCH,
    bundle_converter,
    calculate_crc,
    parse_eid_string,
    unstructure_eid_list,
)

if sys.version_info >= (3, 11):
    from typing import NotRequired, Self
else:
    from typing_extensions import NotRequired, Self

BPVERSION = 7


class CanonicalBlockInit(TypedDict):
    """Parameters needed to initialize a Canonical Block."""

    block_type: BlockType
    block_num: NotRequired[int]
    block_flags: NotRequired[BlockFlags]
    crc_type: NotRequired[CRCType]


@define
class BaseBlock:
    """Class that contains values required for both across primary and
    canonical blocks.
    """

    flags: Any = 0
    crc_type: CRCType = field(default=CRCType.NONE, converter=CRCType)
    crc: bytes | None = CRCType.NONE.fill_value

    def __bytes__(self) -> bytes:
        """Convert block structure to bytes.

        Returns:
            block as byte string

        """
        return bundle_converter.dumps(self)

    def update_crc(self) -> None:
        """Manual trigger to update CRC based on current state."""
        if self.crc_type != CRCType.NONE:
            self.crc = self.crc_type.fill_value
            self.crc = calculate_crc(bundle_converter.unstructure(self), self.crc_type)

    def set_flag(self, flag: BundleFlags | BlockFlags) -> None:
        """Set an individual flag."""
        self.flags |= int(flag)

    def clear_flag(self, flag: BundleFlags | BlockFlags) -> None:
        """Clear an individual flag."""
        self.flags &= ~int(flag)


def flag_property(flag_bit: BundleFlags | BlockFlags) -> property:
    """Generate a property that gets/sets a bit in the instance's _flags attribute.

    Returns:
        Property to set or get flag

    """

    def getter(self: BaseBlock) -> bool:
        return bool(self.flags & flag_bit)

    def setter(self: BaseBlock, value: bool) -> None:  # noqa: FBT001
        if value:
            self.set_flag(flag_bit)
        else:
            self.clear_flag(flag_bit)

    return property(getter, setter)


@define
class CanonicalBlock(BaseBlock):
    """Parameter definitions for Canonical blocks.
    Structure: [block_type, block_number, flags, crc_type, data, crc]
    """

    flags: BlockFlags = field(default=BlockFlags(0), converter=BlockFlags)
    block_type: BlockType = field(default=BlockType.UNKNOWN_BLOCK, converter=BlockType)
    block_number: int = field(default=1, converter=int)  # cannot be 0 (primary)
    data: bytes = field(factory=bytes)

    # Support native malformed data injection
    data_prefix: bytes = field(default=b"")
    data_override: bytes | None = field(default=None)

    replica_fragment = flag_property(BlockFlags.REPLICATE_FRAGMENT)
    status_report = flag_property(BlockFlags.STATUS_BUNDLE)
    delete_bundle = flag_property(BlockFlags.DELETE_BUNDLE)
    discard_block = flag_property(BlockFlags.DISCARD_BLOCK)
    max_array_len = 5

    @classmethod
    def _structure(cls, data: list) -> Self:
        """
        Structure CBOR List as Canonical Block.

        Returns:
            Populated Canonical Block

        """
        block = cls()
        block.block_type = BlockType(data[0])
        block.block_number = data[1]
        block.flags = BlockFlags(data[2])
        block.crc_type = CRCType(data[3])
        block.data = data[4]  # Keep as bytes

        if len(data) > block.max_array_len:
            block.crc = data[5]
        else:
            block.crc = block.crc_type.fill_value
        return block

    def _unstructure(self) -> list:
        """
        Convert CanonicalBlock to CBOR list, applying overrides if present.

        Returns:
            list of canonical block parameters

        """
        # allow full override
        block_data = self.data_override if self.data_override is not None else self.data

        # ensure it's converted to bytes
        if not isinstance(block_data, bytes):
            block_data = bundle_converter.dumps(block_data)

        block_data = self.data_prefix + block_data

        out: list[int | bytes] = [
            int(self.block_type),
            self.block_number,
            int(self.flags),
            int(self.crc_type),
            block_data,
        ]

        if self.crc_type != CRCType.NONE and self.crc:
            out.append(self.crc)
        return out


@define
class PrimaryBlock(BaseBlock):
    """Parameter definitions for Primary Block."""

    version: int = field(default=BPVERSION)
    flags: BundleFlags = field(default=BundleFlags(0), converter=BundleFlags)
    route: BundleRoute = field(factory=BundleRoute)
    life: BundleLife = field(factory=BundleLife)
    fragmentation: BundleFragmentation | None = None

    list_override: list | None = field(default=None)
    extra_elements: list = field(factory=list)
    raw_override: bytes | None = field(default=None)

    is_fragment = flag_property(BundleFlags.IS_FRAGMENT)
    adu_is_admin = flag_property(BundleFlags.ADU_IS_ADMIN_RECORD)
    no_fragment = flag_property(BundleFlags.DO_NOT_FRAGMENT)
    ack_requested = flag_property(BundleFlags.ACK_REQUESTED)
    status_time = flag_property(BundleFlags.STATUS_TIME)
    deliv_report = flag_property(BundleFlags.STATUS_REPORT_DELIV)
    fwd_report = flag_property(BundleFlags.STATUS_REPORT_FWD)
    recv_report = flag_property(BundleFlags.STATUS_REPORT_RECV)
    del_report = flag_property(BundleFlags.STATUS_REPORT_DEL)

    def set_creation(self, ms: int | None = None, seq: int = 0) -> None:
        """Set primary block creation time."""
        if not ms:
            dt = datetime.datetime.now(datetime.timezone.utc)
            dt_now = int((dt - DTN_EPOCH).total_seconds() * 1000)
            self.life.timestamp_ms = dt_now
        else:
            self.life.timestamp_ms = ms
        self.life.sequence = seq

    @classmethod
    def _structure(cls, data: list) -> Self:
        """
        Structure CBOR List as Primary Block.

        Returns:
            Populated Primary Block

        """
        block = cls()
        block.version = data[0]
        block.flags = BundleFlags(data[1])
        block.crc_type = CRCType(data[2])

        block.route.dest_eid = data[3]
        block.route.source_eid = data[4]
        block.route.report_to = data[5]

        creation = data[6]
        block.life.timestamp_ms = creation[0]
        block.life.sequence = creation[1]
        block.life.lifetime = data[7]

        # Fragmentation
        idx = 8
        if block.is_fragment:
            block.fragmentation = BundleFragmentation(
                fragment_offset=data[idx], total_adu_len=data[idx + 1]
            )
            idx += 2

        if idx < len(data):
            block.crc = data[idx]
        else:
            block.crc = block.crc_type.fill_value

        return block

    def _unstructure(self) -> list:
        """
        Convert PrimaryBlock to CBOR list, applying overrides if present.

        Returns:
            list of primary block parameters

        """
        # Override block layout
        if self.list_override is not None:
            return self.list_override

        # Baseline compliant layout
        out: list[int | list | bytes] = [
            self.version,
            int(self.flags),
            int(self.crc_type),
            unstructure_eid_list(parse_eid_string(self.route.dest_eid)),
            unstructure_eid_list(parse_eid_string(self.route.source_eid)),
            unstructure_eid_list(parse_eid_string(self.route.report_to)),
            [self.life.timestamp_ms, self.life.sequence],
            self.life.lifetime,
        ]

        if self.is_fragment and self.fragmentation:
            out.extend(
                [
                    self.fragmentation.fragment_offset,
                    self.fragmentation.total_adu_len,
                ]
            )

        if self.crc_type != CRCType.NONE and self.crc:
            out.append(self.crc)

        # inject extra elements
        if self.extra_elements:
            out.extend(self.extra_elements)

        return out


class ExtensionBlocks(OrderedDict):
    """Store items in the order the keys were last added."""

    def __setitem__(self, key: BlockType, value: CanonicalBlock) -> None:
        """Override ordered dict to ensure payload block is always last."""
        super().__setitem__(key, value)
        if BlockType.PAYLOAD_BLOCK in self.keys():
            self.move_to_end(BlockType.PAYLOAD_BLOCK)
