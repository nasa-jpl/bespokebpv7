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
 Modified: 01/07/2026
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

from block_enum import BlockFlags, BlockType, BundleFlags, CRCType
from bundle_params import BundleFragmentation, BundleLife, BundleRoute
from utils import DTN_EPOCH, calculate_crc, parse_eid_string

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
    serial_fields: list[str] = field(default_factory=list, repr=False)

    def __bytes__(self):
        return cbor2.dumps(self.get_serializable_data())

    def update_crc(self):
        """Manual trigger to update CRC based on current state."""
        if self.crc_type != CRCType.NONE:
            self.crc = self.crc_type.fill_value
            data_to_hash = self.get_serializable_data()
            self.crc = calculate_crc(data_to_hash, self.crc_type)

    def get_serializable_data(self) -> list:
        """
        Constructs the CBOR-ready list based on class-specific field order.
        """
        serial_data = []

        for name in self.serial_fields:
            # RFC 9171: If CRC type is NONE, the CRC field is omitted
            if name == "crc" and self._crc_type == CRCType.NONE:
                break

            val = getattr(self, name)

            # Delegate specialized encoding to a helper method
            serial_data.append(self._process_field_for_serial(name, val))

        return serial_data

    def _process_field_for_serial(
        self,
        name: str,  # pylint: disable=unused-argument
        val: Any,
    ) -> Any:
        """Hook for subclasses to handle specific field encoding (like CBOR wrapping)."""
        return val

    def set_flag(self, flag: Union[BundleFlags, BlockFlags], state=True) -> None:
        """Sets or clears an individual flag."""
        if state:
            # Bitwise OR to set the bit
            self.flags |= int(flag)
        else:
            # Bitwise AND with inverted mask to clear the bit
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
    _data: bytes = b""
    replica_fragment = flag_property(BlockFlags.REPLICATE_FRAGMENT)
    status_report = flag_property(BlockFlags.STATUS_BUNDLE)
    delete_bundle = flag_property(BlockFlags.DELETE_BUNDLE)
    discard_block = flag_property(BlockFlags.DISCARD_BLOCK)
    serial_fields: list[str] = field(
        default_factory=lambda: [
            "_block_type",
            "_block_number",
            "_flags",
            "_crc_type",
            "_data",
            "crc",
        ],
        repr=False,
    )

    def _process_field_for_serial(self, name: str, val: Any) -> Any:
        """
        Encodes non-payload data as a CBOR byte string.
        """
        if name == "_data" and self._block_type != BlockType.PAYLOAD_BLOCK:
            return cbor2.dumps(val)
        return val

    @property
    def block_number(self) -> int:
        """Return block number set for block."""
        return self._block_number

    @block_number.setter
    def block_number(self, value: int):
        self._block_number = value

    @property
    def data(self) -> bytes:
        """Return data as a CBOR array. Up to user to extract data."""
        return cbor2.dumps(self._data)

    @data.setter
    def data(self, value: bytes):
        self._data = cbor2.loads(value)

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
    recv_report = flag_property(BundleFlags.STATUS_REPORT_RECV)
    fwd_report = flag_property(BundleFlags.STATUS_REPORT_FWD)
    deliv_report = flag_property(BundleFlags.STATUS_REPORT_DELIV)
    del_report = flag_property(BundleFlags.STATUS_REPORT_DEL)
    serial_fields: list[str] = field(
        default_factory=lambda: [
            "version",
            "_flags",
            "_crc_type",
            "_dest_eid",
            "_source_eid",
            "_report_to_eid",
            "creation",
            "lifetime",
            "fragment_offset",
            "total_adu_len",
            "crc",
        ],
        repr=False,
    )

    def set_creation(self, ms: Union[int, None] = None, seq: int = 0) -> None:
        """
        Set primary block creation time, if nothing is passed sets to time
        at time of function call.
        """
        # Set creation timestamp if it wasn't provided
        if not ms:
            dt = datetime.datetime.now(datetime.timezone.utc)
            # Ensure DTN_EPOCH is a datetime object
            dt_now = int((dt - DTN_EPOCH).total_seconds() * 1000)
            self.life.timestamp_ms = dt_now
        else:
            self.life.timestamp_ms = ms
        self.life.sequence = seq

    def get_serializable_data(self) -> list:
        """
        Constructs the CBOR-ready list based on class-specific field order.
        """
        serial_data = []
        mapping = {
            "dest": lambda: parse_eid_string(self.route.dest_eid),
            "source": lambda: parse_eid_string(self.route.source_eid),
            "report_to": lambda: parse_eid_string(self.route.report_to),
            "creation": lambda: [self.life.timestamp_ms, self.life.sequence],
            "lifetime": lambda: self.life.lifetime,
            "fragment_offset": lambda: self.fragmentation.fragment_offset,
            "total_adu_len": lambda: self.fragmentation.total_adu_len,
        }

        for name in self.serial_fields:
            # RFC 9171: If CRC type is NONE, the CRC field is omitted
            if name == "crc" and self._crc_type == CRCType.NONE:
                break

            # don't include if bundle is not fragmented
            if not self.is_fragment and name in ["fragment_offset", "total_adu_len"]:
                continue

            if name in mapping:
                val = mapping[name]()
            else:
                val = getattr(self, name)

            # Delegate specialized encoding to a helper method
            serial_data.append(self._process_field_for_serial(name, val))

        return serial_data

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

    @property
    def data(self) -> bytes:
        return self._data

    @data.setter
    def data(self, value: bytes) -> None:
        self._data = value


def list_to_prime(prime_list: list) -> PrimaryBlock:
    """
    Loops through list of primary block values. Only works with values that
    are in order as defined in RFC 9171.
    """
    block = PrimaryBlock()
    for attr_name, val in zip(block.serial_fields, prime_list):
        if "_" in attr_name and "eid" not in attr_name:
            attr_name = attr_name[1:]

        setattr(block, attr_name, val)
    return block


def list_to_canonical(canonical_list: list) -> CanonicalBlock:
    """
    Loops through list of canonical block values. Only works with values
    that are in order as defined in RFC 9171.
    """
    block = CanonicalBlock()
    for attr_name, val in zip(block.serial_fields, canonical_list):
        if "_" in attr_name:
            attr_name = attr_name[1:]
        setattr(block, attr_name, val)

    return block


def list_to_payload(payload_list: list) -> CanonicalBlock:
    """
    Loops through list of canonical block values. Only works with values that
    are in order as defined in RFC 9171. Specific to payload block as ADU
    handling is different.
    """
    block = PayloadBlock()
    for attr_name, val in zip(block.serial_fields, payload_list):
        if "_" in attr_name:
            attr_name = attr_name[1:]
        setattr(block, attr_name, val)

    return block
