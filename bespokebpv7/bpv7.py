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
 Title: Bundle Protocol v7 Class
 Author: Nate Richard
 Modified: 01/14/2026
 Company: JPL
 Date:   12/19/2025

 File: bpv7
 Description:
           Class that can dissect and create BPv7 bundles.
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

import warnings
from itertools import count
from typing import Any, Union

import cbor2
import dpkt  # type: ignore

from bespokebpv7.block_enum import BlockType, CRCType
from bespokebpv7.blocks import (
    CanonicalBlock,
    ExtensionBlocks,
    PayloadBlock,
    PrimaryBlock,
    list_to_canonical,
    list_to_payload,
    list_to_prime,
)
from bespokebpv7.utils import calculate_crc


class BPv7(dpkt.Packet):
    """
    Bundle Protocol Version 7 (RFC 9171)
    Format: [primary_block, *canonical_blocks]
    """

    def __init__(self, *args, debug=False, **kwargs):
        self.debug = debug
        self.primary_block = PrimaryBlock()
        self.blocks = ExtensionBlocks()
        super().__init__(*args, **kwargs)

        self.next_block_num = count(2)

    def __str__(self) -> str:
        lines = [
            f"{'=' * 40}",
            " BPv7 BUNDLE SUMMARY ",
            f"{'=' * 40}",
            f"Source:      {self.primary_block.route.source_eid}",
            f"Destination: {self.primary_block.route.dest_eid}",
            f"Created:     {self.primary_block.life.creation_dt.strftime('%Y-%m-%d %H:%M:%S')}",
            f"Blocks:      {1 + len(self.blocks)} (Primary + {len(self.blocks)} Canonical)",
            f"FLAGS:       {self.primary_block.flags}",
            f"{'=' * 40}",
        ]
        return "\n".join(lines)

    def __repr__(self) -> str:
        lines = [
            f"BPv7(src='{self.primary_block.route.source_eid}'"
            f", dst='{self.primary_block.route.dest_eid}',",
            f"flags={self.primary_block.flags})",
        ]
        return "\n".join(lines)

    def __bytes__(self) -> bytes:
        """Serializes as an indefinite CBOR array (0x9f ... 0xff)"""
        if self.primary_block:
            all_blocks = [self.primary_block.get_serializable_data()] + [
                extblock.get_serializable_data() for extblock in self.blocks.values()
            ]
            body = b"".join(cbor2.dumps(b) for b in all_blocks)
        else:
            body = b""
        return b"\x9f" + body + b"\xff"

    def add_canonical_block(
        self,
        type_code: BlockType,
        data: bytes,
        block_num: Union[int, None] = None,
        crc_type: CRCType = CRCType.NONE,
    ) -> None:
        """Helper to format a canonical block"""
        block = CanonicalBlock()
        if not block_num:
            block.block_number = next(self.next_block_num)
        else:
            block.block_number = block_num
        block.data = data
        block.block_type = type_code
        block.crc_type = crc_type
        self.blocks[type_code] = block

    def add_payload_block(self, data: bytes, crc_type=CRCType.NONE) -> None:
        """Adds a Payload Block with optional CRC"""
        block = PayloadBlock()
        block.data = data
        block.crc_type = crc_type
        self.blocks[BlockType.PAYLOAD_BLOCK] = block

    def get_block_by_type(self, type_code: BlockType) -> Union[Any, None]:
        """Returns the data field of the first block matching type_code"""
        try:
            return self.blocks[type_code]
        except KeyError:
            return None

    def unpack(self, buf: bytes) -> None:
        recv_exts = ""
        proc_exts = ""
        try:
            bundle_data = cbor2.loads(buf)
        except cbor2.CBORDecodeError:
            print("Error decoding bundle")
            return

        self.primary_block = list_to_prime(bundle_data[0])

        for exts in bundle_data[1:]:
            block_type = exts[0]
            if block_type == BlockType.PAYLOAD_BLOCK:
                ext = list_to_payload(exts)
            else:
                ext = list_to_canonical(exts)
            if self.debug:
                recv_ext = cbor2.dumps(exts).hex()
                recv_exts += recv_ext
                proc_ext = bytes(ext).hex()
                proc_exts += proc_ext
                print(
                    f"block {block_type:>3} in:  {recv_ext}\n",
                    f"block {int(ext.block_type):>3} out: {proc_ext}",
                    sep="",
                )
            self.blocks[block_type] = ext

        if self.debug:
            try:
                recv_hed = cbor2.dumps(bundle_data[0]).hex()
            except cbor2.CBOREncodeError:
                print("Error encoding data")
                return

            print(
                f"header in:  {recv_hed}\nheader out: {bytes(self.primary_block).hex()}"
            )
            print(f"received:  9f{recv_hed}{recv_exts}ff")
            print(f"processed: 9f{bytes(self.primary_block).hex()}{proc_exts}ff")
        # Basic validation: check if primary CRC matches (if present)
        if self.primary_block.crc_type != CRCType.NONE:
            actual_crc = self.primary_block.crc
            primary_check = self.primary_block.get_serializable_data()[:-1] + [
                self.primary_block.crc_type.fill_value
            ]
            expected_crc = calculate_crc(primary_check, self.primary_block.crc_type)
            if actual_crc != expected_crc:
                warnings.warn("Primary Block CRC mismatch!", UserWarning)
