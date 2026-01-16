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
 Modified: 01/16/2026
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
from typing import Any, Optional

import cbor2
import dpkt  # type: ignore

from bespokebpv7.block_enum import BlockFlags, BlockType, CRCType
from bespokebpv7.blocks import (
    CanonicalBlock,
    CanonicalBlockInit,
    ExtensionBlocks,
    PrimaryBlock,
    block_converter,
)
from bespokebpv7.ext_functions import BLOCKFUNCTIONS, ext_converter
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
        self.proc_exts = ""
        self.recv_exts = ""
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
        pb_list = block_converter.unstructure(self.primary_block)

        ext_lists = [
            ext_converter.unstructure(extblock) for extblock in self.blocks.values()
        ]

        all_blocks = [pb_list] + ext_lists
        body = b"".join(cbor2.dumps(b) for b in all_blocks)
        return b"\x9f" + body + b"\xff"

    def add_canonical_block(self, block_parms: CanonicalBlockInit, data: bytes) -> None:
        """Helper to format a canonical block"""
        type_code = block_parms["block_type"]

        if "block_num" not in block_parms:
            block_number = next(self.next_block_num)
        else:
            block_number = block_parms["block_num"]

        if "crc_type" not in block_parms:
            crc_type = CRCType.NONE
        else:
            crc_type = block_parms["crc_type"]

        if "block_flags" not in block_parms:
            flags = BlockFlags(0)
        else:
            flags = block_parms["block_flags"]

        block_inputs = [type_code, block_number, flags, crc_type, data]

        if crc_type and crc_type != CRCType.NONE:
            crc = calculate_crc(block_inputs + [crc_type.fill_value], crc_type)
            block_inputs.append(crc)

        block = BLOCKFUNCTIONS.get(type_code, CanonicalBlock)
        self.blocks[type_code] = ext_converter.structure(block_inputs, block)

    def add_payload_block(
        self, data: bytes, flags: BlockFlags = BlockFlags(0), crc_type=CRCType.NONE
    ) -> None:
        """Adds a Payload Block with optional CRC"""
        block_inputs = [BlockType.PAYLOAD_BLOCK, 1, flags, crc_type, data]
        if crc_type != CRCType.NONE:
            crc = calculate_crc(block_inputs + [crc_type.fill_value], crc_type)
            block_inputs.append(crc)
        self.blocks[BlockType.PAYLOAD_BLOCK] = block_converter.structure(
            block_inputs, CanonicalBlock
        )

    def get_block_by_type(self, type_code: BlockType) -> Optional[Any]:
        """Returns the data field of the first block matching type_code"""
        try:
            return self.blocks[type_code]
        except KeyError:
            return None

    def unpack(self, buf: bytes) -> None:
        try:
            bundle_data = cbor2.loads(buf)
        except cbor2.CBORDecodeError as err:
            raise ValueError("Unable to decode cbor array.") from err

        self.primary_block = block_converter.structure(bundle_data[0], PrimaryBlock)

        ext: CanonicalBlock
        for exts in bundle_data[1:]:
            block_type = BlockType(exts[0])
            block = BLOCKFUNCTIONS.get(block_type, CanonicalBlock)
            ext = ext_converter.structure(exts, block)

            self.blocks[block_type] = ext
            if self.debug:
                self._debug(exts, block_type)

        if self.debug:
            self._debug(bundle_data[0], header=True)

        if self.primary_block.crc_type != CRCType.NONE:
            actual_crc = self.primary_block.crc
            primary_list = block_converter.unstructure(self.primary_block)

            primary_check = primary_list[:-1] + [self.primary_block.crc_type.fill_value]

            expected_crc = calculate_crc(primary_check, self.primary_block.crc_type)
            if actual_crc != expected_crc:
                warnings.warn("Primary Block CRC mismatch!", UserWarning)

    def _debug(
        self,
        in_data: list,
        block_type: Optional[BlockType] = None,
        header: bool = False,
    ) -> None:
        """Function to help with debugging parsing."""
        type_str_in = "header in"
        type_str_out = "header out"
        if not header:
            out_num = self.blocks[block_type].block_type
            type_str_in = f"block {block_type:>3}"
            type_str_out = f"block {int(out_num):>3}"

        hexstr = cbor2.dumps(in_data).hex()
        if not header:
            out_data = bytes(self.blocks[block_type]).hex()
            self.recv_exts += hexstr
            self.proc_exts += out_data
        else:
            out_data = bytes(self.primary_block).hex()

        print(f"{type_str_in}:  {hexstr}\n{type_str_out}:  {out_data}", sep="")

        if header:
            print(f"received:  9f{hexstr}{self.recv_exts}ff")
            print(f"processed: 9f{bytes(self.primary_block).hex()}{self.proc_exts}ff")
