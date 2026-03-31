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
 Title: Bundle Protocol v7 Class
 Author: Nate Richard
 Modified: 03/31/2026
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

import cbor2
import dpkt  # type: ignore[import-untyped]

from bespokebpv7.admin_records import (
    ADMINFUNCTIONS,
    BundleStatusReport,
)
from bespokebpv7.block_enum import AdminRecordType, BlockFlags, BlockType, CRCType
from bespokebpv7.blocks import (
    CanonicalBlock,
    CanonicalBlockInit,
    ExtensionBlocks,
    PrimaryBlock,
)
from bespokebpv7.ext_functions import BLOCKFUNCTIONS
from bespokebpv7.utils import bundle_converter, calculate_crc


class BPv7(dpkt.Packet):
    """Bundle Protocol Version 7 (RFC 9171)
    Format: [primary_block, *canonical_blocks]
    """

    def __init__(self, *args, debug: bool = False, **kwargs) -> None:
        """Initialize bundle parameters."""
        self.debug = debug
        self.primary_block = PrimaryBlock()
        self.blocks = ExtensionBlocks()
        self.proc_exts = ""
        self.recv_exts = ""
        super().__init__(*args, **kwargs)

        self.next_block_num = count(2)

    def __str__(self) -> str:
        """Display basic bundle info.

        Returns:
            String of bundle information

        """
        frmtstr = "%Y-%m-%d %H:%M:%S.%f"
        created_str = self.primary_block.life.creation_dt.strftime(frmtstr)
        block_str = f"(Primary + {len(self.blocks)} Canonical)"
        lines = [
            f"{'=' * 40}",
            " BPv7 BUNDLE SUMMARY ",
            f"{'=' * 40}",
            f"Source:      {self.primary_block.route.source_eid}",
            f"Destination: {self.primary_block.route.dest_eid}",
            f"Created:     {created_str}",
            f"Blocks:      {1 + len(self.blocks)} {block_str}",
            f"FLAGS:       {self.primary_block.flags}",
            f"{'=' * 40}",
        ]
        return "\n".join(lines)

    def __repr__(self) -> str:
        """Quick representation of a bundle.

        Returns:
            string of basic bundle info

        """
        src = f"src='{self.primary_block.route.source_eid}"
        dest = f"dst='{self.primary_block.route.dest_eid}'"
        return f"BPv7('{src}, {dest}, flags={self.primary_block.flags})"

    def __bytes__(self) -> bytes:
        """Serialize as an indefinite CBOR array (0x9f ... 0xff).

        Returns:
            bundle as byte string

        """
        pb_list = bundle_converter.unstructure(self.primary_block)

        ext_lists = [
            bundle_converter.unstructure(extblock) for extblock in self.blocks.values()
        ]

        all_blocks = [pb_list, *ext_lists]
        body = b"".join(bundle_converter.dumps(b) for b in all_blocks)
        return b"\x9f" + body + b"\xff"

    def __bool__(self) -> bool:
        """Ensure truthiness checks (like `if bundle:`) don't fall back
        to dpkt.Packet's __len__, which expects a fixed __hdr_len__.

        Returns:
            True always

        """
        return True

    def __len__(self) -> int:
        """Override dpkt's __len__ to return the actual serialized size
        since we dynamically parse CBOR instead of using fixed headers.

        Returns:
            Length of bundle

        """
        return len(bytes(self))

    def add_canonical_block(self, block_parms: CanonicalBlockInit, data: bytes) -> None:
        """Add an extension block."""
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
            crc = calculate_crc([*block_inputs, crc_type.fill_value], crc_type)
            block_inputs.append(crc)

        block_class = BLOCKFUNCTIONS.get(type_code, CanonicalBlock)
        self.blocks[type_code] = bundle_converter.structure(block_inputs, block_class)

    def add_payload_block(
        self,
        data: bytes,
        flags: BlockFlags | None = None,
        crc_type: CRCType = CRCType.NONE,
    ) -> None:
        """Add a Payload Block with optional CRC."""
        if not flags:
            flags = BlockFlags(0)

        block_inputs = [BlockType.PAYLOAD_BLOCK, 1, flags, crc_type, data]
        if crc_type != CRCType.NONE:
            crc = calculate_crc([*block_inputs, crc_type.fill_value], crc_type)
            block_inputs.append(crc)
        self.blocks[BlockType.PAYLOAD_BLOCK] = bundle_converter.structure(
            block_inputs,
            CanonicalBlock,
        )

    def get_block_by_type(self, type_code: BlockType) -> CanonicalBlock | None:
        """Return the first matching block of the matching type_code.

        Returns:
            Canonical block if exists

        """
        try:
            return self.blocks[type_code]
        except KeyError:
            return None

    def unpack(self, buf: bytes) -> None:
        """Unpack indefinite CBOR array into a Bundle.

        Raises:
            ValueError: if it can't decode CBOR

        """
        try:
            bundle_data = bundle_converter.loads(buf, list)
        except cbor2.CBORDecodeError as err:
            errmsg = "CBOR decoding issue"
            raise ValueError(errmsg) from err

        self.primary_block = bundle_converter.structure(bundle_data[0], PrimaryBlock)

        ext: CanonicalBlock
        for exts in bundle_data[1:]:
            block_type = BlockType(exts[0])
            if (
                self.primary_block.adu_is_admin
                and block_type == BlockType.PAYLOAD_BLOCK
            ):
                admin_record = bundle_converter.loads(exts[4], list)
                block = ADMINFUNCTIONS.get(
                    AdminRecordType(admin_record[0]), BundleStatusReport
                )
            else:
                block = BLOCKFUNCTIONS.get(block_type, CanonicalBlock)
            ext = bundle_converter.structure(exts, block)

            self.blocks[block_type] = ext
            if self.debug:
                self._debug(exts, block_type, "block")

        if self.debug:
            self._debug(bundle_data[0])

        if self.primary_block.crc_type != CRCType.NONE:
            actual_crc = self.primary_block.crc
            primary_list = bundle_converter.unstructure(self.primary_block)

            primary_check = [*primary_list[:-1], self.primary_block.crc_type.fill_value]

            expected_crc = calculate_crc(primary_check, self.primary_block.crc_type)
            if actual_crc != expected_crc:
                warnings.warn("Primary Block CRC mismatch!", UserWarning, stacklevel=2)

    def _debug(
        self,
        in_data: list,
        block_type: BlockType | None = None,
        typestr: str = "header",
    ) -> None:
        """Display debugging parsing."""
        type_str_in = f"{typestr}  in"
        type_str_out = f"{typestr} out"
        if typestr == "block":
            out_num = self.blocks[block_type].block_type
            type_str_in = f"{typestr} {block_type:>3}"
            type_str_out = f"{typestr} {int(out_num):>3}"

        hexstr = bundle_converter.dumps(in_data).hex()
        if typestr == "block":
            blk = self.blocks[block_type]
            out_data = bundle_converter.dumps(blk).hex()

            self.recv_exts += hexstr
            self.proc_exts += out_data
        else:
            out_data = bytes(self.primary_block).hex()

        print(f"{type_str_in}:  {hexstr}\n{type_str_out}:  {out_data}")  # noqa: T201

        if typestr == "header":
            print(f"received:  9f{hexstr}{self.recv_exts}ff")  # noqa: T201
            print(f"processed: 9f{bytes(self.primary_block).hex()}{self.proc_exts}ff")  # noqa: T201
