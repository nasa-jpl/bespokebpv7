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
 Title: Utility functions for bundle processing
 Author: Nate Richard
 Modified: 01/16/2026
 Company: JPL
 Date:   12/19/2025

 File: utils
 Description:
           Functions that help with bundle processing and can be useful
           beyond direct bundle processing.
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
import struct
from typing import Optional, Union

import cbor2
import fastcrc

from bespokebpv7.block_enum import CRCType, SchemeCode

DTN_EPOCH = datetime.datetime(2000, 1, 1, tzinfo=datetime.timezone.utc)


def calculate_crc(block_list: list, crc_type: CRCType) -> Optional[bytes]:
    """
    Calculates CRC per RFC 9171.
    The CRC field (last element) is replaced by an empty byte string for calculation.
    """
    if crc_type == CRCType.NONE:
        return None

    data_to_hash = cbor2.dumps(block_list)

    if crc_type == CRCType.CRC16:
        # CRC-16/X-25
        crc_int = fastcrc.crc16.ibm_sdlc(data_to_hash)
        return struct.pack(">H", crc_int)

    if crc_type == CRCType.CRC32:
        # CRC-32C (Castagnoli)
        crc_int = fastcrc.crc32.iscsi(data_to_hash)
        return struct.pack(">L", crc_int)
    return None


def parse_eid_string(eid_str: str) -> list[Union[int, Union[list[int], str]]]:
    """
    Converts 'ipn:node.service' or 'dtn:name' into CBOR list format.
    - ipn:3.1 -> [2, 3, 1]
    - dtn:node1 -> [1, "node1"]
    """
    if ":" not in eid_str:
        return [int(SchemeCode.DTN), eid_str]
    scheme, ssp = eid_str.split(":")
    if scheme.lower() == "ipn":
        parts = ssp.split(".")
        node = int(parts[0])
        service = int(parts[1]) if len(parts) > 1 else 0
        return [int(SchemeCode.IPN), [node, service]]

    # assume some sort of type conversion error as a CBOR unsigned int of 0
    # means dtn:none per RFC 9171 4.2.5.11
    if ssp in ["0", "none"]:
        return [int(SchemeCode.DTN), 0]
    return [int(SchemeCode.DTN), ssp]


def format_eid(eid: list) -> str:
    """
    Parses the EID array at primary_block[eid_index] into a URI string.
    """
    scheme = SchemeCode(eid[0])

    if scheme == SchemeCode.IPN:
        # ipn format: [2, [node_number, service_number]] -> ipn:node.service
        node_nums = eid[1]
        return f"ipn:{node_nums[0]}.{node_nums[1]}"

    if scheme == SchemeCode.DTN:
        # dtn format: [1, "string-name"] -> dtn:string-name
        dtnstr = eid[1]
        if dtnstr == 0:
            dtnstr = "none"
        return f"dtn:{dtnstr}"

    return "unknown:none"
