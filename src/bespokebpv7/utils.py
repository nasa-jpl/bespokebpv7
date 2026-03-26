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
 Title: Utility functions for bundle processing
 Author: Nate Richard
 Modified: 03/24/2026
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
import io
import struct

import cbor2
import fastcrc
from cattrs.preconf.cbor2 import make_converter
from cattrs.strategies import use_class_methods

from bespokebpv7.block_enum import CRCType, SchemeCode

DTN_EPOCH = datetime.datetime(2000, 1, 1, tzinfo=datetime.timezone.utc)


def calculate_crc(block_list: list, crc_type: CRCType) -> bytes | None:
    """Calculate CRC per RFC 9171.
    The CRC field (last element) is replaced by an empty byte string for calculation.

    Returns:
        CRC as bytes or None if unexpected type or type NONE

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


def parse_eid_string(eid_str: str) -> list[int | list[int] | str]:
    """Convert 'ipn:node.service' or 'dtn:name' into CBOR list format.
    - ipn:3.1 -> [2, 3, 1]
    - dtn:node1 -> [1, "node1"]

    Returns:
        list where first element is scheme type, the either a list of ints for
        IPN scheme or a string for a DTN scheme

    """
    # attrs converter maybe sending lists, so just return them
    if isinstance(eid_str, list):
        return eid_str
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
    if ssp in {"0", "none"}:
        return [int(SchemeCode.DTN), 0]
    return [int(SchemeCode.DTN), ssp]


def format_eid(eid: list) -> str:
    """Parse the EID array at primary_block[eid_index] into a URI string.

    Returns:
        A string representation of the endpoint

    """
    scheme = SchemeCode(eid[0])

    if scheme == SchemeCode.IPN:
        # ipn format: [2, [node_number, service_number]] -> ipn:node.service
        node_nums = eid[1]
        return f"ipn:{node_nums[0]}.{node_nums[1]}"

    if scheme == SchemeCode.DTN:
        # dtn format: [1, "string-name"] -> dtn:string-name
        dtnstr = eid[1]
        if dtnstr == 0 or dtnstr is None:
            dtnstr = "none"
        return f"dtn:{dtnstr}"

    return "unknown:none"


def decode_cbor_sequence(data: bytes) -> list:
    """
    Decode a sequence of CBOR objects from bytes.

    Args:
        data: Raw bytes containing CBOR-encoded data

    Returns:
        A list of decoded CBOR objects

    """
    stream = io.BytesIO(data)
    decoder = cbor2.CBORDecoder(stream)
    results = []

    while stream.tell() < len(data):
        obj = decoder.decode()
        results.append(obj)

    return results


def encode_cbor_sequence(objects: list) -> bytes:
    """
    Encode a sequence of objects into CBOR bytes.

    Args:
        objects: A list of objects to encode as CBOR

    Returns:
        Raw bytes containing the CBOR-encoded sequence

    """
    stream = io.BytesIO()
    encoder = cbor2.CBOREncoder(stream)

    for obj in objects:
        encoder.encode(obj)

    return stream.getvalue()


def encode_sdnv(value: int) -> bytes:
    """Encode a non-negative integer into a Self-Delimiting Numeric Value (SDNV).

    Args:
        value: The integer to encode.

    Returns:
        The SDNV encoded byte string.

    Raises:
        ValueError: If the integer is negative.

    """
    if value < 0:
        msg = "SDNVs cannot encode negative integers."
        raise ValueError(msg)

    if value == 0:
        return b"\x00"

    result = bytearray()

    # Extract 7-bit chunks from the value
    flag = 0
    while value > 0:
        new_bits = value & 0x7F
        value >>= 7
        result.append(new_bits + flag)
        if flag == 0:
            flag = 0x80

    # The chunks were extracted from least-significant to most-significant.
    # We need them in big-endian order, so we reverse the bytearray.
    result.reverse()
    return bytes(result)


def decode_sdnv(data: bytes) -> tuple[int, int]:
    """Decode an SDNV from a byte string.

    Args:
        data: A byte string starting with an SDNV.

    Returns:
        A tuple containing:
            - The decoded integer value.
            - The number of bytes consumed from the byte string.

    Raises:
        ValueError: If the byte string ends before the SDNV is fully terminated.

    """
    value = 0
    bytes_consumed = 0

    for byte in data:
        value <<= 7
        value += byte & 0x7F

        bytes_consumed += 1

        if (byte & 0x80) == 0:
            break
    else:
        # We exhausted the bytes without finding a terminal byte (MSB == 0)
        msg = "Incomplete SDNV data: missing terminal byte."
        raise ValueError(msg)

    return value, bytes_consumed


bundle_converter = make_converter()
use_class_methods(bundle_converter, "_structure", "_unstructure")
