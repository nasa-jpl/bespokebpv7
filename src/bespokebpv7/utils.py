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
 Modified: 07/13/2026
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

import copy
import datetime as dt
import io
import struct
from typing import Any

import cbor2
import fastcrc
from cattrs.preconf.cbor2 import make_converter
from cattrs.strategies import use_class_methods

from bespokebpv7.block_enum import CRCType, SchemeCode

__all__ = ["DTN_EPOCH", "calculate_crc", "format_eid", "parse_eid_string"]

DTN_EPOCH = dt.datetime(2000, 1, 1, tzinfo=dt.timezone.utc)
LOCAL_NODE = 2**32 - 1
LEGACY_LIST = 2
ALLOCATOR_LIST = 3
MAX_SDNV_LEN = 10
# Schemes whose SSP is [allocator, number, service], where number is the node
# (ipn) or group (imc) number. A tuple, not a set: membership tests then use ==
# and never hash arbitrary list elements.
NUMBERED_SCHEMES = (SchemeCode.IPN, SchemeCode.IMC)


def calculate_crc(block_list: list[Any], crc_type: CRCType) -> bytes | None:
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


def _expand_legacy_ssp(eid: list[Any]) -> list[Any]:
    """Expand a 2-element ipn/imc SSP ``[fqn, service]`` to 3 elements.

    The fully qualified node (ipn) or group (imc) number packs the allocator
    into its upper 32 bits and the node or group number into its lower 32 bits.

    Returns:
        ``[scheme, [allocator, number, service]]``, or the Null EID for ipn:0.0

    """
    scheme = int(eid[0])
    fqn, service = eid[1]
    allocator = fqn >> 32
    number = fqn & 0xFFFFFFFF
    # Only ipn has a null form; ION uses imc:0.0 as a real (admin) endpoint.
    if scheme == SchemeCode.IPN and allocator == 0 and number == 0:
        return [int(SchemeCode.DTN), 0]
    return [scheme, [allocator, number, service]]


def _split_numbered_ssp(parts: list[str]) -> tuple[int, str, int]:
    """Split the 2 or 3 dot-separated parts of an ipn/imc URI's SSP.

    Returns:
        The allocator (0 when omitted), the node or group number as text,
        and the service

    """
    if len(parts) == LEGACY_LIST:
        return 0, parts[0], int(parts[1])
    return int(parts[0]), parts[1], int(parts[2])


def parse_eid_string(eid_str: str | list[Any]) -> list[Any]:
    """Convert 'ipn:allocator.node.service', 'ipn:node.service',
    'imc:allocator.group.service', 'imc:group.service' or 'dtn:name'
    into CBOR list format.

    Returns:
        A logical 3-element list for IPN [SchemeCode.IPN, [allocator, node, service]]
        or IMC [SchemeCode.IMC, [allocator, group, service]], or a DTN scheme list.

    Raises:
        ValueError: if given format does not match a valid scheme

    """
    if isinstance(eid_str, list):
        if (
            eid_str[0] in NUMBERED_SCHEMES
            and isinstance(eid_str[1], list)
            and len(eid_str[1]) == LEGACY_LIST
        ):
            return _expand_legacy_ssp(eid_str)
        return copy.deepcopy(eid_str)

    if ":" not in eid_str:
        return [int(SchemeCode.DTN), eid_str]

    scheme, ssp = eid_str.split(":", 1)
    scheme = scheme.lower()

    if scheme in {"ipn", "imc"}:
        parts = ssp.split(".")
        if len(parts) not in {LEGACY_LIST, ALLOCATOR_LIST}:
            errmsg = f"Invalid {scheme} URI format."
            raise ValueError(errmsg)
        allocator, number_str, service = _split_numbered_ssp(parts)

        if scheme == "imc":
            return [int(SchemeCode.IMC), [allocator, int(number_str), service]]

        node = LOCAL_NODE if number_str == "!" else int(number_str)

        return (
            [int(SchemeCode.DTN), 0]
            if allocator == 0 and node == 0
            else [int(SchemeCode.IPN), [allocator, node, service]]
        )

    return [int(SchemeCode.DTN), 0 if ssp in {"0", "none"} else ssp]


def format_eid(eid: list[Any]) -> str:
    """Parse the EID array at primary_block[eid_index] into a URI string.

    Returns:
        A string representation of the endpoint.

    """
    scheme = SchemeCode(eid[0])

    if scheme in NUMBERED_SCHEMES:
        ssp = eid[1]
        if len(ssp) == LEGACY_LIST:
            # Handle standard FQNN/FQGN unpacking just in case it slipped through
            fqn, service = ssp
            allocator = fqn >> 32
            number = fqn & 0xFFFFFFFF
        else:
            allocator, number, service = ssp

        # "!" (local node) only exists in the ipn scheme
        local = scheme == SchemeCode.IPN and number == LOCAL_NODE
        number_str = "!" if local else str(number)
        prefix = scheme.name.lower()

        # Omit allocator if it is the Default Allocator (0)
        if allocator == 0:
            return f"{prefix}:{number_str}.{service}"
        return f"{prefix}:{allocator}.{number_str}.{service}"

    if scheme == SchemeCode.DTN:
        dtnstr = eid[1]
        if dtnstr == 0 or dtnstr is None:
            dtnstr = "none"
        return f"dtn:{dtnstr}"

    return "unknown:none"


def unstructure_eid_list(obj: list[Any]) -> list[Any]:
    """List hook, which forces 2-element CBOR encoding for Default Allocators.

    Returns:
        unstructured list

    """
    # Check if this is an IPN or IMC EID list
    if (
        len(obj) == LEGACY_LIST
        and obj[0] in NUMBERED_SCHEMES
        and isinstance(obj[1], list)
    ):
        ssp = obj[1]
        if len(ssp) == ALLOCATOR_LIST:
            allocator, number, service = ssp
            # Fall back to 2-element encoding for backwards compatibility
            if allocator == 0:
                # Pack FQNN (ipn) or FQGN (imc):
                # Most significant 32 bits = Allocator
                # Least significant 32 bits = Node or Group Number
                fqn = (allocator << 32) | (number & 0xFFFFFFFF)
                return [obj[0], [fqn, service]]
            # 3-element encoding is RECOMMENDED for non-default allocators
            return [obj[0], [allocator, number, service]]

    # For all other standard lists, apply recursive unstructuring
    return [bundle_converter.unstructure(item) for item in obj]


def decode_cbor_sequence(data: bytes) -> list[Any]:
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


def encode_cbor_sequence(objects: list[Any]) -> bytes:
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
        ValueError: If the byte string ends before the SDNV is fully
            terminated.
        ValueError: If the SDNV exceeds the maximum encodable length of
            10 bytes.

    """
    value = 0
    bytes_consumed = 0

    for byte in data:
        bytes_consumed += 1

        if bytes_consumed > MAX_SDNV_LEN:
            msg = "SDNV exceeds maximum encodable length (10 bytes)"
            raise ValueError(msg)

        value <<= 7
        value += byte & 0x7F

        if (byte & 0x80) == 0:
            break
    else:
        # We exhausted the bytes without finding a terminal byte (MSB == 0)
        msg = "Incomplete SDNV data: missing terminal byte."
        raise ValueError(msg)

    return value, bytes_consumed


bundle_converter = make_converter()
use_class_methods(bundle_converter, "_structure", "_unstructure")
bundle_converter.register_unstructure_hook(list, unstructure_eid_list)
