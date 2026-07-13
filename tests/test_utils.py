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
 Title: Bespoke BPv7 test suite for utils.py
 Author: Nate Richard
 Modified: 07/13/2026
 Company: JPL
 Date:   01/27/2026

 File: test_utils
 Description:
           Tests to verify functionality of utils functions
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

import pytest
from hypothesis import given
from hypothesis import strategies as st
from strategies import st_eid

from bespokebpv7.block_enum import SchemeCode
from bespokebpv7 import CRCType
from bespokebpv7.utils import (
    calculate_crc,
    decode_sdnv,
    encode_sdnv,
    format_eid,
    parse_eid_string,
    unstructure_eid_list,
)


# ==========================================
# Tests for bespokebpv7/utils.py
# ==========================================
@given(st_eid)
def test_eid_structural_roundtrip(eid_str: str) -> None:
    """Test that parsing a formatted EID matches the original internal structure."""
    initial_parsed = parse_eid_string(eid_str)
    formatted_str = format_eid(initial_parsed)
    second_parsed = parse_eid_string(formatted_str)

    assert initial_parsed == second_parsed


def test_parse_eid_defaults() -> None:
    """Test parsing edge cases."""
    parsed = parse_eid_string("node1")
    assert parsed == [int(SchemeCode.DTN), "node1"]

    parsed_none = parse_eid_string("dtn:none")
    assert parsed_none == [int(SchemeCode.DTN), 0]

    parsed_0 = parse_eid_string("dtn:0")
    assert parsed_0 == [int(SchemeCode.DTN), 0]


def test_parse_ipn_eid() -> None:
    """Verify parsing of the updated IPN scheme."""
    # Standard default allocator
    assert parse_eid_string("ipn:1.2") == [int(SchemeCode.IPN), [0, 1, 2]]

    # Explicit non-default allocator
    assert parse_eid_string("ipn:977000.100.1") == [
        int(SchemeCode.IPN),
        [977000, 100, 1],
    ]

    # LocalNode shorthand
    assert parse_eid_string("ipn:!.7") == [int(SchemeCode.IPN), [0, 4294967295, 7]]

    # Unpacking FQNN from 2-element CBOR lists
    fqnn = (977000 << 32) | 100
    assert parse_eid_string([int(SchemeCode.IPN), [fqnn, 1]]) == [
        int(SchemeCode.IPN),
        [977000, 100, 1],
    ]

    # Invalid formats
    with pytest.raises(ValueError, match=r"Invalid ipn URI format."):
        parse_eid_string("ipn:1")


def test_format_ipn_eid() -> None:
    """Verify formatting of the updated IPN scheme."""
    # Standard default allocator
    assert format_eid([int(SchemeCode.IPN), [0, 1, 2]]) == "ipn:1.2"

    # Explicit non-default allocator
    assert format_eid([int(SchemeCode.IPN), [977000, 100, 1]]) == "ipn:977000.100.1"

    # LocalNode shorthand
    assert format_eid([int(SchemeCode.IPN), [0, 4294967295, 7]]) == "ipn:!.7"

    # Formatting from 2-element CBOR lists directly
    fqnn = (977000 << 32) | 100
    assert format_eid([int(SchemeCode.IPN), [fqnn, 1]]) == "ipn:977000.100.1"


def test_unstructure_eid_list() -> None:
    """Verify the custom cattrs hook correctly handles FQNN packing."""
    # Default allocator packs into 2 elements
    # FQNN for allocator 0, node 1 is just 1
    assert unstructure_eid_list([int(SchemeCode.IPN), [0, 1, 2]]) == [
        int(SchemeCode.IPN),
        [1, 2],
    ]

    # Non-default allocator stays as 3 elements
    assert unstructure_eid_list([int(SchemeCode.IPN), [977000, 100, 1]]) == [
        int(SchemeCode.IPN),
        [977000, 100, 1],
    ]

    # Non-IPN lists should be passed through normally
    assert unstructure_eid_list([int(SchemeCode.DTN), "node1"]) == [
        int(SchemeCode.DTN),
        "node1",
    ]


def test_calculate_crc() -> None:
    """Test CRC calculation."""
    data = [1, 2, b""]

    crc16 = calculate_crc(data, CRCType.CRC16)
    assert crc16
    assert len(crc16) == len(CRCType.CRC16.fill_value)

    crc32 = calculate_crc(data, CRCType.CRC32)
    assert crc32
    assert len(crc32) == len(CRCType.CRC32.fill_value)

    assert calculate_crc(data, CRCType.NONE) is None


# ==========================================
# Tests for SDNV Utilities
# ==========================================
@given(st.integers(min_value=0, max_value=2**64 - 1))
def test_sdnv_roundtrip(value: int) -> None:
    """Verify that an integer can be encoded to and decoded from an SDNV."""
    encoded_bytes = encode_sdnv(value)

    assert isinstance(encoded_bytes, bytes)
    assert len(encoded_bytes) > 0

    assert (encoded_bytes[-1] & 0x80) == 0

    decoded_value, bytes_consumed = decode_sdnv(encoded_bytes)

    assert decoded_value == value
    assert bytes_consumed == len(encoded_bytes)


def test_sdnv_negative_value() -> None:
    """Verify that negative values raise a ValueError during encoding."""
    with pytest.raises(ValueError, match=r"SDNVs cannot encode negative integers."):
        encode_sdnv(-1)


def test_sdnv_incomplete_buffer() -> None:
    """Verify that a truncated SDNV buffer raises a ValueError."""
    bad_data = b"\x81\x82\x83"
    with pytest.raises(
        ValueError, match=r"Incomplete SDNV data: missing terminal byte."
    ):
        decode_sdnv(bad_data)

def test_parse_ipn_null_uri() -> None:
    """Verify that Null IPN URIs are treated as the Null EID (dtn:none)."""
    # RFC 9758: ipn:0.0.<nonzero> is a Null URI
    assert parse_eid_string("ipn:0.0.1") == [int(SchemeCode.DTN), 0]
    assert parse_eid_string("ipn:0.0.12345") == [int(SchemeCode.DTN), 0]

    # Case with 2-element CBOR input (FQNN=0)
    assert parse_eid_string([int(SchemeCode.IPN), [0, 1]]) == [int(SchemeCode.DTN), 0]
