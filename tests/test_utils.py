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
 Modified: 01/27/2026
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

from hypothesis import given
from strategies import st_eid

from bespokebpv7.block_enum import CRCType  # type: ignore[import-untyped]
from bespokebpv7.utils import (  # type: ignore[import-untyped]
    calculate_crc,
    format_eid,
    parse_eid_string,
)


# ==========================================
# Tests for bespokebpv7/utils.py
# ==========================================
@given(st_eid)
def test_eid_roundtrip(eid_str: str) -> None:
    """Test that parsing and then formatting an EID returns the original string."""
    parsed = parse_eid_string(eid_str)
    formatted = format_eid(parsed)
    # Note: dtn:none edge case handling might result in dtn:0 -> dtn:none
    if eid_str in {"dtn:none", "dtn:0"}:
        assert formatted == "dtn:none"
    else:
        assert formatted == eid_str


def test_parse_eid_defaults() -> None:
    """Test parsing edge cases."""
    parsed = parse_eid_string("node1")
    assert parsed == [1, "node1"]

    parsed_none = parse_eid_string("dtn:none")
    assert parsed_none == [1, 0]

    parsed_0 = parse_eid_string("dtn:0")
    assert parsed_0 == [1, 0]


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
