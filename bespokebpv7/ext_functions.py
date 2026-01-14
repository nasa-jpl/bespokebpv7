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
 Title: Bundle Extension Block functions
 Author: Nate Richard
 Modified: 01/14/2025
 Company: JPL
 Date:   12/19/2025

 File: ext_functions
 Description:
           Functions to help with creation and reading of extension blocks
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
from typing import Union
import cbor2

from bespokebpv7.block_enum import BlockType
from bespokebpv7.blocks import CanonicalBlock
from bespokebpv7.utils import format_eid, parse_eid_string


def process_bae(bae: CanonicalBlock) -> Union[int, None]:
    """Extract Bundle Age from Canonical block."""
    if bae.block_type != BlockType.BUNDLE_AGE:
        print("Wrong block")
        return None

    bundle_age = cbor2.loads(bae.data)
    return bundle_age


def create_bae(age: int) -> bytes:
    """Format data required to add BAE."""
    return cbor2.dumps(age)


def process_pnb(bae: CanonicalBlock) -> Union[str, None]:
    """Extract Previous Node from Canonical block."""
    if bae.block_type != BlockType.PREVIOUS_NODE:
        print("Wrong block")
        return None

    bundle_age = cbor2.loads(bae.data)
    return format_eid(bundle_age)


def create_pnb(previous_node: str) -> bytes:
    """Format data required to add BAE."""
    return cbor2.dumps(parse_eid_string(previous_node))


def process_hcb(hcb: CanonicalBlock) -> tuple:
    """Extract bundle hop count data."""
    if hcb.block_type != BlockType.HOP_COUNT:
        print("Wrong block")
        return None, None

    hop_list = cbor2.loads(hcb.data)
    return hop_list[0], hop_list[1]


def create_hcb(hop_limit: int, hop_count: int = 0) -> bytes:
    """Format data required to add bundle hop count."""
    return cbor2.dumps([hop_limit, hop_count])


def process_bib():
    """Extract BIB data."""


def create_bib():
    """Format data required to add BIB."""
