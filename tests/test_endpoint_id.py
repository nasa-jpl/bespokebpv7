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
 Title: EndpointID wire behavior tests
 Author: Nate Richard
 Modified: 11/11/2026
 Company: JPL
 Date:   11/11/2026

 File: test_endpoint_id
 Description:
           EndpointID typed forms, raw passthrough, and BPSec security_source

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

from typing import Any

import pytest

import bespokebpv7
from bespokebpv7 import BPv7
from bespokebpv7.block_enum import BlockType
from bespokebpv7.bpsec import BlockIntegrityBlock
from bespokebpv7.bundle_params import BundleRoute, EndpointID
from bespokebpv7.ext_functions import PreviousNodeExt


@pytest.mark.parametrize(
    "wire",
    [
        [1, "none"],
        [99, "x"],
        [],
        [2, [0, 2, 1]],
        5,
        [2, [1]],
    ],
)
def test_endpoint_id_raw_passthrough_malformed(wire: Any) -> None:
    """Malformed wire forms are kept verbatim and re-emitted unchanged."""
    eid = EndpointID.from_value(wire)
    assert eid.to_cbor() == wire
    assert EndpointID.from_value(eid.to_cbor()).to_cbor() == wire


def test_security_source_default_is_dtn_none_wire() -> None:
    """The BIB default serializes to the RFC form [1, 0]."""
    bib = BlockIntegrityBlock(block_number=2)
    assert bib.security_source.to_cbor() == [1, 0]


def test_security_source_ipn_wire() -> None:
    """ipn:2.1 serializes to the 2-element FQNN form."""
    bib = BlockIntegrityBlock(block_number=2)
    bib.security_source = "ipn:2.1"  # type: ignore[assignment]
    assert bib.security_source.to_cbor() == [2, [2, 1]]


def test_legacy_security_source_bib_reencodes_identically() -> None:
    """A decoded legacy [1, "none"] security_source re-encodes identically."""
    bundle = BPv7()
    bundle.primary_block.route.dest_eid = "ipn:1.2"
    bundle.primary_block.route.source_eid = "ipn:2.1"
    bundle.primary_block.route.report_to = "ipn:2.1"
    bundle.primary_block.life.timestamp_ms = 0
    bundle.primary_block.life.sequence = 40
    bundle.primary_block.life.lifetime = 1000000

    bib = BlockIntegrityBlock(block_number=2)
    bib.security_targets = [1]
    bib.security_source = [1, "none"]  # type: ignore[assignment]
    bib.add_security_result(b"\x00" * 64)
    bundle.blocks[BlockType.BIB] = bib
    bundle.add_payload_block(b"payload")

    encoded = bytes(bundle)
    parsed = BPv7(encoded)
    bib_parsed = parsed.get_block_by_type(BlockType.BIB)
    assert isinstance(bib_parsed, BlockIntegrityBlock)
    assert bib_parsed.security_source.to_cbor() == [1, "none"]
    assert bytes(parsed) == encoded


def test_endpoint_id_exported() -> None:
    """EndpointID is exported from the package root."""
    assert bespokebpv7.EndpointID is EndpointID
    assert "EndpointID" in bespokebpv7.__all__


@pytest.mark.parametrize("uri", ["ipn:2.1", "dtn:none", "ipn:977000.100.1"])
def test_eid_setter_accepts_endpoint_id(uri: str) -> None:
    """EID setters accept an EndpointID and store the same EID as the string form."""
    route = BundleRoute()
    route.dest_eid = EndpointID.from_value(uri)
    assert route.dest_eid == uri
    route.source_eid = EndpointID.from_value(uri)
    assert route.source_eid == uri


def test_extension_eid_setter_accepts_endpoint_id() -> None:
    """Extension EID setters accept an EndpointID."""
    ext = PreviousNodeExt()
    ext.previous_node = EndpointID.from_value("ipn:2.1")
    assert ext.previous_node == "ipn:2.1"
