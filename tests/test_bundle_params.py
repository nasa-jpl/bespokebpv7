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
 Title: Bespoke BPv7 test suite for bundle_params.py
 Author: Nate Richard
 Modified: 07/13/2026
 Company: JPL
 Date:   01/27/2026

 File: test_bundle_params
 Description:
           Tests to verify functionality of bundle_params classes & functions
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

import datetime as dt
from typing import Any

import pytest
from hypothesis import given
from strategies import st_eid

from bespokebpv7 import DTN_EPOCH, format_eid, parse_eid_string
from bespokebpv7.bundle_params import (
    BaseStatusReport,
    BundleLife,
    BundleRoute,
    CRBundleSequence,
    CreationTime,
    CTBundleSequence,
    EndpointID,
    StatusAssertion,
)


# ==========================================
# Tests for bespokebpv7/bundle_params.py
# ==========================================
@given(st_eid, st_eid)
def test_bundle_route(src: str, dst: str) -> None:
    """Verify values are stored correctly in BundleRoute class."""
    expected_src = format_eid(parse_eid_string(src))
    expected_dest = format_eid(parse_eid_string(dst))

    route = BundleRoute()
    route.source_eid = src
    route.dest_eid = dst

    assert route.source_eid == expected_src
    assert route.dest_eid == expected_dest

    raw_list = [1, "test"]
    route.report_to = raw_list
    assert route.report_to == "dtn:test"


def test_bundle_life() -> None:
    """Verify bundle lifetime information is stored correctly in BundleLife."""
    life = BundleLife()
    life.timestamp_ms = 1000
    expected_dt = DTN_EPOCH + dt.timedelta(milliseconds=1000)
    assert life.creation_dt == expected_dt


def test_status_assertion_methods() -> None:
    """Test helper methods in StatusAssertion."""
    sa = StatusAssertion()

    # Default state
    assert sa.asserted_time is None
    assert sa.asserted_dt is None

    # Set explicit time
    ms = 1000
    sa.set_asserted_time(ms)
    assert sa.asserted_time == ms
    assert sa.asserted_dt == DTN_EPOCH + dt.timedelta(milliseconds=ms)

    # Set current time (auto)
    sa.set_asserted_time()
    assert sa.asserted_time is not None
    assert sa.asserted_time > ms


def test_creation_time_structure_raises_on_short_list() -> None:
    """Verify that CreationTime._structure() raises ValueError on lists
    shorter than 2.
    """
    # CreationTime requires [timestamp_ms, sequence]
    truncated_data = [12345]
    with pytest.raises(
        ValueError, match="CreationTime requires timestamp and sequence"
    ):
        CreationTime._structure(truncated_data)


def test_base_status_report_structure_raises_on_short_list() -> None:
    """Verify that BaseStatusReport._structure() raises ValueError on lists
    shorter than 4.
    """
    # BaseStatusReport requires: [status_info, reason_code,
    # status_src_eid, status_creation_time]
    truncated_data = [[], 0, [1, "eid"]]
    with pytest.raises(
        ValueError, match="BaseStatusReport requires at least 4 elements"
    ):
        BaseStatusReport._structure(truncated_data)


@pytest.mark.parametrize(
    ("cls", "attr"),
    [(BaseStatusReport, "status_src_eid"), (CRBundleSequence, "block_src_admin_eid")],
)
def test_eid_setter_does_not_alias_the_callers_list(cls: type, attr: str) -> None:
    """A list given to an EID setter is copied, so later edits do not leak in."""
    obj = cls()
    eid: list[Any] = [2, [0, 3, 1]]
    setattr(obj, attr, eid)
    assert getattr(obj, attr) == "ipn:3.1"

    eid[1][1] = 99  # mutate the nested list the caller still holds
    eid.append("extra")
    assert getattr(obj, attr) == "ipn:3.1"


@pytest.mark.parametrize(
    ("cls", "attr"),
    [(BaseStatusReport, "status_src_eid"), (CRBundleSequence, "block_src_admin_eid")],
)
def test_eid_constructor_does_not_alias_the_callers_list(cls: type, attr: str) -> None:
    """A list passed to the constructor is copied as well."""
    eid: list[Any] = [2, [0, 3, 1]]
    obj = cls(**{attr: eid})
    eid[1][1] = 99
    assert getattr(obj, attr) == "ipn:3.1"


@pytest.mark.parametrize(
    ("uri", "cbor"),
    [
        ("ipn:10.1", [2, [10, 1]]),
        ("ipn:977000.100.1", [2, [977000, 100, 1]]),
        ("dtn:none", [1, 0]),
        ("dtn://node/app", [1, "//node/app"]),
    ],
)
def test_endpoint_id_round_trip(uri: str, cbor: list[Any]) -> None:
    """EndpointID converts between URI, CBOR list and itself without loss."""
    eid = EndpointID.from_value(uri)
    assert eid.to_cbor() == cbor
    assert EndpointID.from_value(cbor) == eid
    assert EndpointID.from_value(eid) is eid
    assert str(eid) == uri


def test_ct_bundle_sequence_dest_seq_is_an_endpoint_id() -> None:
    """dest_seq is converted to an EndpointID on init and on assignment."""
    seq = CTBundleSequence(dest_seq="ipn:10.1", first_seq_num=5, seq_range=2)
    assert isinstance(seq.dest_seq, EndpointID)
    assert str(seq.dest_seq) == "ipn:10.1"
    seq.dest_seq = [2, [(0 << 32) | 20, 3]]  # decoded 2-element CBOR form
    assert str(seq.dest_seq) == "ipn:20.3"
