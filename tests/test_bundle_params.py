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
 Modified: 01/27/2026
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

import datetime

from hypothesis import given
from strategies import st_eid

from bespokebpv7.bundle_params import ( 
    BundleLife,
    BundleRoute,
    StatusAssertion,
)
from bespokebpv7 import DTN_EPOCH


# ==========================================
# Tests for bespokebpv7/bundle_params.py
# ==========================================
@given(st_eid, st_eid)
def test_bundle_route(src: str, dst: str) -> None:
    """Verify values are stored correctly in BundleRoute class."""
    expected_src = src
    expected_dest = dst
    if src == "dtn:0":
        expected_src = "dtn:none"

    if dst == "dtn:0":
        expected_dest = "dtn:none"

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
    expected_dt = DTN_EPOCH + datetime.timedelta(milliseconds=1000)
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
    assert sa.asserted_dt == DTN_EPOCH + datetime.timedelta(milliseconds=ms)

    # Set current time (auto)
    sa.set_asserted_time()
    assert sa.asserted_time is not None
    assert sa.asserted_time > ms
