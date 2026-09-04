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
 Title: Hypothesis custom strategies
 Author: Nate Richard
 Modified: 03/31/2026
 Company: JPL
 Date:   01/27/2026

 File: strategies
 Description:
           Shared Hypothesis strategies for BespokeBPv7 tests
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

from hypothesis import strategies as st

from bespokebpv7.block_enum import (  # type: ignore[import-untyped]
    AdminReasonCode,
    BCBAESVariant,
    BIBSHAVariant,
)
from bespokebpv7.bundle_params import (  # type: ignore[import-untyped]
    BaseStatusReport,
    BundleFragmentation,
    BundleStatusInformation,
    CRBundleSequence,
    CreationTime,
    CTBundleSequence,
    StatusAssertion,
)
from bespokebpv7.segment_enum import LTPSegmentType  # type: ignore[import-untyped]

st_ipn_eid = st.builds(
    lambda n, s: f"ipn:{n}.{s}",
    st.integers(min_value=1, max_value=2**32 - 1),
    st.integers(min_value=0, max_value=2**32 - 1),
)
st_dtn_eid = st.from_regex(r"^dtn:[a-zA-Z0-9]+$", fullmatch=True)
st_eid = st.one_of(st_ipn_eid, st_dtn_eid)

st_data = st.binary(max_size=1024)

st_creb_params = st.tuples(
    st.integers(min_value=0),  # seq_num
    st.integers(min_value=0),  # seq_id
    st.integers(min_value=0, max_value=63),  # int_flag
    st_eid,  # admin_eid
    st_eid,  # report_eid
    st.integers(min_value=1, max_value=5),  # array_len
)


def ct_sequence_strategy() -> st.SearchStrategy:
    """Generate CTBundleSequence objects.

    Returns:
        Custom Hypothesis SearchStrategy for CTBundleSequence

    """
    return st.builds(
        CTBundleSequence,
        dest_seq=st.integers(min_value=0),
        first_seq_num=st.integers(min_value=0),
        seq_range=st.one_of(
            st.integers(min_value=0), st.lists(st.integers(min_value=0), min_size=1)
        ),
    )


def cr_sequence_strategy() -> st.SearchStrategy:
    """Generate CRBundleSequence objects.

    Returns:
        Custom Hypothesis SearchStrategy for CRBundleSequence

    """
    return st.builds(
        CRBundleSequence,
        dest_seq=st.integers(min_value=0),
        first_seq_num=st.integers(min_value=0),
        seq_range=st.one_of(
            st.integers(min_value=0), st.lists(st.integers(min_value=0), min_size=1)
        ),
        block_src_admin_eid=st.one_of(st.none(), st_eid),
    )


def creation_time_strategy() -> st.SearchStrategy:
    """Generate CreationTime objects.

    Returns:
        Custom Hypothesis SearchStrategy for CreationTime

    """
    return st.builds(
        CreationTime,
        timestamp_ms=st.integers(min_value=0),
        sequence=st.integers(min_value=0),
    )


def status_assertion_strategy() -> st.SearchStrategy:
    """Generate StatusAssertion objects.

    Returns:
        Custom Hypothesis SearchStrategy for StatusAssertion

    """
    return st.builds(
        StatusAssertion,
        status_indicator=st.booleans(),
        asserted_time=st.one_of(st.none(), st.integers(min_value=0)),
    )


def bundle_status_info_strategy() -> st.SearchStrategy:
    """Generate BundleStatusInformation objects.

    Returns:
        Custom Hypothesis SearchStrategy for BundleStatusInformation

    """
    return st.builds(
        BundleStatusInformation,
        recv_bundle=status_assertion_strategy(),
        fwd_bundle=status_assertion_strategy(),
        deliv_bundle=status_assertion_strategy(),
        del_bundle=status_assertion_strategy(),
    )


def base_status_report_strategy() -> st.SearchStrategy:
    """Generate BaseStatusReport objects.

    Returns:
        Custom Hypothesis SearchStrategy for BaseStatusReport

    """
    return st.builds(
        BaseStatusReport,
        status_info=bundle_status_info_strategy(),
        reason_code=st.sampled_from(AdminReasonCode),
        status_src_eid=st_eid,
        status_creation_time=creation_time_strategy(),
    )


def fragmentation_strategy() -> st.SearchStrategy:
    """Generate BundleFragmentation objects.

    Returns:
        Custom Hypothesis SearchStrategy for BundleFragmentation

    """
    return st.builds(
        BundleFragmentation,
        fragment_offset=st.integers(min_value=0),
        total_adu_len=st.integers(min_value=0),
    )


st_crypto_key = st.one_of(
    st.binary(min_size=16, max_size=16),  # AES-128
    st.binary(min_size=32, max_size=32),  # AES-256
    st.binary(min_size=64, max_size=64),  # Extended keys
)

st_auth_tag = st.one_of(
    st.binary(min_size=16, max_size=16),  # 128-bit tags
    st.binary(min_size=32, max_size=32),  # 256-bit tags
    st.binary(min_size=64, max_size=64),  # 512-bit tags
)

st_bcb_aes_variant = st.sampled_from(BCBAESVariant)
st_bib_sha_variant = st.sampled_from(BIBSHAVariant)

st_aad_scope_flags = st.integers(min_value=0, max_value=7)
st_integrity_scope_flags = st.integers(min_value=0, max_value=7)

st_security_targets = st.lists(
    st.integers(min_value=1, max_value=10),
    min_size=1,
    max_size=5,
)

st_data_segment_types = st.sampled_from([
    LTPSegmentType.DATA_RED,
    LTPSegmentType.DATA_GREEN,
    LTPSegmentType.DATA_RED_CP,
    LTPSegmentType.DATA_RED_CP_EORP,
    LTPSegmentType.DATA_RED_CP_EORP_EOB,
    LTPSegmentType.DATA_GREEN_EOB,
])

# Reception claims as a report segment carries them: each is an offset into
# the report's scope paired with a length, and a report always makes at
# least one.
st_reception_claims = st.lists(
    st.tuples(
        st.integers(min_value=0, max_value=2**16),
        st.integers(min_value=1, max_value=2**16),
    ),
    min_size=1,
    max_size=8,
)
