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

import cbor2
from hypothesis import strategies as st

from bespokebpv7 import LTPSegmentType
from bespokebpv7.block_enum import (
    AdminReasonCode,
    BCBAESVariant,
    BIBSHAVariant,
    BlockType,
)
from bespokebpv7.bpv7 import BPv7
from bespokebpv7.bundle_params import (
    BaseStatusReport,
    BundleFragmentation,
    BundleStatusInformation,
    CRBundleSequence,
    CreationTime,
    CTBundleSequence,
    StatusAssertion,
)
from bespokebpv7.tcpcl import TCPCL
from bespokebpv7.tcpcl_enum import (
    TCPCLv3MessageType,
    TCPCLv4MessageType,
    TCPCLVersion,
)
from bespokebpv7.tcpcl_messages import (
    TCPCLv3Contact,
    TCPCLv3DataAck,
    TCPCLv3DataSegment,
    TCPCLv3Keepalive,
    TCPCLv3Shutdown,
    TCPCLv4Keepalive,
    TCPCLv4SessInit,
    TCPCLv4SessTerm,
    TCPCLv4XferAck,
    TCPCLv4XferSegment,
)

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

st_data_segment_types = st.sampled_from(
    [
        LTPSegmentType.DATA_RED,
        LTPSegmentType.DATA_GREEN,
        LTPSegmentType.DATA_RED_CP,
        LTPSegmentType.DATA_RED_CP_EORP,
        LTPSegmentType.DATA_RED_CP_EORP_EOB,
        LTPSegmentType.DATA_GREEN_EOB,
    ]
)

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

# ==========================================
# TCPCL Strategies
# ==========================================

st_tcpcl_version = st.sampled_from(TCPCLVersion)
st_tcpclv3_msg_type = st.sampled_from(TCPCLv3MessageType)
st_tcpclv4_msg_type = st.sampled_from(TCPCLv4MessageType)


def st_tcpclv3_contact() -> st.SearchStrategy[TCPCLv3Contact]:
    """Generate TCPCL v3 Contact messages with bounded random payloads.

    Returns:
        Strategy of TCPCLv3 Contacts

    """
    return st.builds(
        TCPCLv3Contact,
        payload=st.binary(max_size=256),
    )


def st_tcpclv3_keepalive() -> st.SearchStrategy[TCPCLv3Keepalive]:
    """Generate TCPCL v3 Keepalive messages with bounded random payloads.

    Returns:
        Strategy of TCPCLv3 Keep Alive packets

    """
    return st.builds(
        TCPCLv3Keepalive,
        payload=st.binary(max_size=256),
    )


def st_tcpclv3_shutdown() -> st.SearchStrategy[TCPCLv3Shutdown]:
    """Generate TCPCL v3 Shutdown messages with bounded random payloads.

    Returns:
        Strategy of TCPCLv3 Shutdown packets

    """
    return st.builds(
        TCPCLv3Shutdown,
        payload=st.binary(max_size=256),
    )


def st_tcpclv3_data_segment() -> st.SearchStrategy[TCPCLv3DataSegment]:
    """Generate TCPCL v3 Data Segment messages honoring flag and seq constraints.

    Returns:
        Strategy of TCPCLv3 Data Segments

    """
    return st.builds(
        TCPCLv3DataSegment,
        s_flag=st.booleans(),
        e_flag=st.booleans(),
        sequence_number=st.integers(min_value=0, max_value=2**32 - 1),
        payload=st.binary(max_size=512),
    )


def st_tcpclv3_data_ack() -> st.SearchStrategy[TCPCLv3DataAck]:
    """Generate TCPCL v3 Data Ack messages with valid sequence numbers.

    Returns:
        Strategy of TCPCLv3 Acks

    """
    return st.builds(
        TCPCLv3DataAck,
        sequence_number=st.integers(min_value=0, max_value=2**32 - 1),
    )


def st_tcpclv4_sess_init() -> st.SearchStrategy[TCPCLv4SessInit]:
    """Generate TCPCL v4 Session Init messages with bounded random payloads.

    Returns:
        Strategy of TCPCLv4 Init messages

    """
    return st.builds(
        TCPCLv4SessInit,
        payload=st.binary(max_size=256),
    )


def st_tcpclv4_keepalive() -> st.SearchStrategy[TCPCLv4Keepalive]:
    """Generate TCPCL v4 Keepalive messages with bounded random payloads.

    Returns:
        Strategy of TCPCLv4 Keep Alives

    """
    return st.builds(
        TCPCLv4Keepalive,
        payload=st.binary(max_size=256),
    )


def st_tcpclv4_sess_term() -> st.SearchStrategy[TCPCLv4SessTerm]:
    """Generate TCPCL v4 Session Termination messages with bounded random payloads.

    Returns:
        Strategy of TCPCLv4 Termination messages

    """
    return st.builds(
        TCPCLv4SessTerm,
        payload=st.binary(max_size=256),
    )


def st_tcpclv4_xfer_segment() -> st.SearchStrategy[TCPCLv4XferSegment]:
    """Generate TCPCL v4 Transfer Segment messages honoring flag and seq constraints.

    Returns:
        Strategy of TCPCLv4 Transfer Segments

    """
    return st.builds(
        TCPCLv4XferSegment,
        s_flag=st.booleans(),
        e_flag=st.booleans(),
        sequence_number=st.integers(min_value=0, max_value=2**32 - 1),
        payload=st.binary(max_size=512),
    )


def st_tcpclv4_xfer_ack() -> st.SearchStrategy[TCPCLv4XferAck]:
    """Generate TCPCL v4 Transfer Ack messages with valid sequence numbers.

    Returns:
        Strategy of TCPCLv4 Acks

    """
    return st.builds(
        TCPCLv4XferAck,
        sequence_number=st.integers(min_value=0, max_value=2**32 - 1),
    )


# Registry mapping (version, message_type) -> strategy for building the message.
_V3_MSG_STRATEGIES = {
    TCPCLv3MessageType.CONTACT: st_tcpclv3_contact,
    TCPCLv3MessageType.KEEPALIVE: st_tcpclv3_keepalive,
    TCPCLv3MessageType.SHUTDOWN: st_tcpclv3_shutdown,
    TCPCLv3MessageType.DATA_SEGMENT: st_tcpclv3_data_segment,
    TCPCLv3MessageType.DATA_ACK: st_tcpclv3_data_ack,
}
_V4_MSG_STRATEGIES = {
    TCPCLv4MessageType.SESS_INIT: st_tcpclv4_sess_init,
    TCPCLv4MessageType.KEEPALIVE: st_tcpclv4_keepalive,
    TCPCLv4MessageType.SESS_TERM: st_tcpclv4_sess_term,
    TCPCLv4MessageType.XFER_SEGMENT: st_tcpclv4_xfer_segment,
    TCPCLv4MessageType.XFER_ACK: st_tcpclv4_xfer_ack,
}


def st_bpv7_bundle() -> st.SearchStrategy[bytes]:
    """Build a valid CBOR-encoded BPv7 bundle as raw bytes.

    Mirrors the construction pattern in test_bpv7.py::test_bpv7_pack_unpack_roundtrip:
    sets source/dest EIDs via st_eid, calls set_creation(1000, 0), adds a payload
    block from st_data, and optionally adds a BundleAge canonical block.

    Returns:
        BPv7 Bundles as bye strings

    """
    return st.builds(
        _build_bpv7_bundle_bytes,
        src=st_eid,
        dst=st_eid,
        payload=st_data,
        age=st.integers(min_value=0, max_value=2**32 - 1),
        include_age=st.booleans(),
    )


def _build_bpv7_bundle_bytes(
    src: str,
    dst: str,
    payload: bytes,
    age: int,
    *,
    include_age: bool,
) -> bytes:
    """Construct a valid BPv7 bundle and serialize it to bytes.

    Returns:
        Bundle as byte string

    """
    bundle = BPv7()
    bundle.primary_block.route.source_eid = src
    bundle.primary_block.route.dest_eid = dst
    bundle.primary_block.set_creation(1000, 0)
    bundle.add_payload_block(payload)
    if include_age:
        bundle.add_canonical_block(
            {"block_type": BlockType.BUNDLE_AGE},
            cbor2.dumps(age),
        )
    return bytes(bundle)


@st.composite
def st_tcpcl_packet(draw: st.DrawFn) -> TCPCL:  # type: ignore[empty-body]
    """Build a TCPCL packet with a random valid message.

    Draws a version, picks a valid message_type for that version, and
    constructs the inner message via the matching strategy.  The resulting
    TCPCL object round-trips through bytes() / unpack().

    Returns:
        Constructed TCPCL packet

    """
    version = draw(st_tcpcl_version)
    if version == TCPCLVersion.V3:
        msg_type = draw(st_tcpclv3_msg_type)
        msg = draw(_V3_MSG_STRATEGIES[msg_type]())
    else:
        msg_type = draw(st_tcpclv4_msg_type)
        msg = draw(_V4_MSG_STRATEGIES[msg_type]())

    pkt = TCPCL()
    pkt.version = version
    pkt.message_type = msg_type
    pkt.message = msg
    return pkt
