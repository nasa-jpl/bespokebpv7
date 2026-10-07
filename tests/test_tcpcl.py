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
 Title: TCP Convergence Layer Tests
 Author: Nate Richard
 Modified: 09/22/2026
 Company: JPL
 Date:   09/22/2026

 File: test_tcpcl.py
 Description:
          Property-based tests for TCPCL v3/v4 parsing and serialization
          using Hypothesis.  Strategies are shared via tests/strategies.py.

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

import struct
from typing import Any

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st
from strategies import (
    st_bpv7_bundle,
    st_tcpcl_packet,
    st_tcpclv3_data_segment,
    st_tcpclv4_xfer_ack,
    st_tcpclv4_xfer_segment,
)

from bespokebpv7 import (
    TCPCL,
    BPv7,
    TCPCLStreamParser,
    TCPCLv3Contact,
    TCPCLv3DataAck,
    TCPCLv3DataSegment,
    TCPCLv3MessageType,
    TCPCLVersion,
)
from bespokebpv7 import tcpcl as tcpcl_module
from bespokebpv7.tcpcl import MAGIC, MESSAGE_MAP
from bespokebpv7.tcpcl_enum import TCPCLv4MessageType
from bespokebpv7.tcpcl_messages import (
    TCPCLMessage,
    TCPCLv3Shutdown,
    TCPCLv4Keepalive,
    TCPCLv4SessTerm,
    TCPCLv4XferAck,
    TCPCLv4XferSegment,
)


def _segment_bpv7(packet: TCPCL) -> BPv7 | None:
    """Narrow packet.message to a segment type and return its .bpv7.

    Returns:
        The segment's extracted bpv7 attribute (None if unset).

    """
    assert isinstance(packet.message, (TCPCLv3DataSegment, TCPCLv4XferSegment))
    return packet.message.bpv7


def _build_simple_bpv7_bundle() -> BPv7:
    """Build a small, deterministic valid BPv7 bundle for reassembly tests.

    Returns:
        A fully-populated BPv7 bundle.

    """
    bundle = BPv7()
    bundle.primary_block.route.source_eid = "ipn:2.1"
    bundle.primary_block.route.dest_eid = "ipn:3.1"
    bundle.primary_block.set_creation(1000, 0)
    bundle.add_payload_block(b"reassembly-test-payload")
    return bundle


def _build_segment_packet_bytes(
    *,
    version: TCPCLVersion,
    s_flag: bool,
    e_flag: bool,
    sequence_number: int,
    payload: bytes,
) -> bytes:
    """Build raw wire bytes for a single v3 DataSegment / v4 XferSegment packet.

    v3 DATA_SEGMENT keeps its RFC 7242 layout (1-byte flags S=0x80/E=0x40 +
    4-byte sequence number). v4 XFER_SEGMENT uses the RFC 9174 Sec 5.2.2
    layout (1-byte flags S=0x02/E=0x01 + 8-byte Transfer ID + 8-byte Data
    length, with no Transfer Extension Items since these tests never need
    them); `sequence_number` is reused as the Transfer ID in that case.

    Returns:
        The serialized TCPCL packet bytes.

    """
    if version == TCPCLVersion.V3:
        msg_type: int = TCPCLv3MessageType.DATA_SEGMENT
        flags = (0x80 if s_flag else 0) | (0x40 if e_flag else 0)
        seg_payload = struct.pack(">B I", flags, sequence_number) + payload
    else:
        msg_type = TCPCLv4MessageType.XFER_SEGMENT
        flags = (0x02 if s_flag else 0) | (0x01 if e_flag else 0)
        seg_payload = struct.pack(">BQ", flags, sequence_number)
        if s_flag:
            # Transfer Extension Items Length (0, no items) -- only present
            # on START segments per RFC 9174 Sec 5.2.2.
            seg_payload += struct.pack(">I", 0)
        seg_payload += struct.pack(">Q", len(payload)) + payload
    length = 1 + len(seg_payload)
    return MAGIC + struct.pack(">B I B", version, length, msg_type) + seg_payload


SEQNUM = 0xFFFFFFFF
TCPMIN = 10
TCPV3SHORT = 5
THREE_SEGMENT_PACKETS = 3
TWO_SEGMENT_PACKETS = 2

# ==========================================
# Version detection
# ==========================================


@given(st_tcpcl_packet())
@settings(max_examples=50)
def test_version_detection_pbt(pkt: TCPCL) -> None:
    """Unpacking a generated packet yields the correct version."""
    serialized = bytes(pkt)
    result = TCPCL()
    result.unpack(serialized)
    assert result.version == pkt.version


# ==========================================
# Malformed input
# ==========================================


@given(st.binary(min_size=4, max_size=20).filter(lambda b: b[:4] != MAGIC))
def test_malformed_magic_pbt(data: bytes) -> None:
    """A bad magic string raises ValueError('Invalid TCPCL magic')."""
    padded = data + b"\x00" * max(0, 10 - len(data))
    pkt = TCPCL()
    with pytest.raises(ValueError, match="Invalid TCPCL magic string"):
        pkt.unpack(padded)


@given(st.binary(max_size=9))
def test_short_buffer_pbt(buf: bytes) -> None:
    """Buffers shorter than 10 bytes raise ValueError('Buffer too short')."""
    if len(buf) < TCPMIN:
        pkt = TCPCL()
        with pytest.raises(ValueError, match="Buffer too short"):
            pkt.unpack(buf)


# ==========================================
# Data segment flags round-trip
# ==========================================


@given(st_tcpclv3_data_segment())
@settings(max_examples=100)
def test_data_segment_flags_pbt(msg: TCPCLv3DataSegment) -> None:
    """Round-trip preserves s_flag, e_flag, sequence_number, and payload."""
    serialized = bytes(msg)
    result = TCPCLv3DataSegment()
    result.unpack(serialized)

    assert result.s_flag == msg.s_flag
    assert result.e_flag == msg.e_flag
    assert result.sequence_number == msg.sequence_number
    assert result.payload == msg.payload


# ==========================================
# RFC compliance for v3 data segments
# ==========================================


@given(
    s_flag=st.booleans(),
    e_flag=st.booleans(),
    seq=st.integers(min_value=0, max_value=2**32 - 1),
    payload=st.binary(max_size=512),
)
def test_rfc_compliance_v3_pbt(
    *,
    s_flag: bool,
    e_flag: bool,
    seq: int,
    payload: bytes,
) -> None:
    """bytes(msg) matches the expected RFC 7242 wire layout.

    Layout: 1-byte flags (S=0x80, E=0x40) + 4-byte big-endian sequence
    number + payload bytes.
    """
    msg = TCPCLv3DataSegment()
    msg.s_flag = s_flag
    msg.e_flag = e_flag
    msg.sequence_number = seq
    msg.payload = payload

    flags_byte = 0
    if s_flag:
        flags_byte |= 0x80
    if e_flag:
        flags_byte |= 0x40

    expected = struct.pack(">B I", flags_byte, seq) + payload
    assert bytes(msg) == expected


# ==========================================
# Serialization round-trip
# ==========================================


@given(st_tcpcl_packet())
@settings(max_examples=100)
def test_serialization_roundtrip_pbt(pkt: TCPCL) -> None:
    """bytes(pkt) round-trips through TCPCL().unpack() preserving all fields."""
    serialized = bytes(pkt)

    result = TCPCL()
    result.unpack(serialized)

    assert result.version == pkt.version
    assert result.message_type == pkt.message_type

    # Verify the inner message type matches
    assert pkt.version is not None
    assert pkt.message_type is not None
    expected_cls = MESSAGE_MAP.get((pkt.version, pkt.message_type))  # type: ignore[arg-type]
    assert expected_cls is not None
    assert isinstance(result.message, expected_cls)

    # Verify inner message serialization round-trips
    assert result.message is not None
    assert pkt.message is not None
    assert bytes(result.message) == bytes(pkt.message)


# ==========================================
# Invalid dispatch
# ==========================================


@given(
    version=st.sampled_from(TCPCLVersion),
    invalid_type=st.integers(min_value=6, max_value=255),
)
def test_invalid_dispatch_pbt(version: TCPCLVersion, invalid_type: int) -> None:
    """An unsupported message type raises ValueError."""
    # Use a simple contact message payload; the type field itself is invalid
    msg = TCPCLv3Contact()
    msg.payload = b""
    payload = bytes(msg)
    length = 1 + len(payload)
    buf = MAGIC + struct.pack(">B I B", version, length, invalid_type) + payload

    pkt = TCPCL()
    with pytest.raises(ValueError, match="Unsupported TCPCL version"):
        pkt.unpack(buf)


# ==========================================
# BPv7 extraction (positive)
# ==========================================


@given(st_bpv7_bundle())
def test_bpv7_extraction_v3_positive_pbt(bundle_bytes: bytes) -> None:
    """A valid BPv7 bundle embedded in a v3 DataSegment (S=1, E=1) is extracted."""
    seg = TCPCLv3DataSegment()
    seg.s_flag = True
    seg.e_flag = True
    seg.sequence_number = 1
    seg.payload = bundle_bytes

    serialized = bytes(seg)
    result = TCPCLv3DataSegment()
    result.unpack(serialized)

    assert result.bpv7 is not None
    assert bytes(result.bpv7) == bundle_bytes


@given(st_bpv7_bundle())
def test_bpv7_extraction_v3_non_bundle_payload_pbt(bundle_bytes: bytes) -> None:
    """When S=1/E=0 (not single-segment), bpv7 stays None even with valid
    bundle bytes.
    """
    seg = TCPCLv3DataSegment()
    seg.s_flag = True
    seg.e_flag = False
    seg.sequence_number = 0
    seg.payload = bundle_bytes

    serialized = bytes(seg)
    result = TCPCLv3DataSegment()
    result.unpack(serialized)

    assert result.bpv7 is None
    assert result.payload == bundle_bytes


# ==========================================
# Stream parser
# ==========================================


@given(st.lists(st_tcpcl_packet(), max_size=5))
@settings(max_examples=20)
def test_stream_parser_fragmented_pbt(packets: list[Any]) -> None:
    """The stream parser recovers packets from a fragmented byte stream.

    Concatenates bytes(p) for all packets, then feeds the concatenation
    to TCPCLStreamParser in 1-byte chunks.  All packets are recovered in order.
    """
    raw = b"".join(bytes(p) for p in packets)
    parser = TCPCLStreamParser()

    recovered = []
    for i in range(len(raw)):
        recovered.extend(parser.feed(raw[i : i + 1]))
    recovered.extend(parser.feed(b""))

    assert len(recovered) == len(packets)
    for orig, rec in zip(packets, recovered, strict=True):
        assert rec.version == orig.version
        assert rec.message_type == orig.message_type
        assert rec.message is not None
        assert orig.message is not None
        assert bytes(rec.message) == bytes(orig.message)


@given(
    st.lists(st_tcpcl_packet(), max_size=5),
    st.lists(
        st.binary(max_size=5).filter(lambda b: MAGIC not in b),
        min_size=0,
        max_size=5,
    ),
)
@settings(max_examples=20)
def test_stream_parser_with_noise_pbt(
    packets: list[Any], noise_chunks: list[Any]
) -> None:
    """The stream parser recovers valid packets interleaved with random noise.

    Noise bytes are placed between packets (before, between, and after).
    Noise that doesn't form valid TCPCL packets is silently skipped via the
    except (ValueError, struct.error): continue path in feed().
    """
    padded_noise = noise_chunks + [b""] * (len(packets) + 1 - len(noise_chunks))
    stream_parts: list[bytes] = []
    for i, pkt in enumerate(packets):
        stream_parts.extend((padded_noise[i], bytes(pkt)))
    stream_parts.append(padded_noise[len(packets)])  # trailing noise

    raw = b"".join(stream_parts)

    parser = TCPCLStreamParser()
    recovered = []
    for i in range(len(raw)):
        recovered.extend(parser.feed(raw[i : i + 1]))
    recovered.extend(parser.feed(b""))

    assert len(recovered) == len(packets)
    for orig, rec in zip(packets, recovered, strict=True):
        assert rec.version == orig.version
        assert rec.message_type == orig.message_type


# ==========================================
# Preserved static edge cases
# ==========================================


def test_v3_contact_minimal_payload() -> None:
    """A v3 Contact packet with a minimal (empty) payload."""
    msg = TCPCLv3Contact()
    msg.payload = b""

    pkt = TCPCL()
    pkt.version = TCPCLVersion.V3
    pkt.message_type = TCPCLv3MessageType.CONTACT
    pkt.message = msg

    serialized = bytes(pkt)
    result = TCPCL()
    result.unpack(serialized)

    assert result.version == TCPCLVersion.V3
    assert result.message_type == TCPCLv3MessageType.CONTACT
    assert isinstance(result.message, TCPCLv3Contact)
    assert result.message.payload == b""


def test_v4_keepalive_zero_length() -> None:
    """A v4 Keepalive with an empty body."""
    msg = TCPCLv4Keepalive()
    msg.payload = b""

    pkt = TCPCL()
    pkt.version = TCPCLVersion.V4
    pkt.message_type = TCPCLv4MessageType.KEEPALIVE
    pkt.message = msg

    serialized = bytes(pkt)
    result = TCPCL()
    result.unpack(serialized)

    assert result.version == TCPCLVersion.V4
    assert isinstance(result.message, TCPCLv4Keepalive)
    assert result.message.payload == b""


def test_v3_data_ack_max_seq() -> None:
    """A TCPCLv3DataAck with sequence_number = 0xFFFFFFFF."""
    msg = TCPCLv3DataAck()
    msg.sequence_number = SEQNUM

    serialized = bytes(msg)
    result = TCPCLv3DataAck()
    result.unpack(serialized)

    assert result.sequence_number == SEQNUM


# ==========================================
# Coverage for edge cases and error paths
# ==========================================


@given(st_tcpcl_packet())
@settings(max_examples=50)
def test_tcpcl_str_repr_pbt(pkt: TCPCL) -> None:
    """__str__ and __repr__ produce non-empty output for populated packets.

    The packet must first be round-tripped through bytes/unpack so that
    inner message objects have __hdr_len__ set (required by dpkt.__bool__).
    """
    serialized = bytes(pkt)
    result = TCPCL()
    result.unpack(serialized)
    assert str(result)
    assert repr(result)


def test_tcpcl_str_empty_message() -> None:
    """__str__ handles a TCPCL with no message (empty packet case)."""
    pkt = TCPCL()
    assert "Empty" in str(pkt)


def test_tcpcl_bytes_version_not_set() -> None:
    """__bytes__ raises AttributeError when version is not set.

    Uses _UnknownMessage which has no class-level version attribute,
    so getattr falls through to self.version (None).
    """
    msg = _UnknownMessage()

    pkt = TCPCL()
    pkt.message = msg
    pkt.version = None  # type: ignore[assignment]

    with pytest.raises(AttributeError, match="TCPCL version not set"):
        bytes(pkt)


class _UnknownMessage(TCPCLMessage):
    """An unknown message type that is not in MESSAGE_MAP."""

    def __bytes__(self) -> bytes:
        return b""

    def unpack(self, buf: bytes) -> None:
        pass


def test_tcpcl_bytes_unknown_message_type() -> None:
    """__bytes__ raises AttributeError for a message not in MESSAGE_MAP."""
    pkt = TCPCL()
    pkt.version = TCPCLVersion.V3
    pkt.message_type = TCPCLv3MessageType.CONTACT
    pkt.message = _UnknownMessage()

    with pytest.raises(AttributeError, match="Could not determine TCPCL message type"):
        bytes(pkt)


@given(st.binary(min_size=10, max_size=20))
def test_tcpcl_payload_length_mismatch_pbt(data: bytes) -> None:
    """A length field larger than the actual payload raises ValueError."""
    # Build a valid MAGIC + version + type, but set length to a huge value
    # that exceeds the actual payload.
    payload = data[:10]
    fake_length = 9999
    buf = (
        MAGIC
        + struct.pack(
            ">B I B", TCPCLVersion.V3, fake_length, TCPCLv3MessageType.CONTACT
        )
        + payload
    )
    pkt = TCPCL()
    with pytest.raises(ValueError, match="Buffer too short for TCPCL payload"):
        pkt.unpack(buf)


@given(st.binary(max_size=4))
def test_tcpcl_v3_data_segment_short_header_pbt(buf: bytes) -> None:
    """TCPCLv3DataSegment.unpack raises ValueError for buffers < 5 bytes."""
    if len(buf) < TCPV3SHORT:
        msg = TCPCLv3DataSegment()
        with pytest.raises(ValueError, match="Buffer too short for TCPCLv3DataSegment"):
            msg.unpack(buf)


@given(st.binary(max_size=3))
def test_tcpcl_v3_data_ack_short_buffer_pbt(buf: bytes) -> None:
    """TCPCLv3DataAck.unpack raises ValueError for buffers < 4 bytes."""
    msg = TCPCLv3DataAck()
    with pytest.raises(ValueError, match="Buffer too short for TCPCLv3DataAck"):
        msg.unpack(buf)


@given(st.binary(max_size=8))
def test_tcpcl_v4_xfer_segment_short_header_pbt(buf: bytes) -> None:
    """TCPCLv4XferSegment.unpack raises ValueError for buffers < 9 bytes.

    9 bytes is the RFC 9174 Sec 5.2.2 flags(1) + Transfer ID(8) prefix.
    """
    msg = TCPCLv4XferSegment()
    with pytest.raises(ValueError, match="Buffer too short for TCPCLv4XferSegment"):
        msg.unpack(buf)


@given(st.binary(max_size=16))
def test_tcpcl_v4_xfer_ack_short_buffer_pbt(buf: bytes) -> None:
    """TCPCLv4XferAck.unpack raises ValueError for buffers < 17 bytes.

    17 bytes is the RFC 9174 Sec 5.2.3 flags(1) + Transfer ID(8) +
    Acknowledged length(8).
    """
    msg = TCPCLv4XferAck()
    with pytest.raises(ValueError, match="Buffer too short for TCPCLv4XferAck"):
        msg.unpack(buf)


def test_v4_xfer_segment_rfc9174_wire_format() -> None:
    """A hand-built RFC 9174 Figure 22 buffer unpacks into expected fields.

    Direct regression test for the non-compliant 5-byte header previously
    used by TCPCLv4XferSegment (issue #61): flags=0x03 (S=1,E=1), 8-byte
    Transfer ID, 4-byte ext-items-length=0, 8-byte data length, data.
    """
    transfer_id = 0x0123456789ABCDEF
    # Not valid CBOR-encoded bundle data (decodes to a bare int, not a
    # list), so BPv7 auto-extraction raises and is suppressed -- this test
    # only cares about the TCPCLv4XferSegment framing fields.
    data = b"\x00" * 14
    buf = (
        struct.pack(">B", 0x03)
        + struct.pack(">Q", transfer_id)
        + struct.pack(">I", 0)
        + struct.pack(">Q", len(data))
        + data
    )

    result = TCPCLv4XferSegment()
    result.unpack(buf)

    assert result.s_flag is True
    assert result.e_flag is True
    assert result.transfer_id == transfer_id
    assert result.transfer_extension_items == b""
    assert result.payload == data


@given(st.binary(max_size=32), st.integers(min_value=1, max_value=16))
def test_v4_xfer_segment_rejects_truncated_data_length(data: bytes, extra: int) -> None:
    """Unpack rejects a declared Data length longer than the remaining buffer."""
    buf = (
        struct.pack(">B", 0x01)
        + struct.pack(">Q", 1)
        + struct.pack(">Q", len(data) + extra)
        + data
    )
    msg = TCPCLv4XferSegment()
    with pytest.raises(
        ValueError,
        match="TCPCLv4XferSegment declared Data length does not match",
    ):
        msg.unpack(buf)


@given(st.binary(min_size=1, max_size=32), st.integers(min_value=1, max_value=16))
def test_v4_xfer_segment_rejects_undersized_declared_length(
    data: bytes, shrink: int
) -> None:
    """Unpack rejects a declared Data length shorter than the remaining buffer.

    This proves trailing bytes are not silently dropped on a short declared
    length -- malformed/non-compliant input must surface as an error rather
    than being masked, consistent with this library's testing philosophy.
    """
    declared = max(len(data) - shrink, 0)
    buf = (
        struct.pack(">B", 0x01)
        + struct.pack(">Q", 1)
        + struct.pack(">Q", declared)
        + data
    )
    msg = TCPCLv4XferSegment()
    with pytest.raises(
        ValueError,
        match="TCPCLv4XferSegment declared Data length does not match",
    ):
        msg.unpack(buf)


def test_v4_xfer_segment_override_lengths_are_rejected_on_unpack() -> None:
    """data_length_override/ext_items_length_override build V&V-malformed segments.

    Setting either override produces a buffer whose declared length lies
    about the actual data; feeding that buffer back into unpack() must
    raise ValueError, demonstrating the library can still construct and
    correctly reject non-compliant v4 transfer segments.
    """
    seg = TCPCLv4XferSegment()
    seg.s_flag = True
    seg.e_flag = True
    seg.transfer_id = 42
    seg.payload = b"abc"
    seg.data_length_override = len(seg.payload) + 5

    malformed = bytes(seg)
    result = TCPCLv4XferSegment()
    with pytest.raises(
        ValueError,
        match="TCPCLv4XferSegment declared Data length does not match",
    ):
        result.unpack(malformed)

    seg2 = TCPCLv4XferSegment()
    seg2.s_flag = True
    seg2.e_flag = True
    seg2.transfer_id = 42
    seg2.transfer_extension_items = b"xx"
    seg2.payload = b"abc"
    seg2.ext_items_length_override = len(seg2.transfer_extension_items) + 5

    malformed2 = bytes(seg2)
    result2 = TCPCLv4XferSegment()
    with pytest.raises(
        ValueError,
        match="Buffer too short for TCPCLv4XferSegment header",
    ):
        result2.unpack(malformed2)


def test_tcpcl_v3_update_length_noop() -> None:
    """TCPCLMessage.update_length is a no-op in the base class."""
    msg = TCPCLMessage()
    msg.update_length()  # base class no-op, should not raise


@given(st_bpv7_bundle())
def test_bpv7_extraction_v4_positive_pbt(bundle_bytes: bytes) -> None:
    """A valid BPv7 bundle embedded in a v4 XferSegment (S=1, E=1) is extracted."""
    seg = TCPCLv4XferSegment()
    seg.s_flag = True
    seg.e_flag = True
    seg.transfer_id = 1
    seg.payload = bundle_bytes

    serialized = bytes(seg)
    result = TCPCLv4XferSegment()
    result.unpack(serialized)

    assert result.bpv7 is not None
    assert bytes(result.bpv7) == bundle_bytes


@given(st_tcpclv3_data_segment())
def test_data_segment_bpv7_serialization_pbt(msg: TCPCLv3DataSegment) -> None:
    """__bytes__ of a v3 DataSegment with bpv7 set uses bytes(bpv7) for data."""
    # Only test single-segment case (S=1, E=1) where bpv7 extraction triggers
    msg.s_flag = True
    msg.e_flag = True

    serialized = bytes(msg)
    result = TCPCLv3DataSegment()
    result.unpack(serialized)

    # The payload should round-trip, and if it was a valid bundle, bpv7 is set
    assert result.payload == msg.payload


@given(st_tcpclv4_xfer_segment())
def test_v4_xfer_segment_bpv7_serialization_pbt(msg: TCPCLv4XferSegment) -> None:
    """__bytes__ of a v4 XferSegment with bpv7 set uses bytes(bpv7) for data."""
    serialized = bytes(msg)
    result = TCPCLv4XferSegment()
    result.unpack(serialized)

    assert result.payload == msg.payload
    assert result.s_flag == msg.s_flag
    assert result.e_flag == msg.e_flag
    assert result.transfer_id == msg.transfer_id
    if msg.s_flag:
        assert result.transfer_extension_items == msg.transfer_extension_items


@given(
    st.lists(st_tcpcl_packet(), min_size=1, max_size=5),
    st.binary(max_size=20),
)
@settings(max_examples=20)
def test_stream_parser_noise_before_packets_pbt(
    packets: list[Any], noise: bytes
) -> None:
    """Noise before the first packet is skipped (start_idx > 0 path)."""
    # Prepend noise that doesn't contain MAGIC to force the start_idx > 0 path
    no_magic_noise = noise.replace(MAGIC, b"")
    raw = no_magic_noise + b"".join(bytes(p) for p in packets)

    parser = TCPCLStreamParser()
    recovered = []
    for i in range(len(raw)):
        recovered.extend(parser.feed(raw[i : i + 1]))
    recovered.extend(parser.feed(b""))

    assert len(recovered) == len(packets)
    for orig, rec in zip(packets, recovered, strict=True):
        assert rec.version == orig.version
        assert rec.message_type == orig.message_type


def test_stream_parser_invalid_packet_skipped() -> None:
    """A buffer that parses as a valid MAGIC+header but invalid message is skipped."""
    # Build a valid header with an invalid version byte (6) that causes
    # MESSAGE_MAP lookup to fail during unpack.
    bad_version = 6
    msg = TCPCLv3Contact()
    msg.payload = b""
    payload = bytes(msg)
    length = 1 + len(payload)
    buf = (
        MAGIC
        + struct.pack(">B I B", bad_version, length, TCPCLv3MessageType.CONTACT)
        + payload
    )

    parser = TCPCLStreamParser()
    recovered = parser.feed(buf)
    assert len(recovered) == 0


@given(st_tcpclv4_xfer_ack())
def test_v4_xfer_ack_roundtrip(msg: TCPCLv4XferAck) -> None:
    """A v4 XferAck round-trips s_flag, e_flag, transfer_id, acknowledged_length."""
    serialized = bytes(msg)
    result = TCPCLv4XferAck()
    result.unpack(serialized)

    assert result.s_flag == msg.s_flag
    assert result.e_flag == msg.e_flag
    assert result.transfer_id == msg.transfer_id
    assert result.acknowledged_length == msg.acknowledged_length


@given(st_bpv7_bundle())
def test_data_segment_v3_bpv7_serialization_path_pbt(bundle_bytes: bytes) -> None:
    """Calling bytes() on a v3 DataSegment with .bpv7 set uses bytes(bpv7).

    Exercises the __bytes__ path that serializes .bpv7 via bytes(self.bpv7).
    """
    seg = TCPCLv3DataSegment()
    seg.s_flag = True
    seg.e_flag = True
    seg.sequence_number = 1
    seg.payload = bundle_bytes

    # Unpack to set .bpv7
    seg.unpack(bytes(seg))
    assert seg.bpv7 is not None

    # Now __bytes__ should use bytes(self.bpv7) since bpv7 is truthy
    flags_byte = 0x80 | 0x40
    expected = struct.pack(">B I", flags_byte, 1) + bundle_bytes
    assert bytes(seg) == expected


@given(st_bpv7_bundle())
def test_xfer_segment_v4_bpv7_serialization_path_pbt(bundle_bytes: bytes) -> None:
    """Calling bytes() on a v4 XferSegment with .bpv7 set uses bytes(bpv7).

    Exercises the __bytes__ path that serializes .bpv7 via bytes(self.bpv7).
    """
    seg = TCPCLv4XferSegment()
    seg.s_flag = True
    seg.e_flag = True
    seg.transfer_id = 1
    seg.payload = bundle_bytes

    # Unpack to set .bpv7
    seg.unpack(bytes(seg))
    assert seg.bpv7 is not None

    # Now __bytes__ should use bytes(self.bpv7) since bpv7 is truthy
    # RFC 9174 Table 5: START = 0x02, END = 0x01.
    flags_byte = 0x02 | 0x01
    expected = (
        struct.pack(">BQ", flags_byte, 1)
        + struct.pack(">I", 0)
        + struct.pack(">Q", len(bundle_bytes))
        + bundle_bytes
    )
    assert bytes(seg) == expected


# ==========================================
# Direct coverage of remaining edge-case lines
# ==========================================


def test_tcpcl_bytes_no_message() -> None:
    """__bytes__ returns empty bytes when no message is set."""
    pkt = TCPCL()
    assert bytes(pkt) == b""


def test_stream_parser_noise_before_magic_starts_packet() -> None:
    """Noise before a valid packet forces start_idx > 0, triggering the
    del self.buffer[:start_idx] path in the stream parser.
    """
    msg = TCPCLv3Contact()
    msg.payload = b"hello"
    pkt = TCPCL()
    pkt.version = TCPCLVersion.V3
    pkt.message_type = TCPCLv3MessageType.CONTACT
    pkt.message = msg

    stream = b"\x00\x00\x00" + bytes(pkt)

    parser = TCPCLStreamParser()
    recovered = parser.feed(stream)
    assert len(recovered) == 1
    assert recovered[0].version == TCPCLVersion.V3
    assert recovered[0].message_type == TCPCLv3MessageType.CONTACT


# ==========================================
# Multi-segment BPv7 reassembly (#37)
# ==========================================


@given(st_bpv7_bundle())
@settings(max_examples=20)
def test_stream_parser_reassembles_multi_segment_v3_bundle(
    bundle_bytes: bytes,
) -> None:
    """A bundle split across 3 v3 DATA_SEGMENT messages reassembles correctly."""
    third = max(1, len(bundle_bytes) // 3)
    chunks = [
        bundle_bytes[:third],
        bundle_bytes[third : 2 * third],
        bundle_bytes[2 * third :],
    ]

    raw = (
        _build_segment_packet_bytes(
            version=TCPCLVersion.V3,
            s_flag=True,
            e_flag=False,
            sequence_number=0,
            payload=chunks[0],
        )
        + _build_segment_packet_bytes(
            version=TCPCLVersion.V3,
            s_flag=False,
            e_flag=False,
            sequence_number=1,
            payload=chunks[1],
        )
        + _build_segment_packet_bytes(
            version=TCPCLVersion.V3,
            s_flag=False,
            e_flag=True,
            sequence_number=2,
            payload=chunks[2],
        )
    )

    parser = TCPCLStreamParser()
    packets = parser.feed(raw)
    assert len(packets) == THREE_SEGMENT_PACKETS
    assert _segment_bpv7(packets[0]) is None
    assert _segment_bpv7(packets[1]) is None
    final_bpv7 = _segment_bpv7(packets[2])
    assert final_bpv7 is not None
    assert bytes(final_bpv7) == bundle_bytes


@given(st_bpv7_bundle())
@settings(max_examples=20)
def test_stream_parser_reassembles_multi_segment_v4_bundle(
    bundle_bytes: bytes,
) -> None:
    """A bundle split across 3 v4 XFER_SEGMENT messages reassembles correctly."""
    third = max(1, len(bundle_bytes) // 3)
    chunks = [
        bundle_bytes[:third],
        bundle_bytes[third : 2 * third],
        bundle_bytes[2 * third :],
    ]

    raw = (
        _build_segment_packet_bytes(
            version=TCPCLVersion.V4,
            s_flag=True,
            e_flag=False,
            sequence_number=0,
            payload=chunks[0],
        )
        + _build_segment_packet_bytes(
            version=TCPCLVersion.V4,
            s_flag=False,
            e_flag=False,
            sequence_number=1,
            payload=chunks[1],
        )
        + _build_segment_packet_bytes(
            version=TCPCLVersion.V4,
            s_flag=False,
            e_flag=True,
            sequence_number=2,
            payload=chunks[2],
        )
    )

    parser = TCPCLStreamParser()
    packets = parser.feed(raw)
    assert len(packets) == THREE_SEGMENT_PACKETS
    assert _segment_bpv7(packets[0]) is None
    assert _segment_bpv7(packets[1]) is None
    final_bpv7 = _segment_bpv7(packets[2])
    assert final_bpv7 is not None
    assert bytes(final_bpv7) == bundle_bytes


def test_stream_parser_discards_orphan_middle_segment() -> None:
    """A middle segment with no transfer in progress is discarded."""
    raw = _build_segment_packet_bytes(
        version=TCPCLVersion.V3,
        s_flag=False,
        e_flag=False,
        sequence_number=0,
        payload=b"orphan",
    )
    parser = TCPCLStreamParser()
    packets = parser.feed(raw)
    assert len(packets) == 1
    assert _segment_bpv7(packets[0]) is None
    assert parser._transfer_buffer is None


def test_stream_parser_new_start_aborts_stale_transfer() -> None:
    """An S=1 segment mid-transfer discards the stale buffer and restarts."""
    parser = TCPCLStreamParser()

    start1 = _build_segment_packet_bytes(
        version=TCPCLVersion.V3,
        s_flag=True,
        e_flag=False,
        sequence_number=0,
        payload=b"stale-start",
    )
    parser.feed(start1)
    assert parser._transfer_buffer == bytearray(b"stale-start")

    bundle_bytes = bytes(_build_simple_bpv7_bundle())
    start2 = _build_segment_packet_bytes(
        version=TCPCLVersion.V3,
        s_flag=True,
        e_flag=False,
        sequence_number=1,
        payload=bundle_bytes[: len(bundle_bytes) // 2],
    )
    end2 = _build_segment_packet_bytes(
        version=TCPCLVersion.V3,
        s_flag=False,
        e_flag=True,
        sequence_number=2,
        payload=bundle_bytes[len(bundle_bytes) // 2 :],
    )
    packets = parser.feed(start2 + end2)
    assert len(packets) == TWO_SEGMENT_PACKETS
    final_bpv7 = _segment_bpv7(packets[1])
    assert final_bpv7 is not None
    assert bytes(final_bpv7) == bundle_bytes


def test_stream_parser_clears_on_shutdown() -> None:
    """A SHUTDOWN/SESS_TERM message clears any in-progress reassembly buffer."""
    parser = TCPCLStreamParser()
    start = _build_segment_packet_bytes(
        version=TCPCLVersion.V3,
        s_flag=True,
        e_flag=False,
        sequence_number=0,
        payload=b"mid-transfer",
    )
    parser.feed(start)
    assert parser._transfer_buffer is not None

    shutdown_msg = TCPCLv3Shutdown()
    shutdown_msg.payload = b""
    shutdown_pkt = TCPCL()
    shutdown_pkt.version = TCPCLVersion.V3
    shutdown_pkt.message_type = TCPCLv3MessageType.SHUTDOWN
    shutdown_pkt.message = shutdown_msg

    parser.feed(bytes(shutdown_pkt))
    assert parser._transfer_buffer is None


def test_stream_parser_sess_term_clears_v4_transfer() -> None:
    """A v4 SESS_TERM message clears any in-progress reassembly buffer."""
    parser = TCPCLStreamParser()
    start = _build_segment_packet_bytes(
        version=TCPCLVersion.V4,
        s_flag=True,
        e_flag=False,
        sequence_number=0,
        payload=b"mid-transfer",
    )
    parser.feed(start)
    assert parser._transfer_buffer is not None

    term_msg = TCPCLv4SessTerm()
    term_msg.payload = b""
    term_pkt = TCPCL()
    term_pkt.version = TCPCLVersion.V4
    term_pkt.message_type = TCPCLv4MessageType.SESS_TERM
    term_pkt.message = term_msg

    parser.feed(bytes(term_pkt))
    assert parser._transfer_buffer is None


def test_stream_parser_buffer_cap_aborts(monkeypatch: pytest.MonkeyPatch) -> None:
    """Exceeding MAX_TRANSFER_BUFFER_SIZE aborts the in-progress transfer."""
    monkeypatch.setattr(tcpcl_module, "MAX_TRANSFER_BUFFER_SIZE", 10)

    parser = TCPCLStreamParser()
    start = _build_segment_packet_bytes(
        version=TCPCLVersion.V3,
        s_flag=True,
        e_flag=False,
        sequence_number=0,
        payload=b"12345",
    )
    middle = _build_segment_packet_bytes(
        version=TCPCLVersion.V3,
        s_flag=False,
        e_flag=False,
        sequence_number=1,
        payload=b"1234567890",
    )
    end = _build_segment_packet_bytes(
        version=TCPCLVersion.V3,
        s_flag=False,
        e_flag=True,
        sequence_number=2,
        payload=b"x",
    )

    packets = parser.feed(start + middle + end)
    assert len(packets) == THREE_SEGMENT_PACKETS
    assert parser._transfer_buffer is None
    # The terminal segment arrives with no transfer in progress (aborted by
    # the cap), so it is treated as a degenerate single segment.
    assert _segment_bpv7(packets[2]) is None


def test_stream_parser_degenerate_end_only_segment() -> None:
    """An E=1-only segment with no prior transfer parses directly as single-segment."""
    bundle_bytes = bytes(_build_simple_bpv7_bundle())
    raw = _build_segment_packet_bytes(
        version=TCPCLVersion.V3,
        s_flag=False,
        e_flag=True,
        sequence_number=0,
        payload=bundle_bytes,
    )
    parser = TCPCLStreamParser()
    packets = parser.feed(raw)
    assert len(packets) == 1
    final_bpv7 = _segment_bpv7(packets[0])
    assert final_bpv7 is not None
    assert bytes(final_bpv7) == bundle_bytes
