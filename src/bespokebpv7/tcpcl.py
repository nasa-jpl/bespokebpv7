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
 Title: TCP Convergence Layer Main Parser
 Author: Nate Richard
 Modified: 09/22/2026
 Company: JPL
 Date:   09/22/2026

 File: tcpcl.py
 Description:
           Main parser and stream handler for TCPCL v3 and v4.
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

import contextlib
import struct
from typing import Any

import dpkt

from bespokebpv7.bpv7 import BPv7
from bespokebpv7.tcpcl_enum import (
    TCPCLv3MessageType,
    TCPCLv4MessageType,
    TCPCLVersion,
)
from bespokebpv7.tcpcl_messages import (
    TCPCLMessage,
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

__all__ = ["TCPCL", "TCPCLStreamParser"]

# Version/Type mapping. See docs/tcpcl.md#message_map-and-reverse-lookup.
MESSAGE_MAP: dict[tuple[TCPCLVersion, int], type[TCPCLMessage]] = {
    (TCPCLVersion.V3, TCPCLv3MessageType.CONTACT): TCPCLv3Contact,
    (TCPCLVersion.V3, TCPCLv3MessageType.KEEPALIVE): TCPCLv3Keepalive,
    (TCPCLVersion.V3, TCPCLv3MessageType.SHUTDOWN): TCPCLv3Shutdown,
    (TCPCLVersion.V3, TCPCLv3MessageType.DATA_SEGMENT): TCPCLv3DataSegment,
    (TCPCLVersion.V3, TCPCLv3MessageType.DATA_ACK): TCPCLv3DataAck,
    (TCPCLVersion.V4, TCPCLv4MessageType.SESS_INIT): TCPCLv4SessInit,
    (TCPCLVersion.V4, TCPCLv4MessageType.KEEPALIVE): TCPCLv4Keepalive,
    (TCPCLVersion.V4, TCPCLv4MessageType.SESS_TERM): TCPCLv4SessTerm,
    (TCPCLVersion.V4, TCPCLv4MessageType.XFER_SEGMENT): TCPCLv4XferSegment,
    (TCPCLVersion.V4, TCPCLv4MessageType.XFER_ACK): TCPCLv4XferAck,
}

MAGIC = b"dtn!"

# TCPCL header minimum sizes.
TCPCL_HEADER_SIZE = 10
TCPCL_STREAM_SEARCH_MIN = 3
TCPCL_STREAM_HEADER_SIZE = 9
TCPCL_DATA_SEG_FLAGS_S = 0x80
TCPCL_DATA_SEG_FLAGS_E = 0x40

# Conservative cap on an in-progress multi-segment transfer buffer
MAX_TRANSFER_BUFFER_SIZE = 64 * 1024 * 1024


class TCPCL(dpkt.Packet):  # type: ignore[misc]
    """
    TCP Convergence Layer (RFC 7242 / RFC 9174).
    Encapsulates a TCPCL message and handles version-based dispatch.
    """

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        """Initialize TCPCL with optional version and message attributes."""
        self.version: TCPCLVersion | None = None
        self.message_type: int | None = None
        self.message: TCPCLMessage | None = None
        super().__init__(*args, **kwargs)

    def unpack(self, buf: bytes) -> None:
        """Unpack raw bytes into the appropriate TCPCL message.

        Raises:
            ValueError: Invalid magic string, unsupported version, or buffer too short.

        """
        if len(buf) < TCPCL_HEADER_SIZE:
            err_msg = "Buffer too short for TCPCL header"
            raise ValueError(err_msg)

        if buf[:4] != MAGIC:
            err_msg = "Invalid TCPCL magic string"
            raise ValueError(err_msg)

        self.version = TCPCLVersion(buf[4])
        length = struct.unpack(">I", buf[5:9])[0]
        self.message_type = buf[9]

        # Payload length excludes the message type byte per RFC.
        payload = buf[10 : 10 + length - 1]

        if len(payload) < length - 1:
            err_msg = "Buffer too short for TCPCL payload"
            raise ValueError(err_msg)

        if self.version is None or self.message_type is None:
            err_msg = "TCPCL version or message type not set"
            raise ValueError(err_msg)

        msg_cls = MESSAGE_MAP.get((self.version, self.message_type))
        if msg_cls is None:
            err_msg = "Unsupported TCPCL version or type"
            raise ValueError(err_msg)

        msg: TCPCLMessage = msg_cls()
        self.message = msg
        msg.unpack(payload)

    def __bytes__(self) -> bytes:
        """Serialize the TCPCL packet back into bytes.

        Returns:
            byte string of the TCPCL packet

        Raises:
            AttributeError: Could not determine TCPCL message type

        """
        if self.message is None:
            return b""

        # Determine version and type from the message object
        version = getattr(self.message, "version", self.version)
        if version is None:
            err_msg = "TCPCL version not set"
            raise AttributeError(err_msg)

        # Reverse-lookup: classes don't store their type.
        msg_type = None
        for (v, t), cls in MESSAGE_MAP.items():
            if v == version and isinstance(self.message, cls):
                msg_type = t
                break

        if msg_type is None:
            err_msg = "Could not determine TCPCL message type"
            raise AttributeError(err_msg)

        payload_bytes = bytes(self.message)
        length = 1 + len(payload_bytes)

        header = MAGIC + struct.pack(">B I B", version, length, msg_type)
        return header + payload_bytes

    def __str__(self) -> str:
        """Human-readable string representation of the TCPCL packet.

        Returns:
            string representation of the TCPCL packet

        """
        if self.message is None:
            return "TCPCL Packet (Empty)"
        return (
            f"TCPCL Packet - Version: "
            f"{self.version.name if self.version else 'None'}, "
            f"Type: {self.message_type}, Msg: {self.message!r}"
        )

    def __repr__(self) -> str:
        """Return a developer-friendly string representation of the TCPCL packet.

        Returns:
            string representation of the TCPCL packet

        """
        return f"TCPCL(version={self.version}, message={self.message!r})"


class TCPCLStreamParser:
    """Helper class for extracting TCPCL packets from a byte stream.

    Also reassembles BPv7 bundles split across multiple data/transfer
    segments; see docs/guides/tcpcl_parsing.md#bpv7-bundle-extraction for
    the full reassembly contract and its known limitations.
    """

    def __init__(self) -> None:
        """Initialize the stream parser with an empty buffer."""
        self.buffer = bytearray()
        self._transfer_buffer: bytearray | None = None

    def _handle_segment(self, message: TCPCLv3DataSegment | TCPCLv4XferSegment) -> None:
        """Feed one data/transfer segment into the reassembly state machine.

        See docs/guides/tcpcl_parsing.md#bpv7-bundle-extraction for the
        full set of edge-case rules (stale-transfer abort, orphan
        discard, buffer cap) this implements.
        """
        if message.s_flag and message.e_flag:
            # Single-segment case already handled by unpack(); nothing to do.
            return

        if message.s_flag:
            # New transfer starting; discard any stale in-progress buffer.
            self._transfer_buffer = bytearray(message.payload)
            return

        if not message.e_flag:
            # Middle segment with no transfer in progress is an orphan.
            if self._transfer_buffer is not None:
                self._transfer_buffer.extend(message.payload)
                if len(self._transfer_buffer) > MAX_TRANSFER_BUFFER_SIZE:
                    self._transfer_buffer = None
            return

        # Terminal (e_flag-only) segment.
        if self._transfer_buffer is not None:
            self._transfer_buffer.extend(message.payload)
            if len(self._transfer_buffer) > MAX_TRANSFER_BUFFER_SIZE:
                self._transfer_buffer = None
                return
            full_bytes = bytes(self._transfer_buffer)
            self._transfer_buffer = None
            with contextlib.suppress(ValueError, TypeError):
                message.bpv7 = BPv7(full_bytes)
        else:
            # Degenerate case: terminal segment with no preceding start.
            with contextlib.suppress(ValueError, TypeError):
                message.bpv7 = BPv7(message.payload)

    def feed(self, data: bytes) -> list[TCPCL]:
        """Add data to the buffer and return any complete TCPCL packets found.

        Returns:
            list of complete TCPCL packets extracted from the buffer

        """
        self.buffer.extend(data)
        packets: list[TCPCL] = []

        while True:
            start_idx = self.buffer.find(MAGIC)
            if start_idx == -1:
                # Retain partial magic for split packets.
                if len(self.buffer) > TCPCL_STREAM_SEARCH_MIN:
                    del self.buffer[: len(self.buffer) - TCPCL_STREAM_SEARCH_MIN]
                break

            if start_idx > 0:
                del self.buffer[:start_idx]

            if len(self.buffer) < TCPCL_STREAM_HEADER_SIZE:
                break

            length = struct.unpack(">I", self.buffer[5:9])[0]

            total_len = TCPCL_STREAM_HEADER_SIZE + length

            if len(self.buffer) < total_len:
                break

            packet_bytes = bytes(self.buffer[:total_len])
            del self.buffer[:total_len]

            try:
                packet = TCPCL()
                packet.unpack(packet_bytes)
            except (ValueError, struct.error):
                continue

            message = packet.message
            if isinstance(message, (TCPCLv3DataSegment, TCPCLv4XferSegment)):
                self._handle_segment(message)
            elif isinstance(message, (TCPCLv3Shutdown, TCPCLv4SessTerm)):
                # A terminated session cannot continue a transfer.
                self._transfer_buffer = None

            packets.append(packet)

        return packets
