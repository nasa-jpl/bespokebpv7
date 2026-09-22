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

*******************************************************************************
  Title: TCP Convergence Layer Messages
  Author: Nate Richard
  Modified: 09/22/2026
  Company: JPL
  Date:   09/22/2026

  File: tcpcl_messages.py
  Description:
            Hierarchy of TCPCL message types for v3 and v4.
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
*******************************************************************************
"""

import contextlib
import struct
from typing import Any

import dpkt  # type: ignore[import-untyped]

from bespokebpv7.bpv7 import BPv7
from bespokebpv7.tcpcl_enum import TCPCLVersion

# Minimum header sizes.
TCPCLV3_DATA_SEG_HEADER_SIZE = 5
TCPCLV4_DATA_SEG_HEADER_SIZE = 5
TCPCLV4_XFER_ACK_HEADER_SIZE = 4


class TCPCLMessage(dpkt.Packet):  # type: ignore[misc]
    """Base class for all TCPCL messages."""

    def update_length(self) -> None:
        """Update the message length field before serialization."""


class TCPCLv3Message(TCPCLMessage):
    """Base class for TCPCL v3 messages."""

    version = TCPCLVersion.V3


class TCPCLv3Contact(TCPCLv3Message):
    """TCPCL v3 Contact message."""

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        """Initialize a TCPCL v3 Contact message."""
        super().__init__(*args, **kwargs)
        self.payload = b""

    def unpack(self, buf: bytes) -> None:
        """Unpack raw bytes into the contact message payload."""
        self.payload = buf

    def __bytes__(self) -> bytes:
        """Serialize the contact message back into bytes.

        Returns:
            byte string of the contact message

        """
        return self.payload


class TCPCLv3Keepalive(TCPCLv3Message):
    """TCPCL v3 Keepalive message."""

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        """Initialize a TCPCL v3 Keepalive message."""
        super().__init__(*args, **kwargs)
        self.payload = b""

    def unpack(self, buf: bytes) -> None:
        """Unpack raw bytes into the keepalive message payload."""
        self.payload = buf

    def __bytes__(self) -> bytes:
        """Serialize the keepalive message back into bytes.

        Returns:
            byte string of the keepalive message

        """
        return self.payload


class TCPCLv3Shutdown(TCPCLv3Message):
    """TCPCL v3 Shutdown message."""

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        """Initialize a TCPCL v3 Shutdown message."""
        super().__init__(*args, **kwargs)
        self.payload = b""

    def unpack(self, buf: bytes) -> None:
        """Unpack raw bytes into the shutdown message payload."""
        self.payload = buf

    def __bytes__(self) -> bytes:
        """Serialize the shutdown message back into bytes.

        Returns:
            byte string of the shutdown message

        """
        return self.payload


class TCPCLv3DataSegment(TCPCLv3Message):
    """TCPCL v3 Data Segment message.

    Handles the Start (S) and End (E) flags and encapsulates BPv7 bundles.
    """

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        """Initialize a TCPCL v3 Data Segment message.

        Accepts the same arguments as the parent ``TCPCLv3Message``;
        ``s_flag``, ``e_flag``, ``sequence_number``, ``payload``, and
        ``bpv7`` are set after super-init with sensible defaults.

        """
        super().__init__(*args, **kwargs)
        self.s_flag = False
        self.e_flag = False
        self.sequence_number = 0
        self.payload = b""
        self.bpv7: BPv7 | None = None

    def unpack(self, buf: bytes) -> None:
        """Unpack raw bytes into a TCPCL v3 Data Segment.

        Raises:
            ValueError: Buffer too short for the data segment header.

        """
        if len(buf) < TCPCLV3_DATA_SEG_HEADER_SIZE:
            err_msg = "Buffer too short for TCPCLv3DataSegment header"
            raise ValueError(err_msg)

        self.s_flag = bool(buf[0] & 0x80)
        self.e_flag = bool(buf[0] & 0x40)

        self.sequence_number = struct.unpack(">I", buf[1:5])[0]

        self.payload = buf[5:]

        # Extract BPv7 if single-segment (S=1, E=1)
        if self.s_flag and self.e_flag:
            with contextlib.suppress(ValueError, TypeError):
                self.bpv7 = BPv7(self.payload)

    def __bytes__(self) -> bytes:
        """Serialize the data segment back into bytes.

        Returns:
            byte string of the data segment

        """
        flags = 0
        if self.s_flag:
            flags |= 0x80
        if self.e_flag:
            flags |= 0x40

        header = struct.pack(">B I", flags, self.sequence_number)

        data = bytes(self.bpv7) if self.bpv7 else self.payload

        return header + data


class TCPCLv3DataAck(TCPCLv3Message):
    """TCPCL v3 Data Ack message."""

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        """Initialize a TCPCL v3 Data Ack message."""
        super().__init__(*args, **kwargs)
        self.sequence_number = 0

    def unpack(self, buf: bytes) -> None:
        """Unpack raw bytes into a TCPCL v3 Data Ack message.

        Raises:
            ValueError: Buffer too short for the data ack header.

        """
        if len(buf) < TCPCLV4_XFER_ACK_HEADER_SIZE:
            err_msg = "Buffer too short for TCPCLv3DataAck"
            raise ValueError(err_msg)
        self.sequence_number = struct.unpack(">I", buf[:4])[0]

    def __bytes__(self) -> bytes:
        """Serialize the data ack message back into bytes.

        Returns:
            byte string of the data ack message

        """
        return struct.pack(">I", self.sequence_number)


class TCPCLv4Message(TCPCLMessage):
    """Base class for TCPCL v4 messages."""

    version = TCPCLVersion.V4


class TCPCLv4SessInit(TCPCLv4Message):
    """TCPCL v4 Session Initialization message."""

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        """Initialize a TCPCL v4 Session Initialization message."""
        super().__init__(*args, **kwargs)
        self.payload = b""

    def unpack(self, buf: bytes) -> None:
        """Unpack raw bytes into the session init message payload."""
        self.payload = buf

    def __bytes__(self) -> bytes:
        """Serialize the session init message back into bytes.

        Returns:
            byte string of the session init message

        """
        return self.payload


class TCPCLv4Keepalive(TCPCLv4Message):
    """TCPCL v4 Keepalive message."""

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        """Initialize a TCPCL v4 Keepalive message."""
        super().__init__(*args, **kwargs)
        self.payload = b""

    def unpack(self, buf: bytes) -> None:
        """Unpack raw bytes into the keepalive message payload."""
        self.payload = buf

    def __bytes__(self) -> bytes:
        """Serialize the keepalive message back into bytes.

        Returns:
            byte string of the keepalive message

        """
        return self.payload


class TCPCLv4SessTerm(TCPCLv4Message):
    """TCPCL v4 Session Termination message."""

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        """Initialize a TCPCL v4 Session Termination message."""
        super().__init__(*args, **kwargs)
        self.payload = b""

    def unpack(self, buf: bytes) -> None:
        """Unpack raw bytes into the session term message payload."""
        self.payload = buf

    def __bytes__(self) -> bytes:
        """Serialize the session term message back into bytes.

        Returns:
            byte string of the session term message

        """
        return self.payload


class TCPCLv4XferSegment(TCPCLv4Message):
    """TCPCL v4 Transfer Segment message.

    Handles the Start (S) and End (E) flags and encapsulates BPv7 bundles.
    """

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        """Initialize a TCPCL v4 Transfer Segment message.

        Accepts the same arguments as the parent ``TCPCLv4Message``;
        ``s_flag``, ``e_flag``, ``sequence_number``, ``payload``, and
        ``bpv7`` are set after super-init with sensible defaults.

        """
        super().__init__(*args, **kwargs)
        self.s_flag = False
        self.e_flag = False
        self.sequence_number = 0
        self.payload = b""
        self.bpv7: BPv7 | None = None

    def unpack(self, buf: bytes) -> None:
        """Unpack raw bytes into a TCPCL v4 Transfer Segment.

        Raises:
            ValueError: Buffer too short for the transfer segment header.

        """
        if len(buf) < TCPCLV4_DATA_SEG_HEADER_SIZE:
            err_msg = "Buffer too short for TCPCLv4XferSegment header"
            raise ValueError(err_msg)

        self.s_flag = bool(buf[0] & 0x80)
        self.e_flag = bool(buf[0] & 0x40)

        self.sequence_number = struct.unpack(">I", buf[1:5])[0]

        self.payload = buf[5:]

        # Extract BPv7 if single-segment (S=1, E=1).
        if self.s_flag and self.e_flag:
            with contextlib.suppress(ValueError, TypeError):
                self.bpv7 = BPv7(self.payload)

    def __bytes__(self) -> bytes:
        """Serialize the transfer segment back into bytes.

        Returns:
            byte string of the transfer segment

        """
        flags = 0
        if self.s_flag:
            flags |= 0x80
        if self.e_flag:
            flags |= 0x40

        header = struct.pack(">B I", flags, self.sequence_number)

        data = bytes(self.bpv7) if self.bpv7 else self.payload

        return header + data


class TCPCLv4XferAck(TCPCLv4Message):
    """TCPCL v4 Transfer Ack message."""

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        """Initialize a TCPCL v4 Transfer Ack message."""
        super().__init__(*args, **kwargs)
        self.sequence_number = 0

    def unpack(self, buf: bytes) -> None:
        """Unpack raw bytes into a TCPCL v4 Transfer Ack message.

        Raises:
            ValueError: Buffer too short for the transfer ack header.

        """
        if len(buf) < TCPCLV4_XFER_ACK_HEADER_SIZE:
            err_msg = "Buffer too short for TCPCLv4XferAck"
            raise ValueError(err_msg)
        self.sequence_number = struct.unpack(">I", buf[:4])[0]

    def __bytes__(self) -> bytes:
        """Serialize the transfer ack message back into bytes.

        Returns:
            byte string of the transfer ack message

        """
        return struct.pack(">I", self.sequence_number)
