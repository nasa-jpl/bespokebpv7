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
TCPCLV3_DATA_ACK_SIZE = 4
# RFC 9174 Sec 5.2.2: 1 flags byte + 8-byte Transfer ID. The Data length
# field (and any Transfer Extension Items, when S flag is set) follow this
# prefix and are validated separately in TCPCLv4XferSegment.unpack().
TCPCLV4_DATA_SEG_HEADER_SIZE = 9
# RFC 9174 Sec 5.2.3: 1 flags byte + 8-byte Transfer ID + 8-byte
# Acknowledged length.
TCPCLV4_XFER_ACK_HEADER_SIZE = 17


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
        if len(buf) < TCPCLV3_DATA_ACK_SIZE:
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
        ``s_flag``, ``e_flag``, ``transfer_id``, ``transfer_extension_items``,
        ``payload``, and ``bpv7`` are set after super-init with sensible
        defaults.

        ``data_length_override`` and ``ext_items_length_override`` are
        optional V&V-testing hooks: when set to an ``int``, ``__bytes__``
        emits that value as the declared Data length / Transfer Extension
        Items Length instead of the actual length of the real data, letting
        callers deliberately construct wire-malformed segments per
        ``AGENTS.md``'s testing philosophy. They default to ``None`` and are
        ignored in that case.

        """
        super().__init__(*args, **kwargs)
        self.s_flag = False
        self.e_flag = False
        self.transfer_id = 0
        self.transfer_extension_items: bytes = b""
        self.payload = b""
        self.bpv7: BPv7 | None = None
        self.data_length_override: int | None = None
        self.ext_items_length_override: int | None = None

    def unpack(self, buf: bytes) -> None:
        """Unpack raw bytes into a TCPCL v4 Transfer Segment (RFC 9174 Sec 5.2.2).

        Raises:
            ValueError: Buffer too short for the transfer segment header,
                or the declared Data length does not exactly match the
                actual remaining buffer length.

        """
        if len(buf) < TCPCLV4_DATA_SEG_HEADER_SIZE:
            err_msg = "Buffer too short for TCPCLv4XferSegment header"
            raise ValueError(err_msg)

        # RFC 9174 Table 5: START = 0x02, END = 0x01.
        self.s_flag = bool(buf[0] & 0x02)
        self.e_flag = bool(buf[0] & 0x01)

        self.transfer_id = struct.unpack(">Q", buf[1:9])[0]

        offset = 9
        if self.s_flag:
            if len(buf) < offset + 4:
                err_msg = "Buffer too short for TCPCLv4XferSegment header"
                raise ValueError(err_msg)
            ext_len = struct.unpack(">I", buf[offset : offset + 4])[0]
            offset += 4
            if len(buf) < offset + ext_len:
                err_msg = "Buffer too short for TCPCLv4XferSegment header"
                raise ValueError(err_msg)
            self.transfer_extension_items = buf[offset : offset + ext_len]
            offset += ext_len
        else:
            self.transfer_extension_items = b""

        if len(buf) < offset + 8:
            err_msg = "Buffer too short for TCPCLv4XferSegment header"
            raise ValueError(err_msg)
        data_length = struct.unpack(">Q", buf[offset : offset + 8])[0]
        offset += 8

        if len(buf) - offset != data_length:
            err_msg = (
                "TCPCLv4XferSegment declared Data length does not match "
                "remaining buffer"
            )
            raise ValueError(err_msg)

        self.payload = buf[offset : offset + data_length]

        # Extract BPv7 if single-segment (S=1, E=1).
        if self.s_flag and self.e_flag:
            with contextlib.suppress(ValueError, TypeError):
                self.bpv7 = BPv7(self.payload)

    def __bytes__(self) -> bytes:
        """Serialize the transfer segment back into bytes (RFC 9174 Sec 5.2.2).

        Returns:
            byte string of the transfer segment

        """
        # RFC 9174 Table 5: START = 0x02, END = 0x01.
        flags = 0
        if self.s_flag:
            flags |= 0x02
        if self.e_flag:
            flags |= 0x01

        data = bytes(self.bpv7) if self.bpv7 else self.payload

        body = struct.pack(">BQ", flags, self.transfer_id)

        if self.s_flag:
            ext_len = (
                self.ext_items_length_override
                if self.ext_items_length_override is not None
                else len(self.transfer_extension_items)
            )
            body += struct.pack(">I", ext_len) + self.transfer_extension_items

        declared_data_len = (
            self.data_length_override
            if self.data_length_override is not None
            else len(data)
        )
        body += struct.pack(">Q", declared_data_len) + data

        return body


class TCPCLv4XferAck(TCPCLv4Message):
    """TCPCL v4 Transfer Ack message."""

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        """Initialize a TCPCL v4 Transfer Ack message."""
        super().__init__(*args, **kwargs)
        self.s_flag = False
        self.e_flag = False
        self.transfer_id = 0
        self.acknowledged_length = 0

    def unpack(self, buf: bytes) -> None:
        """Unpack raw bytes into a TCPCL v4 Transfer Ack message (RFC 9174 Sec 5.2.3).

        Raises:
            ValueError: Buffer too short for the transfer ack header.

        """
        if len(buf) < TCPCLV4_XFER_ACK_HEADER_SIZE:
            err_msg = "Buffer too short for TCPCLv4XferAck"
            raise ValueError(err_msg)
        # RFC 9174 Table 5: START = 0x02, END = 0x01.
        self.s_flag = bool(buf[0] & 0x02)
        self.e_flag = bool(buf[0] & 0x01)
        self.transfer_id = struct.unpack(">Q", buf[1:9])[0]
        self.acknowledged_length = struct.unpack(">Q", buf[9:17])[0]

    def __bytes__(self) -> bytes:
        """Serialize the transfer ack message back into bytes (RFC 9174 Sec 5.2.3).

        Returns:
            byte string of the transfer ack message

        """
        flags = 0
        if self.s_flag:
            flags |= 0x02
        if self.e_flag:
            flags |= 0x01
        return struct.pack(">BQQ", flags, self.transfer_id, self.acknowledged_length)
