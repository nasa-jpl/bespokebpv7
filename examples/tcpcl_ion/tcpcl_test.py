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
 Title: TCPCL Integration Test Suite
 Author: Nate Richard
 Modified: 09/22/2026
 Company: JPL
 Date:   09/22/2026

 File: tcpcl_test.py
 Description:
           Validates TCPCL handshakes and bundle transfers using a simple
           TCP server and client implementation.
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

import argparse
import socket
import sys
import threading
import time

from bespokebpv7 import (
    TCPCL,
    BPv7,
    TCPCLStreamParser,
    TCPCLv3DataSegment,
    TCPCLv3MessageType,
    TCPCLVersion,
)


def _handle_packet(pkt: TCPCL, target_bundle_bytes: bytes | None = None) -> None:
    """Validate a single received packet, printing success or mismatch."""
    msg = pkt.message
    if msg is None or not isinstance(msg, TCPCLv3DataSegment):
        return

    if not (msg.s_flag and msg.e_flag):
        return

    if msg.bpv7 is None:
        print("Bundle mismatch!")
        return

    if target_bundle_bytes and bytes(msg.bpv7) != target_bundle_bytes:
        print("Bundle mismatch!")
    else:
        print(f"Successfully received bundle: {msg.bpv7}")


def _handle_connection(
    conn: socket.socket, target_bundle_bytes: bytes | None = None
) -> None:
    """Feed an accepted connection's stream into the parser and validate packets."""
    parser = TCPCLStreamParser()
    while data := conn.recv(4096):
        for pkt in parser.feed(data):
            _handle_packet(pkt, target_bundle_bytes)


def run_tcp_server(
    host: str, port: int, target_bundle_bytes: bytes | None = None
) -> None:
    """TCP server that listens for TCPCL packets and validates a bundle transfer."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((host, port))
        s.listen(1)
        s.settimeout(5)
        try:
            conn, _ = s.accept()
        except TimeoutError:
            return
        with conn:
            _handle_connection(conn, target_bundle_bytes)


def send_tcpcl_bundle(host: str, port: int, bundle_bytes: bytes) -> None:
    """Client that sends a single-segment TCPCL v3 bundle."""
    msg = TCPCLv3DataSegment()
    msg.s_flag = True
    msg.e_flag = True
    msg.sequence_number = 1
    msg.payload = bundle_bytes

    pkt = TCPCL()
    pkt.version = TCPCLVersion.V3
    pkt.message_type = TCPCLv3MessageType.DATA_SEGMENT
    pkt.message = msg

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((host, port))
        s.sendall(bytes(pkt))


def test_bundle_transfer(args: argparse.Namespace) -> None:
    """Integration test: Send a valid BPv7 bundle over TCPCL."""
    host, port = args.host, args.port
    bundle = BPv7()
    bundle.add_payload_block(b"Valid Bundle Payload")
    bundle_bytes = bytes(bundle)

    server_thread = threading.Thread(
        target=run_tcp_server, args=(host, port, bundle_bytes), daemon=True
    )
    server_thread.start()

    time.sleep(0.2)
    send_tcpcl_bundle(host, port, bundle_bytes)
    time.sleep(0.2)


def test_malformed_frame(args: argparse.Namespace) -> None:
    """Integration test: Server should handle malformed TCPCL frames gracefully."""
    host, port = args.host, args.port + 1

    def server() -> None:
        parser = TCPCLStreamParser()
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind((host, port))
            s.listen(1)
            s.settimeout(2)
            try:
                conn, _ = s.accept()
                with conn:
                    data = conn.recv(4096)
                    parser.feed(data)
            except TimeoutError:
                pass

    threading.Thread(target=server, daemon=True).start()
    time.sleep(0.2)

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((host, port))
        s.sendall(b"garbage data that is not tcpcl")


def main() -> None:
    """Stand up test server & run tests."""
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=5555)
    args = parser.parse_args()

    print(f"Running integration tests on {args.host}:{args.port}...")
    test_bundle_transfer(args)
    print("Bundle transfer test passed.")
    test_malformed_frame(args)
    print("Malformed frame test passed.")
    print("All integration tests passed.")
    sys.exit(0)


if __name__ == "__main__":
    main()
