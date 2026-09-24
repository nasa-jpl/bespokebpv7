"""------------------------------------
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
 Title: Verification and Validation Test
 Author: Nate Richard
 Modified: 06/22/2026
 Company: JPL
 Date:   01/29/2026

 File: runtest
 Description:
           Script to demonstrate how to send both good and bad bundles to an
           implmentation
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

import cbor2

from bespokebpv7 import BlockType, BPv7, CRCType

received_responses: list[bytes] = []


def udp_receiver(stop: threading.Event, rport: int = 2113) -> None:
    """Listen for incoming UDP packets and parses them as BPv7 bundles."""
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.bind(("127.0.0.1", rport))
        s.settimeout(1)
        while not stop.is_set():
            try:
                data, addr = s.recvfrom(65535)
                print(f"\n[RECEIVER] Received {len(data)} bytes from {addr}")
            except TimeoutError:
                continue

            try:
                resp_bundle = BPv7(data)
            except ValueError as e:
                print(f"[RECEIVER] Error parsing incoming data as BPv7: {e}")
                continue

            payload_block = resp_bundle.get_block_by_type(BlockType.PAYLOAD_BLOCK)

            if payload_block:
                payload_content = payload_block.data
                received_responses.append(payload_content)
                print("[RECEIVER] Successfully parsed bundle!")
                print(
                    f"[RECEIVER] Source: {resp_bundle.primary_block.route.source_eid}"
                )
                print(f"[RECEIVER] Payload: {payload_content.decode(errors='replace')}")
            else:
                print("[RECEIVER] Warning: Parsed bundle but found no payload block.")


def send_bundle(raw_bundle: bytes, sport: int = 3113) -> None:
    """Send the raw bundle bytes via UDP."""
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.sendto(raw_bundle, ("127.0.0.1", sport))


def create_bundle(
    crc: bool = False,
    creation: bool = False,
    add_ext: bool = False,
    pldnum: int = 1,
) -> bytes:
    """Create a BPv7 bundle with specificed parameters.

    Returns:
        Populated bundle

    Raises:
        RuntimeError: When payload block is missing

    """
    bundle = BPv7()
    bundle.primary_block.route.source_eid = "ipn:2.1"
    bundle.primary_block.route.dest_eid = "ipn:3.1"
    bundle.add_payload_block(b"Hello world!")
    if pldnum != 1:
        pld = bundle.get_block_by_type(BlockType.PAYLOAD_BLOCK)
        if pld is None:
            msg = "Payload block must exist to set its block number."
            raise RuntimeError(msg)
        pld.block_number = pldnum
    if creation:
        bundle.primary_block.set_creation()
    if crc:
        bundle.primary_block.crc_type = CRCType.CRC16
        bundle.primary_block.update_crc()
    else:
        bundle.primary_block.crc_type = CRCType.NONE
    if add_ext:
        bundle.add_canonical_block(
            {"block_type": BlockType.HOP_COUNT}, cbor2.dumps([5, 10])
        )
    return bytes(bundle)


def generate_malformed_bytes(
    target_block_type: BlockType, injection_bytes: bytes = b"deadbeef"
) -> bytes:
    """Generate a bundle with bad extension block data.

    Args:
        target_block_type: Blocktype to malicously modify
        injection_bytes: The bad bytes to add to the target's valid CBOR.

    Returns:
        The raw bytes of the malformed bundle.

    """
    bundle = BPv7(create_bundle(crc=True, creation=True, add_ext=True))

    target_block = bundle.get_block_by_type(target_block_type)

    if target_block:
        target_block.data_prefix = injection_bytes

    return bytes(bundle)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="bespokebpv7 V&V Test.")
    parser.add_argument(
        "--recv-port",
        "-r",
        type=int,
        help="Port to receive bundle status reports.",
    )
    parser.add_argument(
        "--src-port",
        "-s",
        type=int,
        help="Port to send bundle to, generating status reports.",
    )

    vargs = parser.parse_args()

    print("--- Starting Bespoke BPv7 Verification Suite ---")
    stop_event = threading.Event()
    receiver_thread = threading.Thread(
        target=udp_receiver,
        args=(
            stop_event,
            vargs.recv_port,
        ),
    )
    receiver_thread.start()

    test_cases: list[tuple[str, bytes]] = [
        (
            "Payload block number != 1",
            create_bundle(crc=True, creation=True, pldnum=99),
        ),
        ("Malformed Hop Count", generate_malformed_bytes(BlockType.HOP_COUNT)),
        ("No Primary CRC and no BIB", create_bundle(creation=True)),
        ("Creation Time 0 and no Bundle Age block", create_bundle(crc=True)),
    ]

    for desc, test_bundle in test_cases:
        print(f"\n[Test] Sending: {desc}")
        send_bundle(test_bundle, vargs.src_port)
        time.sleep(3)

    print("\n[Test] Sending conformant bundle (expecting echo)...")
    b_good = create_bundle(crc=True, creation=True)
    send_bundle(bytes(b_good), vargs.src_port)
    time.sleep(3)

    stop_event.set()
    receiver_thread.join()

    print("\n--- Summary ---")
    print("Total bundles sent: 5")
    print(f"Total valid payloads echoed back: {len(received_responses)}")

    if len(received_responses) == 1:
        print("SUCCESS: Only the conformant bundle triggered an echo response!")
        sys.exit(0)
    else:
        print(f"FAILED: Expected 1 response, but got {len(received_responses)}.")
        sys.exit(1)
