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
 Title: TCPCL Performance Benchmark
 Author: Nate Richard
 Modified: 09/22/2026
 Company: JPL
 Date:   09/22/2026

 File: test_tcpcl_perf.py
 Description:
           Benchmarks TCPCL parsing/serialization overhead relative to LTP.
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

import timeit

from bespokebpv7 import (
    TCPCL,
    TCPCLv3DataSegment,
    TCPCLv3MessageType,
    TCPCLVersion,
)
from bespokebpv7.bpv7 import BPv7
from bespokebpv7.ltp import LTP
from bespokebpv7.segments import DataSegment


def create_test_bundle(payload_data: bytes) -> bytes:
    """Create a valid BPv7 bundle with the given payload.

    Returns:
        A bundle as a byte string

    """
    bundle = BPv7()
    bundle.primary_block.route.source_eid = "ipn:2.1"
    bundle.primary_block.route.dest_eid = "ipn:3.1"
    bundle.add_payload_block(payload_data)
    return bytes(bundle)


def bench_tcpcl_unpack(buf: bytes) -> TCPCL:
    """Unpack a TCPCL packet from a buffer.

    Returns:
        Parsed TCPCL packet

    """
    pkt = TCPCL()
    pkt.unpack(buf)
    return pkt


def bench_ltp_unpack(buf: bytes) -> LTP:
    """Unpack an LTP segment from a buffer.

    Returns:
        Parsed LTP Segment

    """
    pkt = LTP()
    pkt.unpack(buf)
    return pkt


def bench_tcpcl_serialize(pkt: TCPCL) -> bytes:
    """Serialize a TCPCL packet to bytes.

    Returns:
        TCPCL packet as a byte string

    """
    return bytes(pkt)


def bench_ltp_serialize(pkt: LTP) -> bytes:
    """Serialize an LTP segment to bytes.

    Returns:
        LTP Segment as bytes string

    """
    return bytes(pkt)


def run_benchmark(payload_size: int, iterations: int = 10000) -> None:
    """Run the TCPCL vs LTP performance benchmark for a given payload size."""
    payload = b"A" * payload_size
    bundle_bytes = create_test_bundle(payload)

    # Prepare TCPCL packet (S=1, E=1 triggers BPv7 extraction)
    msg = TCPCLv3DataSegment()
    msg.s_flag = True
    msg.e_flag = True
    msg.sequence_number = 1
    msg.payload = bundle_bytes
    tcpcl_pkt = TCPCL()
    tcpcl_pkt.version = TCPCLVersion.V3
    tcpcl_pkt.message_type = TCPCLv3MessageType.DATA_SEGMENT
    tcpcl_pkt.message = msg
    tcpcl_buf = bytes(tcpcl_pkt)

    # Prepare LTP packet (Client Service ID 1 triggers BPv7 extraction)
    ltp_pkt = LTP()
    ltp_pkt.segment = DataSegment()
    ltp_pkt.segment.data = bundle_bytes
    ltp_pkt.segment.client_service_id = 1
    ltp_buf = bytes(ltp_pkt)

    # Time Unpacking
    t_tcpcl_unpack = timeit.timeit(
        lambda: bench_tcpcl_unpack(tcpcl_buf), number=iterations
    )
    t_ltp_unpack = timeit.timeit(lambda: bench_ltp_unpack(ltp_buf), number=iterations)

    # Time Serialization
    t_tcpcl_ser = timeit.timeit(
        lambda: bench_tcpcl_serialize(tcpcl_pkt), number=iterations
    )
    t_ltp_ser = timeit.timeit(lambda: bench_ltp_serialize(ltp_pkt), number=iterations)

    print(f"\nPayload Size: {payload_size} bytes | Iterations: {iterations}")  # ruff: ignore[print]
    print(f"Unpack -> TCPCL: {t_tcpcl_unpack:.4f}s, LTP: {t_ltp_unpack:.4f}s")  # ruff: ignore[print]
    print(f"Serialize -> TCPCL: {t_tcpcl_ser:.4f}s, LTP: {t_ltp_ser:.4f}s")  # ruff: ignore[print]

    overhead_unpack = ((t_tcpcl_unpack - t_ltp_unpack) / t_ltp_unpack) * 100
    overhead_ser = ((t_tcpcl_ser - t_ltp_ser) / t_ltp_ser) * 100

    print(f"Overhead Unpack: {overhead_unpack:.2f}%")  # ruff: ignore[print]
    print(f"Overhead Serialize: {overhead_ser:.2f}%")  # ruff: ignore[print]


if __name__ == "__main__":
    print("Starting TCPCL vs LTP Performance Benchmark...")  # ruff: ignore[print]
    run_benchmark(1024)  # 1 KB
    run_benchmark(1024 * 1024)  # 1 MB
