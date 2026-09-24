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
 Title: PCAP Parsing example
 Author: Nate Richard
 Modified: 01/30/2026
 Company: JPL
 Date:   01/27/2026

 File: pcap_parse
 Description:
           Functions to demonstrate extracting and parsing bundles from a PCAP
           file
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
import sys
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

import dpkt

from bespokebpv7 import BPv7


def bp_parse(ts: float, buff: bytes, record: dict[float, list[BPv7]]) -> None:
    """Extract Bundle data from PCAP data.

    Args:
        ts: timestamp from PCAP
        buff: Ethernet frame as bytes
        record: Append decoded bundle to list

    """
    try:
        ip_pkt = dpkt.ethernet.Ethernet(buff).ip  # pyright: ignore[reportAttributeAccessIssue] pylint: disable=E1101
        data = ip_pkt.udp.data
    except AttributeError:
        # pass on non-UDP packets
        return
    try:
        decoded = BPv7(data)
    except TypeError:
        # CBOR will likely be able to decode an int from non-bundle UDP data and since
        # bundles will decode as a list, it'll raise a TypeError when trying to access
        # non-existing elements the decoded data.
        return
    record[ts].append(decoded)


def pcap_extract(pcapfile: str) -> dict[float, list[BPv7]]:
    """Get a dictionary of bundles from a given PCAP file.

    Args:
        pcapfile: Path object to PCAP file

    Returns:
        dict with timestamp as key and list of bundles received at given timestamp

    """
    bundle_dict: dict[float, list[BPv7]] = defaultdict(list)
    pcappath = Path(pcapfile)

    with pcappath.open("rb") as file:
        pcapreader = dpkt.pcap.Reader(file)
        pcapreader.loop(bp_parse, bundle_dict)
    return bundle_dict


if __name__ == "__main__":
    FSTR = "%Y-%m-%d %H:%M:%S.%f"
    parser = argparse.ArgumentParser("PCAP file to extract bundles.")
    parser.add_argument("pcap", help="Path to PCAP file")
    args = parser.parse_args()

    bundled = pcap_extract(args.pcap)

    # expect 4 bundles with 2 with duplicate timestamps
    if bundled and len(bundled) == 3:  # ruff: ignore[magic-value-comparison]
        for tstamp, bundles in bundled.items():
            timestamp = datetime.fromtimestamp(tstamp, tz=timezone.utc).strftime(FSTR)
            for bundle in bundles:
                print(f"Bundle Received: {timestamp}\n{bundle}\n")
        sys.exit(0)
    else:
        print("No bundles in PCAP.")
        sys.exit(1)
