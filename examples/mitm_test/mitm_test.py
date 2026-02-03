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
 Title: Man-In-The-Middle Attack Example
 Author: Nate Richard
 Modified: 02/02/2026
 Company: JPL
 Date:   01/28/2026

 File: mitm_test
 Description:
           Classes to simulate MITM attack on a DTN implementation
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
import socketserver
import threading
from collections.abc import Callable
from typing import cast

from bespokebpv7.bpv7 import BPv7  # type: ignore[import-untyped]
from bespokebpv7.utils import parse_eid_string  # type: ignore[import-untyped]


class BPv7ProxyServer(socketserver.ThreadingMixIn, socketserver.UDPServer):
    """Multi-threaded UDP Server.

    Stores the configuration for the proxy.
    """

    def __init__(
        self,
        server_address: tuple,
        requesthandlerclass: Callable,
        config_map: dict,
    ) -> None:
        """Set parameters for man in the middle"""
        super().__init__(server_address, requesthandlerclass)
        self.node_port_map: dict[int, int] = config_map["node_port_map"]
        self.modify_enabled = config_map["modify"]
        self.bidirectional = config_map["bidirectional"]
        self.src_node = config_map["src_node"]
        self.expected_mods = config_map["expected"]

        self.mods = 0
        # Lock to ensure thread-safe incrementing of the counter
        self.count_lock = threading.Lock()


class ThreadedUDPRequestHandler(socketserver.BaseRequestHandler):
    """Handles incoming UDP packets in a separate thread."""

    def handle(self) -> None:
        """Handle incoming packets."""
        raw_data = self.request[0]
        current_socket = self.request[1]

        server = cast("BPv7ProxyServer", self.server)

        try:
            bundle = BPv7(raw_data)
        except ValueError as e:
            print(f"[!] Failed to decode bundle: {e}")
            return

        dest_node_list = parse_eid_string(bundle.primary_block.route.dest_eid)

        # Assumes IPN scheme [scheme_code, [node, service]]
        if isinstance(dest_node_list[1], list):
            dest_node = dest_node_list[1][0]
        else:
            print("[!] Only IPN scheme support, dropping.")
            return

        dest_port = server.node_port_map.get(dest_node)

        if dest_port:
            print(f"Routing bundle for Node {dest_node} -> 127.0.0.1:{dest_port}")
        else:
            print(f"[!] Unknown destination node: {dest_node}, dropping.")
            return

        should_modify = server.modify_enabled

        if should_modify and not server.bidirectional:
            src_node_list = parse_eid_string(bundle.primary_block.route.source_eid)

            current_src_node = None
            if isinstance(src_node_list[1], list):
                current_src_node = src_node_list[1][0]

            if current_src_node != server.src_node:
                print(
                    "   [>>] Unidirectional Mode: "
                    f"Skipping modification for traffic from Node {current_src_node}"
                )
                should_modify = False

        if should_modify:
            mod_bundle = self.modify_bundle(bundle)
            try:
                final_data = bytes(mod_bundle)
            except ValueError as e:
                print(f"[!] Failed to repack bundle: {e}")
                final_data = raw_data
        else:
            print("   [>>] Pass-through: Forwarding original bytes.")
            final_data = raw_data

        # --- Forwarding ---
        current_socket.sendto(final_data, ("127.0.0.1", dest_port))

        if should_modify:
            with server.count_lock:
                server.mods += 1
                print(f"   [COUNT] Mod {server.mods}/{server.expected_mods} completed.")

                if server.mods >= server.expected_mods:
                    print("   [!] Mod limit reached. Triggering server shutdown...")
                    # We use a separate thread for shutdown to avoid deadlocking the
                    # current request
                    threading.Thread(target=server.shutdown).start()

    @staticmethod
    def modify_bundle(bundle: BPv7) -> BPv7:
        """Apply modifications to the bundle object in place.

        Args:
            bundle: Original received bundle

        Returns:
            Modified bundle

        """
        # Modify primary block, so BIB fails
        if not bundle.primary_block.deliv_report:
            print("   [MOD] Requesting delivery report (invalidating BIB)...")
            bundle.primary_block.deliv_report = True
            bundle.primary_block.update_crc()

        return bundle


if __name__ == "__main__":
    parser = argparse.ArgumentParser("Define parameters for Man-In-The-Middle proxy.")
    parser.add_argument(
        "--proxy-ip",
        "--ip",
        help="IP address to bind to for handling bundles.",
        default="127.0.0.1",
    )
    parser.add_argument(
        "--proxy-port",
        help="Port to listen on for incoming bundles.",
        type=int,
        default=5115,
    )
    parser.add_argument(
        "--modify",
        "-m",
        help="Enable inflight modification of bundles.",
        action="store_true",
    )
    parser.add_argument(
        "--bidirectional",
        "-b",
        help="Enable modification in both directions.",
        action="store_true",
    )
    parser.add_argument(
        "--src-node",
        "-s",
        help="Node number that will determine which direction modification will apply.",
        type=int,
    )
    parser.add_argument(
        "--src-port", help="Port for source node induct", type=int, default=2112
    )
    parser.add_argument(
        "--dst-node",
        "-d",
        help="Node number that will be the destination for modified bundles.",
        type=int,
    )
    parser.add_argument(
        "--dst-port", help="Port for destination node induct.", type=int, default=3113
    )

    args = parser.parse_args()

    NODE_PORT_MAP = {args.src_node: args.src_port, args.dst_node: args.dst_port}

    CONFIG_MAP = {
        "node_port_map": NODE_PORT_MAP,
        "modify": args.modify,
        "bidirectional": args.bidirectional,
        "src_node": args.src_node,
        "expected": 3,
    }

    print("--- BespokeBPv7 Threaded UDP Proxy ---")
    print(f"Listening: {args.proxy_ip}:{args.proxy_port}")
    print(f"Routing Map: {NODE_PORT_MAP}")
    print(f"Modification Enabled: {args.modify}")
    print(f"Bidirectional Modification: {args.bidirectional}")
    if args.modify and not args.bidirectional:
        print(f"Unidirectional Source Node: {args.src_node}")

    mserver = BPv7ProxyServer(
        (args.proxy_ip, args.proxy_port),
        ThreadedUDPRequestHandler,
        CONFIG_MAP,
    )

    print("Proxy is running. Press Ctrl+C to stop.")

    try:
        mserver.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down proxy...")
        mserver.shutdown()
