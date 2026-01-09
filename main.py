import binascii

import cbor2

from block_enum import BlockType, CRCType
from bpv7 import BPv7
from ext_functions import process_bae, process_pnb, create_pnb


def test():
    """Test function to verify processing"""
    test_bundle = "9f88071844008202820301820100820100821b000000b5998c982b011a000493e08506021000458202820200850704010042183485010101004454455354ff"
    hex_bundle = binascii.unhexlify(test_bundle)
    a = BPv7(hex_bundle)
    b = bytes(a).hex()
    pnb = a.get_block_by_type(BlockType.PREVIOUS_NODE)
    bae = a.get_block_by_type(BlockType.BUNDLE_AGE)
    if pnb:
        process_pnb(pnb)
    if bae:
        process_bae(bae)
    print(b == test_bundle)
    print(a.primary_block.flags)
    a.primary_block.is_fragment = True
    print(a.primary_block.flags)


if __name__ == "__main__":
    payload = cbor2.dumps("Hello world!")
    x = BPv7()
    x.add_payload_block(payload)
    x.primary_block.set_creation()
    x.primary_block.no_fragment = True
    x.primary_block.status_time = True
    x.primary_block.crc_type = CRCType.CRC16
    x.primary_block.route.source_eid = "ipn:2.1"
    x.primary_block.route.dest_eid = "ipn:3.1"
    x.primary_block.update_crc()
    x.add_canonical_block(BlockType.PREVIOUS_NODE, create_pnb("ipn:2.0"), block_num=1024)
    print(bytes(x).hex())
