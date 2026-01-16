import binascii

import cbor2

from bespokebpv7.block_enum import BlockType, CRCType
from bespokebpv7.bpv7 import BPv7
from bespokebpv7.utils import parse_eid_string


def test():
    """Test function to verify processing"""
    test_bundle = "9f88071844008202820301820100820100821b000000b5998c982b011a000493e08506021000458202820200850704010042183485010101004454455354ff"
    hex_bundle = binascii.unhexlify(test_bundle)
    a = BPv7(hex_bundle, debug=True)
    b = bytes(a).hex()
    print(f"Input equals output: {b == test_bundle}")


def create_new():
    """Example to create new bundle"""
    payload = cbor2.dumps("Hello!")
    x = BPv7()
    x.add_payload_block(payload)
    x.primary_block.set_creation()
    x.primary_block.no_fragment = True
    x.primary_block.status_time = True
    x.primary_block.crc_type = CRCType.CRC16
    x.primary_block.route.source_eid = "ipn:2.1"
    x.primary_block.route.dest_eid = "ipn:3.1"
    x.primary_block.update_crc()
    x.add_canonical_block(
        BlockType.PREVIOUS_NODE, cbor2.dumps(parse_eid_string("ipn:2.0"))
    )
    print(x)
    print(bytes(x).hex())


def modify():
    """Example on modifying bundle"""
    y = "9f88070000820282030182028201018202820100821b000000bb0e20b4ea001a000927c08508020100410086010100014d48656c6c6f2c20576f726c64214254b3ff"
    z = BPv7(binascii.unhexlify(y))
    payload = cbor2.dumps("Hello!")
    z.blocks[BlockType.PAYLOAD_BLOCK].data = payload
    z.blocks[BlockType.PAYLOAD_BLOCK].update_crc()
    z.primary_block.no_fragment = True
    z.primary_block.status_time = True
    z.primary_block.route.source_eid = "ipn:2.1"
    z.primary_block.route.dest_eid = "ipn:3.1"
    z.primary_block.crc_type = CRCType.CRC16
    z.primary_block.set_creation()
    z.primary_block.update_crc()
    print(z)
    print(bytes(z))


if __name__ == "__main__":
    print("Verify functionality:")
    test()

    print("\n\nCreate new bundle:")
    create_new()

    print("\n\nModify existing bundle:")
    modify()
