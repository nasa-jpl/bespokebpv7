"""
------------------------------------
     JET PROPULSION LABORATORY
------------------------------------
Title: BPv7 Serialization Converter
File: converter.py
Description:
    Configures cattrs for serializing/deserializing BPv7 objects to/from
    the list-based formats required by RFC 9171 (CBOR).
"""

from typing import Any, List, Type, Union, Callable

import cbor2
from cattrs.preconf.cbor2 import make_converter

from bespokebpv7.block_enum import BlockType, CRCType, BundleFlags, BlockFlags, SecurityContextFlags
from bespokebpv7.blocks import (
    CanonicalBlock,
    PayloadBlock,
    PrimaryBlock,
)
from bespokebpv7.bundle_params import BundleRoute, BundleLife, BundleFragmentation
from bespokebpv7.bpsec import (
    AbstractSecurityBlock,
    BlockIntegrityBlock,
    SecurityParameter,
    SecurityResult
)
from bespokebpv7.utils import parse_eid_string

converter = make_converter()


# --- Security Hooks (BPsec) ---

def unstructure_sec_param(param: SecurityParameter) -> List[Any]:
    return [param.parm_id, param.value]


def structure_sec_param(data: List[Any], _: Type) -> SecurityParameter:
    return SecurityParameter(parm_id=data[0], value=data[1])


def unstructure_sec_result(res: SecurityResult) -> List[Any]:
    return [res.result_id, res.value]


def structure_sec_result(data: List[Any], _: Type) -> SecurityResult:
    return SecurityResult(result_id=data[0], value=data[1])


# --- Primary Block Hooks ---

def unstructure_primary_block(block: PrimaryBlock) -> List[Any]:
    """
    Serializes PrimaryBlock to
    [version, flags, crc_type, dest, src, report, creation, life, frag, adu_len, crc]
    """
    output: list[Union[int, list, bytes]] = [
        block.version,
        block.flags.value,
        block.crc_type.value,
    ]
    output.append(parse_eid_string(block.route.dest_eid))
    output.append(parse_eid_string(block.route.source_eid))
    output.append(parse_eid_string(block.route.report_to))
    output.append([block.life.timestamp_ms, block.life.sequence])
    output.append(block.life.lifetime)

    if block.is_fragment:
        output.append(block.fragmentation.fragment_offset)
        output.append(block.fragmentation.total_adu_len)

    if block.crc_type != CRCType.NONE and block.crc:
        output.append(block.crc)

    return output


def structure_primary_block(data: List[Any], _) -> PrimaryBlock:

    version = data[0]
    flags = BundleFlags(data[1])
    crc_type = CRCType(data[2])

    route = BundleRoute(
        _dest_eid=data[3],
        _source_eid=data[4],
        _report_to_eid=data[5]
    )

    creation_data = data[6]
    life = BundleLife(
        timestamp_ms=creation_data[0],
        sequence=creation_data[1],
        lifetime=data[7]
    )

    fragmentation = BundleFragmentation()
    crc = b""
    current_idx = 8

    if flags & BundleFlags.IS_FRAGMENT:
        fragmentation.fragment_offset = data[current_idx]
        fragmentation.total_adu_len = data[current_idx + 1]
        current_idx += 2

    if crc_type != CRCType.NONE and current_idx < len(data):
        crc = data[current_idx]

    return PrimaryBlock(
        version=version,
        _flags=flags,
        _crc_type=crc_type,
        route=route,
        life=life,
        fragmentation=fragmentation,
        crc=crc
    )


# --- Canonical / Payload / Security Block Hooks ---

def _unstructure_canonical_base(block: CanonicalBlock, data_content: Any) -> List[Any]:
    """Helper to build the standard [type, num, flags, crc_type, data, crc] list."""
    output = [
        block.block_type.value,
        block.block_number,
        block.flags.value,
        block.crc_type.value,
        data_content
    ]
    if block.crc_type != CRCType.NONE:
        output.append(block.crc)
    return output


def unstructure_canonical_block(block: CanonicalBlock) -> List[Any]:
    if block.block_type == BlockType.PAYLOAD_BLOCK:
        data_content = block.data
    else:
        data_content = cbor2.dumps(block.data)

    return _unstructure_canonical_base(block, data_content)


def unstructure_security_block(block: AbstractSecurityBlock) -> List[Any]:
    """
    Serializes a Security Block.
    1. Unstructures internal fields to ASB List.
    2. CBOR dumps ASB List.
    3. Wraps in Canonical Block List.
    """
    # 1. Build Abstract Security Block (ASB) List
    # Structure: [targets, context_id, flags, source, parameters, results]
    asb_list = [
        block.security_targets,
        block.security_context_id,
        block.security_context_flags.value,
        block.security_source,
        [converter.unstructure(p) for p in block.security_parameters],
        [converter.unstructure(r) for r in block.security_results],
    ]

    # 2. Encode ASB to bytes (this becomes the 'block-type-specific-data')
    asb_bytes = cbor2.dumps(asb_list)

    # 3. Build outer Canonical Block
    return _unstructure_canonical_base(block, asb_bytes)


def _structure_bib(raw_data: bytes) -> BlockIntegrityBlock:
    """Helper to structure Abstract Security Blocks (BIB/BCB)."""
    asb_list = cbor2.loads(raw_data)
    block = BlockIntegrityBlock()

    # Map RFC 9172 list structure to class fields
    block.security_targets = asb_list[0]
    block.security_context_id = asb_list[1]
    block.security_context_flags = SecurityContextFlags(asb_list[2])
    block.security_source = asb_list[3]
    block.security_parameters = [
        converter.structure(p, SecurityParameter) for p in asb_list[4]
    ]
    block.security_results = [
        converter.structure(r, SecurityResult) for r in asb_list[5]
    ]
    return block


def _structure_payload(raw_data: bytes) -> PayloadBlock:
    """Helper to structure Payload Block (keeps raw data)."""
    block = PayloadBlock()
    block.data = raw_data
    return block


def _structure_generic(raw_data: bytes) -> CanonicalBlock:
    """Helper to structure generic Canonical Blocks (CBOR loads data)."""
    block = CanonicalBlock()
    block.data = cbor2.loads(raw_data)
    return block


BLOCK_HANDLER_MAP: dict[BlockType, Callable[[bytes], CanonicalBlock]] = {
    BlockType.PAYLOAD_BLOCK: _structure_payload,
    BlockType.BIB: _structure_bib,
    BlockType.UNKNOWN_BLOCK: _structure_generic
}


def structure_canonical_block(data: List[Any], _: Type) -> CanonicalBlock:
    """
    Deserializes list to appropriate Block class using registry maps.
    """
    b_type_val = data[0]
    try:
        b_type = BlockType(b_type_val)
    except ValueError:
        b_type = BlockType.UNKNOWN_BLOCK

    b_num = data[1]
    flags = BlockFlags(data[2])
    crc_type = CRCType(data[3])
    raw_data = data[4]

    handler = BLOCK_HANDLER_MAP.get(b_type, _structure_generic)

    # 2. Instantiate and Populate Data Field
    block = handler(raw_data)

    # 3. Populate Common Fields
    block.block_type = b_type
    block.block_number = b_num
    block.flags = flags
    block.crc_type = crc_type

    if crc_type != CRCType.NONE and len(data) > 5:
        block.crc = data[5]

    return block


converter.register_unstructure_hook(PrimaryBlock, unstructure_primary_block)
converter.register_structure_hook(PrimaryBlock, structure_primary_block)
converter.register_unstructure_hook(CanonicalBlock, unstructure_canonical_block)
converter.register_unstructure_hook(BlockIntegrityBlock, unstructure_security_block)
converter.register_structure_hook(CanonicalBlock, structure_canonical_block)
converter.register_structure_hook(PayloadBlock, structure_canonical_block)
converter.register_structure_hook(BlockIntegrityBlock, structure_canonical_block)
converter.register_unstructure_hook(SecurityParameter, unstructure_sec_param)
converter.register_structure_hook(SecurityParameter, structure_sec_param)
converter.register_unstructure_hook(SecurityParameter, unstructure_sec_result)
converter.register_structure_hook(SecurityParameter, structure_sec_result)
