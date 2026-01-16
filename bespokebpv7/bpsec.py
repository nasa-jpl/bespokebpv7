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
 Title: Bundle Protocol Security Classes
 Author: Nate Richard
 Modified: 01/15/2026
 Company: JPL
 Date:   12/19/2025

 File: bpsec
 Description:
           Classes that help create and process BPSec extension blocks
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

from typing import Union

from attrs import define, field
from cattrs.preconf.cbor2 import make_converter
from cattrs.strategies import use_class_methods
import cbor2

from bespokebpv7.block_enum import (
    BlockFlags,
    BIBParmEnum,
    BIBResultEnum,
    BIBSHAVariant,
    BlockType,
    CRCType,
    IntegrityScopeFlags,
    SecurityContextFlags,
)
from bespokebpv7.blocks import CanonicalBlock


def asb_flag_property(flag_bit):
    """
    Generates a property that gets/sets a bit in the instance's security
    context flags attribute.
    """

    def getter(self):
        return bool(self.security_context_flags & flag_bit)

    def setter(self, value: bool):
        self.set_context_flag(flag_bit, value)

    return property(getter, setter)


def integrity_flag_property(flag_bit):
    """
    Generates a property that gets/sets a bit in the instance's integrity scope
    flags attribute.
    """

    def getter(self):
        return bool(self.integrity_scope_flags & flag_bit)

    def setter(self, value: bool):
        self.set_scope_flag(flag_bit, value)

    return property(getter, setter)


@define
class SecurityParameter:
    """
    Represents a single Security Context Parameter.
    Structure: [ Parameter ID, Parameter Value ]
    """

    parm_id: int
    value: Union[bytes, int]

    def unstructure(self):
        """Flatten class for cbor encoding"""
        return [self.parm_id, self.value]


@define
class SecurityResult:
    """
    Represents a single Security Result.
    Structure: [ Result ID, Result Value ]
    """

    result_id: int
    value: bytes

    def unstructure(self):
        """Flatten class for cbor encoding"""
        return [self.result_id, self.value]


@define
class AbstractSecurityBlock(CanonicalBlock):
    """
    Represents the Abstract Security Block (ASB).
    """

    security_targets: list[int] = field(factory=list)
    security_context_id: int = field(default=0)
    security_context_flags: SecurityContextFlags = field(
        default=SecurityContextFlags(0), converter=SecurityContextFlags
    )
    security_source: list = field(factory=lambda: [1, "none"])
    security_parameters: list[SecurityParameter] = field(factory=list)
    security_results: list[SecurityResult] = field(factory=list)

    parm_present = asb_flag_property(SecurityContextFlags.CONTAIN_SECURITY_PARM)

    def set_context_flag(
        self,
        security_flag: SecurityContextFlags,
        state=True,
    ) -> None:
        """Sets or clears an individual security context flag."""
        if state:
            self.security_context_flags |= int(security_flag)
        else:
            self.security_context_flags &= ~int(security_flag)


@define
class BlockIntegrityBlock(AbstractSecurityBlock):
    """
    Block Integrity Block (BIB).
    """

    block_type: BlockType = field(default=BlockType.BIB, converter=BlockType)
    security_context_id: int = field(default=1)
    integrity_scope_flags: IntegrityScopeFlags = field(
        default=IntegrityScopeFlags(7), converter=IntegrityScopeFlags
    )

    include_primary_block = integrity_flag_property(
        IntegrityScopeFlags.INCLUDE_PRIMARY_BLOCK
    )
    include_target_header = integrity_flag_property(
        IntegrityScopeFlags.INCLUDE_TARGET_HEADER
    )
    include_security_header = integrity_flag_property(
        IntegrityScopeFlags.INCLUDE_SECURITY_HEADER
    )

    def __attrs_post_init__(self):
        self.security_context_flags = SecurityContextFlags(1)

    def set_sha_variant(self, variant: BIBSHAVariant) -> None:
        """Set SHA variant security parameter."""
        self.security_parameters.append(
            SecurityParameter(BIBParmEnum.SHA_VARIANT, variant)
        )

    def add_wrapped_key(self, key: bytes):
        """Set wrapped key security key."""
        self.security_parameters.append(SecurityParameter(BIBParmEnum.WRAPPED_KEY, key))

    def add_integrity_scope(self, val: Union[int, None] = None):
        """Stores Integrity scope flags as a security parameter."""
        if not val:
            val = self.integrity_scope_flags
        self.security_parameters.append(
            SecurityParameter(BIBParmEnum.INTEGRITY_SCOPE_FLAGS, val)
        )

    def add_security_result(self, result: bytes):
        """Add expected HMAC result"""
        self.security_results.append(
            SecurityResult(BIBResultEnum.EXPECTED_HMAC, result)
        )

    def set_scope_flag(self, security_flag: IntegrityScopeFlags, state=True) -> None:
        """Sets or clears an individual security context flag."""
        if state:
            self.integrity_scope_flags |= int(security_flag)
        else:
            self.integrity_scope_flags &= ~int(security_flag)

    @classmethod
    def _structure(cls, data: list) -> "BlockIntegrityBlock":
        """BIB structure method."""
        block = cls()
        block.block_type = BlockType(data[0])
        block.block_number = data[1]
        block.flags = BlockFlags(data[2])
        block.crc_type = CRCType(data[3])
        block.data = data[4]
        bib_data = cbor2.loads(data[4])

        block.security_targets = bib_data[0]
        block.security_context_id = bib_data[1]
        block.security_context_flags = bib_data[2]
        next_idx = 3

        if block.parm_present:
            for parm in bib_data[next_idx]:
                block.security_parameters.append(SecurityParameter(parm[0], parm[1]))
            next_idx += 1

        for result in bib_data[next_idx]:
            block.security_results.append(SecurityResult(result[0], result[1]))

        if len(data) > 5:
            block.crc = data[5]
        else:
            block.crc = CRCType.NONE.fill_value

        return block

    def _unstructure(self) -> list:
        """BIB unstructure method."""
        out: list[Union[int, bytes]] = [
            int(self.block_type),
            self.block_number,
            int(self.flags),
            int(self.crc_type),
        ]

        data = [
            self.security_targets,
            self.security_context_id,
            int(self.security_context_flags),
        ]
        if self.parm_present:
            parm_list = [parm.unstructure() for parm in self.security_parameters]
            data.append(parm_list)

        result_list = [result.unstructure() for result in self.security_results]
        data.append(result_list)
        out.append(cbor2.dumps(data))

        if self.crc_type != CRCType.NONE and self.crc:
            out.append(self.crc)

        return out


bpsec_converter = make_converter()
use_class_methods(bpsec_converter, "_structure", "_unstructure")
