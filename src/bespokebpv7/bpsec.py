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
 Title: Bundle Protocol Security Classes
 Author: Nate Richard
 Modified: 01/26/2026
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

from typing import Self

from attrs import define, field

from bespokebpv7.block_enum import (
    BIBParmEnum,
    BIBResultEnum,
    BIBSHAVariant,
    BlockType,
    IntegrityScopeFlags,
    SecurityContextFlags,
)
from bespokebpv7.blocks import CanonicalBlock
from bespokebpv7.utils import bundle_converter


def asb_flag_property(flag_bit: SecurityContextFlags) -> property:
    """Generate a property that gets/sets a bit in the instance's security
    context flags attribute.

    Returns:
        Property to get/set flag

    """

    def getter(self) -> bool:  # noqa: ANN001
        return bool(self.security_context_flags & flag_bit)

    def setter(self, value: bool) -> None:  # noqa: ANN001, FBT001
        if value:
            self.set_context_flag(flag_bit)
        else:
            self.clear_context_flag(flag_bit)

    return property(getter, setter)


def integrity_flag_property(flag_bit: IntegrityScopeFlags) -> property:
    """Generate a property that gets/sets a bit in the instance's integrity scope
    flags attribute.

    Returns:
        Property to get/set flag

    """

    def getter(self) -> bool:  # noqa: ANN001
        return bool(self.integrity_scope_flags & flag_bit)

    def setter(self, value: bool) -> None:  # noqa: ANN001, FBT001
        if value:
            self.set_scope_flag(flag_bit)
        else:
            self.clear_scope_flag(flag_bit)

    return property(getter, setter)


@define
class SecurityParameter:
    """Represents a single Security Context Parameter.
    Structure: [ Parameter ID, Parameter Value ]
    """

    parm_id: int
    value: bytes | int

    @classmethod
    def _structure(cls, data: list) -> Self:
        """Structure a SecurityParameter from a list.

        Returns:
            Populate Security Parameter

        """
        return cls(parm_id=data[0], value=data[1])

    def _unstructure(self) -> list:
        """Flatten class for cbor encoding.

        Returns:
            list of parameter id and parameter value.

        """
        return [self.parm_id, self.value]


@define
class SecurityResult:
    """Represents a single Security Result.
    Structure: [ Result ID, Result Value ]
    """

    result_id: int
    value: bytes

    @classmethod
    def _structure(cls, data: list) -> Self:
        """Structure a SecurityResult from a list [id, value].

        Returns:
            Populated Security Result

        """
        return cls(result_id=data[0], value=data[1])

    def _unstructure(self) -> list[int | bytes]:
        """Flatten class for cbor encoding.

        Returns:
            list of security result id and security result

        """
        return [self.result_id, self.value]


@define
class AbstractSecurityBlock(CanonicalBlock):
    """Represents the Abstract Security Block (ASB)."""

    security_targets: list[int] = field(factory=list)
    security_context_id: int = field(default=0)
    security_context_flags: SecurityContextFlags = field(
        default=SecurityContextFlags(0),
        converter=SecurityContextFlags,
    )
    security_source: list = field(factory=lambda: [1, "none"])
    security_parameters: list[SecurityParameter] = field(factory=list)
    security_results: list[SecurityResult] = field(factory=list)

    parm_present = asb_flag_property(SecurityContextFlags.CONTAIN_SECURITY_PARM)

    def set_context_flag(self, security_flag: SecurityContextFlags) -> None:
        """Set an individual security context flag."""
        self.security_context_flags |= int(security_flag)

    def clear_context_flag(self, security_flag: SecurityContextFlags) -> None:
        """Clear an individual security context flag."""
        self.security_context_flags &= ~int(security_flag)


@define
class BlockIntegrityBlock(AbstractSecurityBlock):
    """Block Integrity Block (BIB)."""

    block_type: BlockType = field(default=BlockType.BIB, converter=BlockType)
    security_context_id: int = field(default=1)
    integrity_scope_flags: IntegrityScopeFlags = field(
        default=IntegrityScopeFlags(7),
        converter=IntegrityScopeFlags,
    )

    include_primary_block = integrity_flag_property(
        IntegrityScopeFlags.INCLUDE_PRIMARY_BLOCK,
    )
    include_target_header = integrity_flag_property(
        IntegrityScopeFlags.INCLUDE_TARGET_HEADER,
    )
    include_security_header = integrity_flag_property(
        IntegrityScopeFlags.INCLUDE_SECURITY_HEADER,
    )

    def __attrs_post_init__(self) -> None:
        """Set security context flags are initiation."""
        self.security_context_flags = SecurityContextFlags(1)
        self.block_type = BlockType.BIB

    def set_sha_variant(self, variant: BIBSHAVariant | None = None) -> None:
        """Set SHA variant security parameter."""
        if not variant:
            variant = BIBSHAVariant.HMAC_384_384
        self.security_parameters.append(
            SecurityParameter(BIBParmEnum.SHA_VARIANT, variant),
        )
        self.parm_present = True

    def add_wrapped_key(self, key: bytes) -> None:
        """Set wrapped key security key."""
        self.security_parameters.append(SecurityParameter(BIBParmEnum.WRAPPED_KEY, key))
        self.parm_present = True

    def add_integrity_scope(self, val: int | None = None) -> None:
        """Store Integrity scope flags as a security parameter."""
        if not val:
            val = self.integrity_scope_flags
        self.security_parameters.append(
            SecurityParameter(BIBParmEnum.INTEGRITY_SCOPE_FLAGS, val),
        )
        self.parm_present = True

    def add_security_result(self, result: bytes) -> None:
        """Add expected HMAC result"""
        self.security_results.append(
            SecurityResult(BIBResultEnum.EXPECTED_HMAC, result),
        )

    def set_scope_flag(self, security_flag: IntegrityScopeFlags) -> None:
        """Set an individual integrity scope flag."""
        self.integrity_scope_flags |= int(security_flag)

    def clear_scope_flag(self, security_flag: IntegrityScopeFlags) -> None:
        """Clear an individual integrity scope flag."""
        self.integrity_scope_flags &= ~int(security_flag)

    @classmethod
    def _structure(cls, data: list) -> Self:
        """Structure a BIB from a CBOR list (extension block fields).

        Returns:
            Populated Block Integrity Block

        """
        # Parse the outer CanonicalBlock fields
        block = super()._structure(data)

        # Parse the inner security specific fields from the data bytes
        bib_data = bundle_converter.loads(block.data, list)

        block.security_targets = bib_data[0]
        block.security_context_id = bib_data[1]
        block.security_context_flags = SecurityContextFlags(bib_data[2])
        next_idx = 3

        if block.parm_present:  # pylint: disable=E1101
            for parm in bib_data[next_idx]:
                block.security_parameters.append(  # pylint: disable=E1101
                    bundle_converter.structure(parm, SecurityParameter)
                )
            next_idx += 1

        for result in bib_data[next_idx]:
            block.security_results.append(  # pylint: disable=E1101
                bundle_converter.structure(result, SecurityResult)
            )

        return block

    def _unstructure(self) -> list:
        """Unstructure the BIB into a CBOR list.

        Returns:
            Class as list

        """
        # Convert internal fields to the structure expected by RFC 9171
        data = [
            self.security_targets,
            self.security_context_id,
            int(self.security_context_flags),
        ]
        if self.parm_present:
            parm_list = [
                bundle_converter.unstructure(parm) for parm in self.security_parameters
            ]
            data.append(parm_list)

        result_list = [
            bundle_converter.unstructure(result) for result in self.security_results
        ]
        data.append(result_list)

        # Pack into the data field of the CanonicalBlock
        self.data = bundle_converter.dumps(data)

        # Return the outer block structure
        return super()._unstructure()
