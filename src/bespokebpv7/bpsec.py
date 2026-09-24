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
 Modified: 01/27/2026
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

import sys

from attrs import define, field

from bespokebpv7.block_enum import (
    AADScopeFlags,
    BCBAESVariant,
    BCBParmEnum,
    BCBResultEnum,
    BIBParmEnum,
    BIBResultEnum,
    BIBSHAVariant,
    BlockType,
    IntegrityScopeFlags,
    SecurityContextFlags,
)
from bespokebpv7.blocks import CanonicalBlock
from bespokebpv7.utils import (
    bundle_converter,
    decode_cbor_sequence,
    encode_cbor_sequence,
)

if sys.version_info >= (3, 11):
    from typing import Any, Self
else:
    from typing import Any

    from typing_extensions import Self


def asb_flag_property(flag_bit: SecurityContextFlags) -> property:
    """Generate a property that gets/sets a bit in the instance's security
    context flags attribute.

    Returns:
        Property to get/set flag

    """

    def getter(self: "AbstractSecurityBlock") -> bool:
        return bool(self.security_context_flags & flag_bit)

    def setter(self: "AbstractSecurityBlock", value: bool) -> None:  # ruff: ignore[boolean-type-hint-positional-argument]
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

    def getter(self: "BlockIntegrityBlock") -> bool:
        return bool(self.integrity_scope_flags & flag_bit)

    def setter(self: "BlockIntegrityBlock", value: bool) -> None:  # ruff: ignore[boolean-type-hint-positional-argument]
        if value:
            self.set_scope_flag(flag_bit)
        else:
            self.clear_scope_flag(flag_bit)

    return property(getter, setter)


def aad_flag_property(flag_bit: AADScopeFlags) -> property:
    """Generate a property that gets/sets a bit in the instance's AAD scope
    flags attribute.

    Returns:
        Property to get/set flag

    """

    def getter(self: "BlockConfidentialityBlock") -> bool:
        return bool(self.aad_scope_flags & flag_bit)

    def setter(self: "BlockConfidentialityBlock", value: bool) -> None:  # ruff: ignore[boolean-type-hint-positional-argument]
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
    def _structure(cls, data: list[Any]) -> Self:
        """Structure a SecurityParameter from a list.

        Returns:
            Populate Security Parameter

        """
        return cls(parm_id=data[0], value=data[1])

    def _unstructure(self) -> list[Any]:
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
    def _structure(cls, data: list[Any]) -> Self:
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
    security_source: list[Any] = field(factory=lambda: [1, "none"])
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
        if val is None:
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
    def _structure(cls, data: list[Any]) -> Self:
        """Structure a BIB from a CBOR list (extension block fields).

        Returns:
            Populated Block Integrity Block

        """
        # Parse the outer CanonicalBlock fields
        block = super()._structure(data)

        # Parse the inner security specific fields from the data bytes
        bib_data = decode_cbor_sequence(block.data)

        block.security_targets = bib_data[0]
        block.security_context_id = bib_data[1]
        block.security_context_flags = SecurityContextFlags(bib_data[2])
        block.security_source = bib_data[3]
        next_idx = 4

        if block.parm_present:
            for parm in bib_data[next_idx]:
                block.security_parameters.append(
                    bundle_converter.structure(parm, SecurityParameter)
                )
            next_idx += 1

        for result in bib_data[next_idx][0]:
            block.security_results.append(
                bundle_converter.structure(result, SecurityResult)
            )

        return block

    def _unstructure(self) -> list[Any]:
        """Unstructure the BIB into a CBOR list.

        Returns:
            Class as list

        """
        # Convert internal fields to the structure expected by RFC 9171
        data = [
            self.security_targets,
            self.security_context_id,
            int(self.security_context_flags),
            self.security_source,
        ]
        if self.parm_present:
            parm_list = [
                bundle_converter.unstructure(parm) for parm in self.security_parameters
            ]
            data.append(parm_list)

        result_list = [
            bundle_converter.unstructure(result) for result in self.security_results
        ]
        data.append([result_list])

        # Pack into the data field of the CanonicalBlock
        self.data = encode_cbor_sequence(data)

        # Return the outer block structure
        return super()._unstructure()


@define
class BlockConfidentialityBlock(AbstractSecurityBlock):
    """Block Confidentiality Block (BCB)."""

    block_type: BlockType = field(default=BlockType.BCB, converter=BlockType)
    security_context_id: int = field(default=2)
    aad_scope_flags: AADScopeFlags = field(
        default=AADScopeFlags(7),
        converter=AADScopeFlags,
    )

    include_primary_block = aad_flag_property(
        AADScopeFlags.INCLUDE_PRIMARY_BLOCK,
    )
    include_target_header = aad_flag_property(
        AADScopeFlags.INCLUDE_TARGET_HEADER,
    )
    include_security_header = aad_flag_property(
        AADScopeFlags.INCLUDE_SECURITY_HEADER,
    )

    def __attrs_post_init__(self) -> None:
        """Set security context flags and AAD scope flags at initialization."""
        self.security_context_flags = SecurityContextFlags(1)
        self.aad_scope_flags = AADScopeFlags(7)
        self.block_type = BlockType.BCB

    def set_aes_variant(self, variant: BCBAESVariant | None = None) -> None:
        """Set AES-GCM variant security parameter."""
        if not variant:
            variant = BCBAESVariant.AES_GCM_256
        self.security_parameters.append(
            SecurityParameter(BCBParmEnum.AES_VARIANT, variant),
        )
        self.parm_present = True

    def add_wrapped_key(self, key: bytes) -> None:
        """Set wrapped key security parameter."""
        self.security_parameters.append(SecurityParameter(BCBParmEnum.WRAPPED_KEY, key))
        self.parm_present = True

    def add_aad_scope(self, val: int | None = None) -> None:
        """Store AAD scope flags as a security parameter."""
        if val is None:
            val = self.aad_scope_flags
        self.security_parameters.append(
            SecurityParameter(BCBParmEnum.AAD_SCOPE_FLAGS, val),
        )
        self.parm_present = True

    def add_security_result(self, result: bytes) -> None:
        """Add authentication tag result"""
        self.security_results.append(
            SecurityResult(BCBResultEnum.AUTH_TAG, result),
        )

    def set_scope_flag(self, security_flag: AADScopeFlags) -> None:
        """Set an individual AAD scope flag."""
        self.aad_scope_flags |= int(security_flag)

    def clear_scope_flag(self, security_flag: AADScopeFlags) -> None:
        """Clear an individual AAD scope flag."""
        self.aad_scope_flags &= ~int(security_flag)

    @classmethod
    def _structure(cls, data: list[Any]) -> Self:
        """Structure a BCB from a CBOR list (extension block fields).

        Returns:
            Populated Block Confidentiality Block

        """
        # Parse the outer CanonicalBlock fields
        block = super()._structure(data)

        # Parse the inner security specific fields from the data bytes
        bcb_data = decode_cbor_sequence(block.data)

        block.security_targets = bcb_data[0]
        block.security_context_id = bcb_data[1]
        block.security_context_flags = SecurityContextFlags(bcb_data[2])
        block.security_source = bcb_data[3]
        next_idx = 4

        if block.parm_present:
            for parm in bcb_data[next_idx]:
                block.security_parameters.append(
                    bundle_converter.structure(parm, SecurityParameter)
                )
            next_idx += 1

        for result in bcb_data[next_idx][0]:
            block.security_results.append(
                bundle_converter.structure(result, SecurityResult)
            )

        return block

    def _unstructure(self) -> list[Any]:
        """Unstructure the BCB into a CBOR list.

        Returns:
            Class as list

        """
        # Convert internal fields to the structure expected by RFC 9173
        data = [
            self.security_targets,
            self.security_context_id,
            int(self.security_context_flags),
            self.security_source,
        ]
        if self.parm_present:
            parm_list = [
                bundle_converter.unstructure(parm) for parm in self.security_parameters
            ]
            data.append(parm_list)

        result_list = [
            bundle_converter.unstructure(result) for result in self.security_results
        ]
        data.append([result_list])

        # Pack into the data field of the CanonicalBlock
        self.data = encode_cbor_sequence(data)

        # Return the outer block structure
        return super()._unstructure()
