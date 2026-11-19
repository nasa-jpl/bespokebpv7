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
from operator import index as _index

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
from bespokebpv7.bundle_params import EndpointID
from bespokebpv7.utils import (
    bundle_converter,
    decode_cbor_sequence,
    encode_cbor_sequence,
)

if sys.version_info >= (3, 11):
    from typing import Any, NamedTuple, Self
else:
    from typing import Any, NamedTuple

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


def _endpoint_id(value: Any) -> EndpointID:
    """Attrs converter: a URI string or decoded CBOR value to an EndpointID.

    Returns:
        The endpoint ID

    """
    return EndpointID.from_value(value)


@define
class AbstractSecurityBlock(CanonicalBlock):
    """Represents the Abstract Security Block (ASB)."""

    security_targets: list[int] = field(factory=list)
    security_context_id: int = field(default=0)
    security_context_flags: SecurityContextFlags = field(
        default=SecurityContextFlags(0),
        converter=SecurityContextFlags,
    )
    security_source: EndpointID = field(
        factory=lambda: EndpointID.from_value("dtn:none"),
        converter=_endpoint_id,
    )
    security_parameters: list[SecurityParameter] = field(factory=list)
    security_results: list[SecurityResult] = field(factory=list)

    parm_present = asb_flag_property(SecurityContextFlags.CONTAIN_SECURITY_PARM)

    def set_context_flag(self, security_flag: SecurityContextFlags) -> None:
        """Set an individual security context flag."""
        self.security_context_flags |= int(security_flag)

    def clear_context_flag(self, security_flag: SecurityContextFlags) -> None:
        """Clear an individual security context flag."""
        self.security_context_flags &= ~int(security_flag)


_SEC_DATA_MIN_FIELDS = 4
_SEC_DATA_WITHOUT_PARM = 5
_SEC_DATA_WITH_PARM = 6
_SEC_DATA_PARMS_INDEX = 4


def _validate_security_data_header(sec_data: Any, kind: str) -> int:
    """Validate the fixed prefix of the inner security data.

    Returns:
        int: the raw security context flags.

    Raises:
        ValueError: if the inner security data is malformed.

    """
    msg = f"{kind} security data is malformed"
    if not isinstance(sec_data, list) or len(sec_data) < _SEC_DATA_MIN_FIELDS:
        raise ValueError(msg)
    try:
        flags = _index(sec_data[2])
    except TypeError as err:
        raise ValueError(msg) from err
    parm_present = bool(flags & int(SecurityContextFlags.CONTAIN_SECURITY_PARM))
    required = _SEC_DATA_WITH_PARM if parm_present else _SEC_DATA_WITHOUT_PARM
    if len(sec_data) < required:
        raise ValueError(msg)
    return flags


class _ScopeRestoreConfig(NamedTuple):
    """Configuration for restoring the wire scope flags after decoding."""

    parm_id: BIBParmEnum | BCBParmEnum
    scope_enum: type[IntegrityScopeFlags] | type[AADScopeFlags]
    scope_attr: str


def _restore_scope_flags(
    block: AbstractSecurityBlock,
    config: _ScopeRestoreConfig,
    msg: str,
) -> None:
    """Restore the scope flags from the decoded scope parameter, if present.

    Raises:
        ValueError: if a scope parameter value is not an integer.

    """
    for parm in block.security_parameters:
        if parm.parm_id != config.parm_id:
            continue
        scope_operand: Any = parm.value
        try:
            scope_value = _index(scope_operand)
        except TypeError as err:
            raise ValueError(msg) from err
        setattr(block, config.scope_attr, config.scope_enum(scope_value))


def _structure_security_body(
    block: AbstractSecurityBlock,
    sec_data: Any,
    *,
    kind: str,
    scope_restore: _ScopeRestoreConfig,
) -> None:
    """Populate the inner security-specific fields of a BIB/BCB in place.

    A results slot of ``[[]]`` (one empty list) is accepted as an empty
    results set, yielding no SecurityResults; this keeps "no results" distinct
    from a malformed slot.

    Raises:
        ValueError: if the inner security data is malformed.

    """
    msg = f"{kind} security data is malformed"
    flags = _validate_security_data_header(sec_data, kind)
    try:
        block.security_targets = sec_data[0]
        block.security_context_id = sec_data[1]
        block.security_context_flags = SecurityContextFlags(flags)
        block.security_source = sec_data[3]
    except (IndexError, TypeError, KeyError) as err:
        raise ValueError(msg) from err
    next_idx = _SEC_DATA_PARMS_INDEX
    if block.parm_present:
        parm_items = sec_data[next_idx]
        if not isinstance(parm_items, list):
            raise ValueError(msg)
        try:
            for parm in parm_items:
                block.security_parameters.append(
                    bundle_converter.structure(parm, SecurityParameter),
                )
            next_idx += 1
            # Restore the wire scope so flag properties reflect the decoded block.
            _restore_scope_flags(block, scope_restore, msg)
        except (IndexError, TypeError, KeyError) as err:
            raise ValueError(msg) from err
    results_slot = sec_data[next_idx]
    if not (
        isinstance(results_slot, list)
        and results_slot
        and isinstance(results_slot[0], list)
    ):
        raise ValueError(msg)
    try:
        for result in results_slot[0]:
            block.security_results.append(
                bundle_converter.structure(result, SecurityResult),
            )
    except (IndexError, TypeError, KeyError) as err:
        raise ValueError(msg) from err


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

        Note: ``ValueError`` is raised (via ``_structure_security_body``) if the
        inner security data is malformed.

        """
        block = super()._structure(data)

        bib_data = decode_cbor_sequence(block.data)
        _structure_security_body(
            block,
            bib_data,
            kind="BIB",
            scope_restore=_ScopeRestoreConfig(
                parm_id=BIBParmEnum.INTEGRITY_SCOPE_FLAGS,
                scope_enum=IntegrityScopeFlags,
                scope_attr="integrity_scope_flags",
            ),
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
            self.security_source.to_cbor(),
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

        Note: ``ValueError`` is raised (via ``_structure_security_body``) if the
        inner security data is malformed.

        """
        block = super()._structure(data)

        bcb_data = decode_cbor_sequence(block.data)
        _structure_security_body(
            block,
            bcb_data,
            kind="BCB",
            scope_restore=_ScopeRestoreConfig(
                parm_id=BCBParmEnum.AAD_SCOPE_FLAGS,
                scope_enum=AADScopeFlags,
                scope_attr="aad_scope_flags",
            ),
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
            self.security_source.to_cbor(),
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
