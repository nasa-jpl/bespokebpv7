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
 Modified: 01/14/2026
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

from dataclasses import dataclass, field
from typing import Any, Union

import cbor2

from bespokebpv7.block_enum import (
    BIBParmEnum,
    BIBResultEnum,
    BIBSHAVariant,
    BlockType,
    IntegrityScopeFlags,
    SecurityContextFlags,
)
from bespokebpv7.blocks import CanonicalBlock


@dataclass
class SecurityParameter:
    """
    Represents a single Security Context Parameter.
    Structure: [ Parameter ID, Parameter Value ]
    """

    parm_id: int
    value: Any  # Value type depends on the Security Context (CBOR encoded)


@dataclass
class SecurityResult:
    """
    Represents a single Security Result.
    Structure: [ Result ID, Result Value ]
    """

    result_id: int
    value: Any  # Value type depends on the Security Context (CBOR encoded)


@dataclass
class AbstractSecurityBlock(CanonicalBlock):
    """
    Represents the Abstract Security Block (ASB) defined in RFC 9172 Section 3.6.

    The ASB is not a standalone block but defines the structure of the
    'block-type-specific-data' field for BIB (Block Integrity Block) and
    BCB (Block Confidentiality Block).

    The presence of optional security parameters is determined by the
    `security_context_flags`.
    """

    # 1. Security Targets: List of Block Numbers (Unsigned Integers)
    # Identifies the blocks within the bundle that this security service applies to.
    _security_targets: list[int] = field(default_factory=list[int])

    # 2. Security Context ID: Unsigned Integer
    # Identifies the security context (algorithm/service) used (e.g., HMAC-SHA256).
    security_context_id: int = 0

    # 3. Security Context Flags: Unsigned Integer (Bitfield)
    # Controls the processing and presence of optional fields.
    _security_context_flags: SecurityContextFlags = SecurityContextFlags(0)

    # 4. Security Source: Endpoint ID (Optional)
    # Present if 'Security Source Present' flag (0x02) is set.
    # Represents the node that inserted this security block.
    security_source: list = field(default_factory=lambda: [1, "none"])

    # 5. Security Parameters: List of Parameters (Optional)
    # Present if 'Security Parameters Present' flag (0x01) is set.
    # Configuration data required by the security context.
    security_parameters: list[SecurityParameter] = field(default_factory=list)

    # 6. Security Results: List of Results (Optional)
    # Present if 'Security Results Present' flag (0x04) is set.
    # The output of the security operation (e.g., signatures, auth tags).
    security_results: list[SecurityResult] = field(default_factory=list)

    def set_data(self) -> None:
        """Sets defined security data as block specific data."""
        security_data = []
        for name, val in self.__dict__.items():
            if "security" in name:
                security_data.append(val)

        self.data = cbor2.dumps(security_data)

    def set_context_flag(
        self,
        security_flag: SecurityContextFlags,
        state=True,
    ) -> None:
        """Sets or clears an individual security context flag."""
        if state:
            # Bitwise OR to set the bit
            self._security_context_flags |= int(security_flag)
        else:
            # Bitwise AND with inverted mask to clear the bit
            self._security_context_flags &= ~int(security_flag)

    @property
    def security_targets(self) -> list:
        """Return list of block numbers that are security targets"""
        return self._security_targets

    @security_targets.setter
    def security_targets(self, value: int) -> None:
        self._security_targets.append(value)

    @property
    def security_context_flags(self) -> SecurityContextFlags:
        """Returns flags as set for block."""
        return self._security_context_flags

    @security_context_flags.setter
    def security_context_flags(self, value: SecurityContextFlags) -> None:
        self._security_context_flags = value

    @property
    def parm_present_fragment(self) -> bool:
        """Return whether the security block has security context parameters."""
        return bool(self._security_context_flags & SecurityContextFlags.CONTAIN_SECURITY_PARM)

    @parm_present_fragment.setter
    def parm_present_fragment(self, value: bool):
        self.set_context_flag(SecurityContextFlags.CONTAIN_SECURITY_PARM, value)


@dataclass
class BlockIntegrityBlock(AbstractSecurityBlock):
    """
    Block Integrity Block (BIB) as defined in RFC 9173.

    The BIB is an instantiation of the Abstract Security Block (ASB)
    with Block Type Code 11. It provides data integrity services
    for the target blocks.
    """

    _block_type: BlockType = BlockType.BIB
    security_context_id: int = 1
    _integrity_scope_flags: IntegrityScopeFlags = IntegrityScopeFlags(7)

    def __post_init__(self):
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

    def set_scope_flag(
        self,
        security_flag: IntegrityScopeFlags,
        state=True,
    ) -> None:
        """Sets or clears an individual security context flag."""
        if state:
            # Bitwise OR to set the bit
            self._integrity_scope_flags |= int(security_flag)
        else:
            # Bitwise AND with inverted mask to clear the bit
            self._integrity_scope_flags &= ~int(security_flag)

    @property
    def integrity_scope_flags(self) -> IntegrityScopeFlags:
        """Returns flags as set for block."""
        return self._integrity_scope_flags

    @integrity_scope_flags.setter
    def integrity_scope_flags(self, value: int) -> None:
        self._integrity_scope_flags = IntegrityScopeFlags(value)

    @property
    def include_primary_block(self) -> bool:
        """Return whether to include primary block"""
        return bool(self.flags & IntegrityScopeFlags.INCLUDE_PRIMARY_BLOCK)

    @include_primary_block.setter
    def include_primary_block(self, value: bool):
        self.set_scope_flag(IntegrityScopeFlags.INCLUDE_PRIMARY_BLOCK, value)

    @property
    def include_target_header(self) -> bool:
        """Return whether to include target header"""
        return bool(self.flags & IntegrityScopeFlags.INCLUDE_TARGET_HEADER)

    @include_target_header.setter
    def include_target_header(self, value: bool):
        self.set_scope_flag(IntegrityScopeFlags.INCLUDE_TARGET_HEADER, value)

    @property
    def include_security_header(self) -> bool:
        """Return whether to include security header"""
        return bool(self.flags & IntegrityScopeFlags.INCLUDE_SECURITY_HEADER)

    @include_security_header.setter
    def include_security_header(self, value: bool):
        self.set_scope_flag(IntegrityScopeFlags.INCLUDE_SECURITY_HEADER, value)
