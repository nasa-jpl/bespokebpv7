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

from dataclasses import dataclass, field
from typing import Union, List

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
    value: Union[bytes, int]


@dataclass
class SecurityResult:
    """
    Represents a single Security Result.
    Structure: [ Result ID, Result Value ]
    """
    result_id: int
    value: bytes


@dataclass
class AbstractSecurityBlock(CanonicalBlock):
    """
    Represents the Abstract Security Block (ASB) defined in RFC 9172.
    """
    # 1. Security Targets
    security_targets: List[int] = field(default_factory=list)

    # 2. Security Context ID
    security_context_id: int = 0

    # 3. Security Context Flags
    _security_context_flags: SecurityContextFlags = SecurityContextFlags(0)

    # 4. Security Source
    security_source: List = field(default_factory=lambda: [1, "none"])

    # 5. Security Parameters
    security_parameters: List[SecurityParameter] = field(default_factory=list)

    # 6. Security Results
    security_results: List[SecurityResult] = field(default_factory=list)

    def set_context_flag(
        self,
        security_flag: SecurityContextFlags,
        state=True,
    ) -> None:
        """Sets or clears an individual security context flag."""
        if state:
            self._security_context_flags |= int(security_flag)
        else:
            self._security_context_flags &= ~int(security_flag)

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
        return bool(
            self._security_context_flags & SecurityContextFlags.CONTAIN_SECURITY_PARM
        )

    @parm_present_fragment.setter
    def parm_present_fragment(self, value: bool):
        self.set_context_flag(SecurityContextFlags.CONTAIN_SECURITY_PARM, value)


@dataclass
class BlockIntegrityBlock(AbstractSecurityBlock):
    """
    Block Integrity Block (BIB) as defined in RFC 9173.
    """
    _block_type: BlockType = BlockType.BIB
    security_context_id: int = 1
    _integrity_scope_flags: IntegrityScopeFlags = IntegrityScopeFlags(7)

    def __post_init__(self):
        # Set default flags
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
            self._integrity_scope_flags |= int(security_flag)
        else:
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
        return bool(self._integrity_scope_flags & IntegrityScopeFlags.INCLUDE_PRIMARY_BLOCK)

    @include_primary_block.setter
    def include_primary_block(self, value: bool):
        self.set_scope_flag(IntegrityScopeFlags.INCLUDE_PRIMARY_BLOCK, value)

    @property
    def include_target_header(self) -> bool:
        """Return whether to include target header"""
        return bool(self._integrity_scope_flags & IntegrityScopeFlags.INCLUDE_TARGET_HEADER)

    @include_target_header.setter
    def include_target_header(self, value: bool):
        self.set_scope_flag(IntegrityScopeFlags.INCLUDE_TARGET_HEADER, value)

    @property
    def include_security_header(self) -> bool:
        """Return whether to include security header"""
        return bool(self._integrity_scope_flags & IntegrityScopeFlags.INCLUDE_SECURITY_HEADER)

    @include_security_header.setter
    def include_security_header(self, value: bool):
        self.set_scope_flag(IntegrityScopeFlags.INCLUDE_SECURITY_HEADER, value)
