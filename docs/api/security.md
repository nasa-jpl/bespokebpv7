# Security API Reference

Classes for creating and processing Bundle Protocol Security
(BPSec) extension blocks.

## Classes

### `SecurityParameter`

Represents a single Security Context Parameter.
Structure: `[ Parameter ID, Parameter Value ]`.

**Attributes:**

- `parm_id` (`int`): The parameter identifier.
- `value` (`bytes | int`): The parameter value.

**Methods:**

- `_structure(cls, data: list[Any]) -> Self`: Structure a
  `SecurityParameter` from a list.
- `_unstructure(self) -> list[Any]`: Flatten class for CBOR encoding.

---

### `SecurityResult`

Represents a single Security Result. Structure: `[ Result ID, Result Value ]`.

**Attributes:**

- `result_id` (`int`): The result identifier.
- `value` (`bytes`): The result value.

**Methods:**

- `_structure(cls, data: list[Any]) -> Self`: Structure a `SecurityResult`
  from a list `[id, value]`.
- `_unstructure(self) -> list[int | bytes]`: Flatten class for CBOR encoding.

---

### `AbstractSecurityBlock`

Represents the Abstract Security Block (ASB). Inherits from `CanonicalBlock`.

**Attributes:**

- `security_targets` (`list[int]`): List of security targets.
- `security_context_id` (`int`): Security context identifier. Defaults to `0`.
- `security_context_flags` (`SecurityContextFlags`): Security context flags.
- `security_source` (`list[Any]`): Security source. Defaults to `[1, "none"]`.
- `security_parameters` (`list[SecurityParameter]`): List of security
  parameters.
- `security_results` (`list[SecurityResult]`): List of security results.
- `parm_present` (`bool`, property): Indicates if security parameters are present.

**Methods:**

- `set_context_flag(self, security_flag: SecurityContextFlags) -> None`:
  Set an individual security context flag.
- `clear_context_flag(self, security_flag: SecurityContextFlags) -> None`:
  Clear an individual security context flag.

---

### `BlockIntegrityBlock`

Block Integrity Block (BIB). Inherits from `AbstractSecurityBlock`.

**Attributes:**

- `block_type` (`BlockType`): Block type. Defaults to `BlockType.BIB`.
- `security_context_id` (`int`): Security context identifier. Defaults to `1`.
- `integrity_scope_flags` (`IntegrityScopeFlags`): Integrity scope flags.
  Defaults to `IntegrityScopeFlags(7)`.
- `include_primary_block` (`bool`, property): Whether to include the
  primary block in the integrity scope.
- `include_target_header` (`bool`, property): Whether to include the target
  header in the integrity scope.
- `include_security_header` (`bool`, property): Whether to include the
  security header in the integrity scope.

**Methods:**

- `set_sha_variant(self, variant: BIBSHAVariant | None = None) -> None`:
  Set SHA variant security parameter.
- `add_wrapped_key(self, key: bytes) -> None`: Set wrapped key security
  parameter.
- `add_integrity_scope(self, val: int | None = None) -> None`: Store integrity
  scope flags as a security parameter.
- `add_security_result(self, result: bytes) -> None`: Add expected HMAC result.
- `set_scope_flag(self, security_flag: IntegrityScopeFlags) -> None`:
  Set an individual integrity scope flag.
- `clear_scope_flag(self, security_flag: IntegrityScopeFlags) -> None`:
  Clear an individual integrity scope flag.
- `_structure(cls, data: list[Any]) -> Self`: Structure a BIB from a CBOR list.
- `_unstructure(self) -> list[Any]`: Unstructure the BIB into a CBOR list.

---

### `BlockConfidentialityBlock`

Block Confidentiality Block (BCB). Inherits from `AbstractSecurityBlock`.

**Attributes:**

- `block_type` (`BlockType`): Block type. Defaults to `BlockType.BCB`.
- `security_context_id` (`int`): Security context identifier. Defaults to `2`.
- `aad_scope_flags` (`AADScopeFlags`): AAD scope flags. Defaults to
  `AADScopeFlags(7)`.
- `include_primary_block` (`bool`, property): Whether to include the primary
  block in the AAD scope.
- `include_target_header` (`bool`, property): Whether to include the target
  header in the AAD scope.
- `include_security_header` (`bool`, property): Whether to include the
  security header in the AAD scope.

**Methods:**

- `set_aes_variant(self, variant: BCBAESVariant | None = None) -> None`:
  Set AES-GCM variant security parameter.
- `add_wrapped_key(self, key: bytes) -> None`: Set wrapped key security parameter.
- `add_aad_scope(self, val: int | None = None) -> None`:
  Store AAD scope flags as a security parameter.
- `add_security_result(self, result: bytes) -> None`: Add authentication tag result.
- `set_scope_flag(self, security_flag: AADScopeFlags) -> None`:
  Set an individual AAD scope flag.
- `clear_scope_flag(self, security_flag: AADScopeFlags) -> None`:
  Clear an individual AAD scope flag.
- `_structure(cls, data: list[Any]) -> Self`: Structure a BCB from a CBOR list.
- `_unstructure(self) -> list[Any]`: Unstructure the BCB into a CBOR list.
