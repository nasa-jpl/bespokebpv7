# Security API Reference

Classes for creating and processing Bundle Protocol Security
(BPSec) extension blocks.

## Security Workflow

`bespokebpv7` builds and parses BPSec blocks, but it does not run the
cryptography. You compute the HMAC or authentication tag yourself, then
store it in the block as a security result. This keeps full control over
the bytes for V&V testing, including deliberately wrong results.

The sequence for a Block Integrity Block (BIB) is:

1. Build the bundle's primary block.
2. Compute the security result over the target block.
3. Create the `BlockIntegrityBlock`: set its targets and source, then
   add each `SecurityParameter` (SHA variant, integrity scope flags) and
   the `SecurityResult`.
4. Add the BIB to the `BPv7` bundle, followed by the payload block so the
   payload stays last.

The example below reproduces
[RFC 9173 Appendix A.1](https://www.rfc-editor.org/rfc/rfc9173#appendix-A.1)
(an HMAC-SHA-512 BIB over the payload block). The serialized bundle is
byte-for-byte identical to the one in the RFC.

```python
import hashlib
import hmac

import cbor2

from bespokebpv7 import BlockType, BPv7
from bespokebpv7.block_enum import BIBSHAVariant, IntegrityScopeFlags
from bespokebpv7.bpsec import BlockIntegrityBlock

key = bytes.fromhex("1a2b1a2b1a2b1a2b1a2b1a2b1a2b1a2b")
payload = b"Ready to generate a 32-byte payload"

# 1. Primary block: ipn:2.1 -> ipn:1.2, creation time 0, sequence 40
bundle = BPv7()
bundle.primary_block.route.dest_eid = "ipn:1.2"
bundle.primary_block.route.source_eid = "ipn:2.1"
bundle.primary_block.route.report_to = "ipn:2.1"
bundle.primary_block.life.timestamp_ms = 0
bundle.primary_block.life.sequence = 40
bundle.primary_block.life.lifetime = 1000000

# 2. Integrity-protected plaintext (RFC 9173 Section 3.7) with no
#    additional scope: the CBOR-encoded scope flags followed by the
#    target block's CBOR-encoded block-type-specific data.
scope = IntegrityScopeFlags(0)
ippt = cbor2.dumps(int(scope)) + cbor2.dumps(payload)
mac = hmac.new(key, ippt, hashlib.sha512).digest()

# 3. BIB targeting the payload block (block number 1)
bib = BlockIntegrityBlock(block_number=2)
bib.security_targets = [1]
bib.security_source = [2, [2, 1]]  # ipn:2.1, CBOR form written as-is
bib.set_sha_variant(BIBSHAVariant.HMAC_512_512)
bib.integrity_scope_flags = scope
bib.add_integrity_scope()
bib.add_security_result(mac)

# 4. BIB first, then the payload block
bundle.blocks[BlockType.BIB] = bib
bundle.add_payload_block(payload)

serialized = bytes(bundle)
```

When a scope flag is set, the IPPT also includes the primary block, the
target block header or the security block header, as listed in RFC 9173
Section 3.7. To check a received BIB, rebuild the IPPT from the parsed
bundle, compute the HMAC with the shared key and compare it with
`bib.security_results[0].value` using `hmac.compare_digest`.

A Block Confidentiality Block (BCB) follows the same steps with
`BlockConfidentialityBlock`. Add the initialization vector as
`SecurityParameter(BCBParmEnum.IV, iv)` (RFC 9173 requires it; there is
no helper method), then `set_aes_variant()` and `add_aad_scope()`, and
store the AES-GCM authentication tag with `add_security_result()`. The
target block's data must also be replaced with the ciphertext.

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
