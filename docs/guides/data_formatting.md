# EID Data Formatting

This guide provides a deep dive into how Endpoint Identifiers (EIDs) are
formatted and represented within the `bespokebpv7` library.

## Overview

An EID (Endpoint Identifier) is used in BPv7 to identify the source,
destination, and report-to endpoints of a bundle. In the wire format, EIDs
are stored as CBOR arrays. To make them human-readable, the library provides
utilities to convert between URI strings and these internal CBOR
representations.

## EID String Formats

The library supports two primary EID schemes: the **IPN (Interplanetary
Networking)** scheme and the **DTN** scheme.

### IPN Scheme

The IPN scheme is commonly used in DTN implementations for space
applications (like ION). It typically follows the format:
`ipn:allocator.node.service`

- **Allocator**: A 32-bit integer identifying the authority that assigned
  the node number. The Default Allocator is `0`.
- **Node**: A 32-bit integer identifying the specific node. The symbol `!`
  is used to represent the local node (`2^32 - 1`).
- **Service**: A 32-bit integer identifying the specific service on that node.

**Example:** `"ipn:2.1"` (where `2` is the node and `1` is the service,
using the Default Allocator).

### DTN Scheme

The DTN scheme is a more general URI-based scheme. It typically follows
the format:
`dtn://example/path` or simply `dtn:name`.

**Example:** `"dtn://example/path"`

---

## Internal CBOR Representation

Internally, `bespokebpv7` represents EIDs as CBOR arrays consisting of a
scheme code and a scheme-specific part (SSP).

**General Format:** `[scheme_code, scheme_specific_part]`

| Scheme | Scheme Code (`SchemeCode`) | Internal Representation Example | String Representation |
| :--- | :---: | :--- | :--- |
| **DTN** | `1` | `[1, "//example/path"]` | `"dtn://example/path"` |
| **IPN** | `2` | `[2, [0, 2, 1]]` | `"ipn:2.1"` |

### IPN Internal Structure

For the IPN scheme, the scheme-specific part is itself a list:
`[allocator, node, service]`.

- `"ipn:2.1"` $\rightarrow$ `[2, [0, 2, 1]]` (Default allocator `0` is
  explicitly stored in the full list).
- Note: Some legacy implementations may pack the allocator and node into a
  single 64-bit "Fully Qualified Node Name" (FQNN), but the recommended BPv7
  format uses the 3-element list.

---

## Utility Functions

The following functions in `src/bespokebpv7/utils.py` handle the conversion
between string and internal formats.

### `parse_eid_string(eid_str)`

Converts a human-readable EID string into the internal CBOR list format.

- **Input**: A string (e.g., `"ipn:2.1"`) or an existing list.
- **Output**: A list `[scheme_code, ssp]`.
- **Behavior**:
  - If the string contains `:`, it splits the scheme from the rest.
  - If the scheme is `ipn`, it parses the allocator, node, and service.
  - Otherwise, it defaults to the `dtn` scheme.

### `format_eid(eid)`

Converts an internal CBOR list back into a human-readable URI string.

- **Input**: A list `[scheme_code, ssp]`.
- **Output**: A string (e.g., `"ipn:2.1"`).
- **Behavior**:
  - For `SchemeCode.IPN`, it reconstructs the `ipn:allocator.node.service`
    string. If the allocator is `0`, it is omitted from the resulting string
    for brevity.
  - For `SchemeCode.DTN`, it returns `dtn:ssp`.

---

## Standard Reference

For detailed specifications on EID formats and the Bundle Protocol version 7,
refer to **[RFC 9171](https://datatracker.ietf.org/doc/html/rfc9171)**.
