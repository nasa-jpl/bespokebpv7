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
Networking)** scheme and the **DTN** scheme. It also supports ION's **IMC
(IPN Multicast)** group scheme.

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

### IMC Scheme

ION's IPN Multicast scheme addresses a multicast group instead of a node. It
follows the same layout as IPN, with a group number in place of the node
number: `imc:allocator.group.service`, or `imc:group.service` for the Default
Allocator. ION encodes it with scheme code `3`. The `!` local-node shorthand
does not apply, and `imc:0.0` is a real endpoint (ION's IMC admin endpoint),
not the Null EID.

**Example:** `"imc:5.1"` (group `5`, service `1`). The member node numbers
for a group bundle travel in the IMC extension block (see `IMCExt`).

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
| **IMC** | `3` | `[3, [0, 5, 1]]` | `"imc:5.1"` |

### IPN Internal Structure

For the IPN scheme, the scheme-specific part is itself a list:
`[allocator, node, service]`.

- `"ipn:2.1"` $\rightarrow$ `[2, [0, 2, 1]]` (Default allocator `0` is
  explicitly stored in the full list).
- Note: Some legacy implementations may pack the allocator and node into a
  single 64-bit "Fully Qualified Node Name" (FQNN), but the recommended BPv7
  format uses the 3-element list.

IMC uses the same structure, `[allocator, group, service]`. On the wire, a
Default Allocator group is written as the 2-element `[fqgn, service]` (Fully
Qualified Group Number) and any other allocator as `[allocator, group,
service]`, the two forms ION's decoder accepts.

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
  - If the scheme is `imc`, it parses the allocator, group, and service.
  - Otherwise, it defaults to the `dtn` scheme.

### `format_eid(eid)`

Converts an internal CBOR list back into a human-readable URI string.

- **Input**: A list `[scheme_code, ssp]`.
- **Output**: A string (e.g., `"ipn:2.1"`).
- **Behavior**:
  - For `SchemeCode.IPN`, it reconstructs the `ipn:allocator.node.service`
    string. If the allocator is `0`, it is omitted from the resulting string
    for brevity.
  - For `SchemeCode.IMC`, it does the same with `imc:allocator.group.service`.
  - For `SchemeCode.DTN`, it returns `dtn:ssp`.

---

## Standard Reference

For detailed specifications on EID formats and the Bundle Protocol version 7,
refer to **[RFC 9171](https://datatracker.ietf.org/doc/html/rfc9171)**.
