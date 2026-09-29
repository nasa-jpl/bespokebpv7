# dpkt Integration Guide

The `bespokebpv7` library uses [`dpkt`](https://github.com/kbandla/dpkt) as a
base class for packet-like types. The `BPv7`, `LTP`, and `TCPCL` classes all
inherit from `dpkt.Packet` and extend it with CBOR and protocol-specific
decoding.

## Why dpkt.Packet?

`dpkt.Packet` provides a framework for parsing wire-format packets with
fixed headers. However, BPv7 bundles, LTP segments, and TCPCL messages use
variable-length CBOR encoding rather than fixed-length binary headers. This
creates two integration challenges:

1. **Truthiness**: `dpkt.Packet.__bool__` falls back to `__len__` when
   defined, which in turn relies on `__hdr_len__` (a fixed header size).
   Since CBOR data has no fixed header, this would produce incorrect results.

1. **Length**: `dpkt.Packet.__len__` returns the fixed header length, not
   the actual serialized CBOR size.

## `__bool__()` Override

The `BPv7` class overrides `__bool__` to always return `True`:

```python
def __bool__(self) -> bool:
    """Ensure truthiness checks (like `if bundle:`) don't fall back
    to dpkt.Packet's __len__, which expects a fixed __hdr_len__.
    """
    return True
```

This ensures that truthiness checks (e.g., `if bundle:`) behave intuitively —
a parsed bundle object is always considered truthy, regardless of its
serialized length.

## `__len__()` Override

The `BPv7` class overrides `__len__` to return the actual serialized size:

```python
def __len__(self) -> int:
    """Override dpkt's __len__ to return the actual serialized size
    since we dynamically parse CBOR instead of using fixed headers.
    """
    return len(bytes(self))
```

This makes length calculations reflect the true CBOR-encoded size, which is
essential since CBOR uses variable-length encoding (indefinite arrays with
break codes) that dpkt's fixed-header model cannot capture.

## Classes with These Overrides

| Class | Module | `__bool__` | `__len__` |
| ------- | -------- | ------------ | ----------- |
| `BPv7` | `bpv7.py` | ✅ Always returns `True` | ✅ `len(bytes(self))` |
| `LTP` | `ltp.py` | No override (inherited from `dpkt.Packet`) | No override |
| `TCPCL` | `tcpcl.py` | No override | No override |

Only `BPv7` requires these overrides because it uses indefinite CBOR arrays.
`LTP` and `TCPCL` use fixed-format headers and do not need custom truthiness
or length behavior.

## References

- [BPv7 API Reference](../api/core.md)
- [LTP API Reference](../api/ltp.md)
- [TCPCL API Reference](../api/tcpcl.md)
