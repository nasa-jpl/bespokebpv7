# TCPCL Enumerations

This page documents the enumerations used by the TCP Convergence Layer
(TCPCL) in `bespokebpv7`.

## TCPCLVersion

TCPCL Versions (RFC 7242 / RFC 9174).

| Member | Value |
| :--- | :--- |
| `V3` | 3 |
| `V4` | 4 |

## TCPCLv3MessageType

TCPCL v3 Message Types (RFC 7242).

| Member | Value |
| :--- | :--- |
| `CONTACT` | 1 |
| `KEEPALIVE` | 2 |
| `SHUTDOWN` | 3 |
| `DATA_SEGMENT` | 4 |
| `DATA_ACK` | 5 |

## TCPCLv4MessageType

TCPCL v4 Message Types (RFC 9174).

| Member | Value |
| :--- | :--- |
| `SESS_INIT` | 1 |
| `KEEPALIVE` | 2 |
| `SESS_TERM` | 3 |
| `XFER_SEGMENT` | 4 |
| `XFER_ACK` | 5 |
