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
 Title: Block enumerations
 Author: Nate Richard
 Modified: 01/21/2026
 Company: JPL
 Date:   12/19/2025

 File: block_enum
 Description:
           Enumerations for specific block parameters
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

from enum import Enum, IntEnum, IntFlag


class BundleFlags(IntFlag):
    """Enumeration for supported bundle flags."""

    __str__ = Enum.__str__
    IS_FRAGMENT = 1 << 0
    ADU_IS_ADMIN_RECORD = 1 << 1
    DO_NOT_FRAGMENT = 1 << 2
    ACK_REQUESTED = 1 << 5
    STATUS_TIME = 1 << 6
    STATUS_REPORT_DELIV = 1 << 14
    STATUS_REPORT_FWD = 1 << 16
    STATUS_REPORT_RECV = 1 << 17
    STATUS_REPORT_DEL = 1 << 18


class BlockFlags(IntFlag):
    """Enumeration for supported block flags."""

    __str__ = Enum.__str__
    REPLICATE_FRAGMENT = 1 << 0
    STATUS_BUNDLE = 1 << 1
    DELETE_BUNDLE = 1 << 2
    DISCARD_BLOCK = 1 << 4


class SchemeCode(IntEnum):
    """BPv7 EID Scheme Codes per IANA registry"""

    DTN = 1
    IPN = 2


class BlockType(IntEnum):
    """Enumeration for supported extension block types."""

    __str__ = Enum.__str__
    UNKNOWN_BLOCK = -1
    PRIMARY_BLOCK = 0
    PAYLOAD_BLOCK = 1
    PREVIOUS_NODE = 6
    BUNDLE_AGE = 7
    METADATA = 8
    HOP_COUNT = 10
    BIB = 11
    BCB = 12
    CTEB = 13  # Placeholder
    CREB = 14  # Placeholder
    DATA_LABEL = 192
    QOS = 193
    IMC = 195


class CRCType(IntEnum):
    """Enumeration for supported CRC types."""

    __str__ = Enum.__str__
    NONE = 0
    CRC16 = 1
    CRC32 = 2

    @property
    def fill_value(self) -> bytes:
        """Returns the null/fill byte string for the CRC field per RFC 9171."""
        if self == CRCType.CRC16:
            return b"\x00\x00"
        if self == CRCType.CRC32:
            return b"\x00\x00\x00\x00"
        return b""


class SecurityContextFlags(IntFlag):
    """Enumerations for Security Context Flags from RFC 9172"""

    CONTAIN_SECURITY_PARM = 1 << 0


class IntegrityScopeFlags(IntFlag):
    """Enumerations for Integrity Scope Flags from RFC 9173"""

    INCLUDE_PRIMARY_BLOCK = 1 << 0
    INCLUDE_TARGET_HEADER = 1 << 1
    INCLUDE_SECURITY_HEADER = 1 << 2


class AADScopeFlags(IntFlag):
    """Enumerations for additional authenticated data Scope Flags from
    RFC 9173
    """


class BIBSHAVariant(IntEnum):
    """Enumeration of BIB SHA Variants"""

    __str__ = Enum.__str__
    HMAC_256_256 = 5
    HMAC_384_384 = 6
    HMAC_512_512 = 7


class BIBParmEnum(IntEnum):
    """Enumeration of parameter IDs for BIB in RFC 9173"""

    __str__ = Enum.__str__
    SHA_VARIANT = 1
    WRAPPED_KEY = 2
    INTEGRITY_SCOPE_FLAGS = 3


class BIBResultEnum(IntEnum):
    """Enumeration of parameter IDs for BIB in RFC 9173"""

    __str__ = Enum.__str__
    EXPECTED_HMAC = 1


class CREBFlags(IntFlag):
    """Enumeration for Custody Reporting extension block flags."""

    __str__ = Enum.__str__
    RECV_REPORT_REQ = 1 << 0
    FWD_REPORT_REQ = 1 << 1
    DELIV_REPORT_REQ = 1 << 2
    DEL_REPORT_REQ = 1 << 3
    CT_ACCEPT_REQ = 1 << 4
    CT_REJECT_REQ = 1 << 5


class AdminRecordType(IntEnum):
    """Enumeration of Adminstrative Record type codes."""

    __str__ = Enum.__str__
    BUNDLE_STATUS_REPORTS = 1
    COMPRESSED_CUSTODY_SIGNAL = 13  # Placeholder
    COMPRESSED_REPORT_SIGNAL = 14  # Placeholder


class AdminReasonCode(IntEnum):
    """Enumeration of Bundle Status Report reason codes."""

    __str__ = Enum.__str__
    NO_INFO = 0
    LIFETIME_EXPIRED = 1
    FWD_UNIDIRECTIONAL = 2
    TRANSMIT_CANCEL = 3
    DEPLETED_STORE = 4
    DEST_EID_UNAVAIL = 5
    NO_ROUTE = 6
    NO_TIMELY_CONTACT = 7
    UNINTELLIGIBLE = 8
    HOP_LIMIT_EXCEED = 9
    TRAFFIC_PARED = 10
    UNSUPPORTED = 11
    RESERVED = 255


class CustodyAcceptanceCode(IntEnum):
    """Disposition codes for custody acceptance."""

    __str__ = Enum.__str__
    CT_ACCEPTED = 1


class CustodyRefusalCode(IntEnum):
    """Disposition codes for custody refusal."""

    __str__ = Enum.__str__
    CT_REFUSED = -1


class ReportReason(IntEnum):
    """Status Report Reason Codes."""

    __str__ = Enum.__str__
    RECV_REPORT = 0
    FWD_REPORT = 1
    DELIV_REPORT = 2
    DEL_REPORT = 3
    CT_ACCEPT_REPORT = 4
    CT_REJECT_REPORT = 5
