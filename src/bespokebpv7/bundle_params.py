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
 Title: BPv7 Primary Block Parameters
 Author: Nate Richard
 Modified: 01/27/2026
 Company: JPL
 Date:   01/07/2026

 File: bundle_params
 Description:
           Combines a few bundle parameters that are related into classes to
           help with code management and legibility.
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

import copy
import datetime as dt
import sys

from attrs import Converter, define, field, frozen
from attrs.converters import optional

from bespokebpv7.block_enum import AdminReasonCode, SchemeCode
from bespokebpv7.utils import (
    DTN_EPOCH,
    bundle_converter,
    format_eid,
    parse_eid_string,
    unstructure_eid_list,
)

if sys.version_info >= (3, 11):
    from typing import Any, Self
else:
    from typing import Any

    from typing_extensions import Self

MIN_CREATION_TIME_LEN = 2
MIN_BASE_STATUS_REPORT_LEN = 4


@define
class BundleRoute:
    """Routing EIDs for a bundle."""

    _dest_eid: list[Any] = field(
        factory=lambda: [1, None],
        converter=Converter(parse_eid_string),  # type: ignore[misc]
    )
    _source_eid: list[Any] = field(
        factory=lambda: [1, None],
        converter=Converter(parse_eid_string),  # type: ignore[misc]
    )
    _report_to_eid: list[Any] = field(
        factory=lambda: [1, None],
        converter=Converter(parse_eid_string),  # type: ignore[misc]
    )

    @property
    def source_eid(self) -> str:
        """Source EID"""
        return format_eid(self._source_eid)

    @source_eid.setter
    def source_eid(self, value: "EndpointID | str | list[Any]") -> None:
        self._source_eid = eid_list_from_value(value)

    @property
    def dest_eid(self) -> str:
        """Destination EID"""
        return format_eid(self._dest_eid)

    @dest_eid.setter
    def dest_eid(self, value: "EndpointID | str | list[Any]") -> None:
        self._dest_eid = eid_list_from_value(value)

    @property
    def report_to(self) -> str:
        """Report to EID"""
        return format_eid(self._report_to_eid)

    @report_to.setter
    def report_to(self, value: "EndpointID | str | list[Any]") -> None:
        self._report_to_eid = eid_list_from_value(value)


@define
class CreationTime:
    """Bundle creation time parameters."""

    timestamp_ms: int = field(default=0)
    sequence: int = field(default=0)

    @property
    def creation_dt(self) -> dt.datetime:
        """Creation time as datetime object, does not use sequence number."""
        return DTN_EPOCH + dt.timedelta(milliseconds=self.timestamp_ms)

    def _unstructure(self) -> list[Any]:
        """Convert CreationTime to list for CBOR encoding.

        Returns:
            Creation time as list [timestamp_ms, sequence]

        """
        return [self.timestamp_ms, self.sequence]

    @classmethod
    def _structure(cls, data: list[Any]) -> Self:
        """Convert list to CreationTime.

        Returns:
            Completed CreationTime class

        Raises:
            ValueError: If the list is too short to contain timestamp and sequence.

        """
        if len(data) < MIN_CREATION_TIME_LEN:
            msg = "CreationTime requires timestamp and sequence"
            raise ValueError(msg)
        return cls(timestamp_ms=data[0], sequence=data[1])


@define
class BundleLife(CreationTime):
    """Parameters for bundle life cycle."""

    lifetime: int = field(default=86400000)  # 1 day


@define
class BundleFragmentation:
    """Parameters when a bundle is fragmented."""

    fragment_offset: int = field(default=0)
    total_adu_len: int = field(default=0)


@define
class StatusAssertion:
    """Structure to report status assertions for bundle transport."""

    status_indicator: bool = field(default=False)
    asserted_time: int | None = field(default=None, converter=optional(int))
    _max_array_len = 2

    def set_asserted_time(self, ms: int | None = None) -> None:
        """Set status report asserted time."""
        if not ms:
            dtime = dt.datetime.now(dt.timezone.utc)
            dt_now = int((dtime - DTN_EPOCH).total_seconds() * 1000)
            self.asserted_time = dt_now
        else:
            self.asserted_time = ms

    @property
    def asserted_dt(self) -> dt.datetime | None:
        """Creation time as datetime object, does not use sequence number.

        Returns:
            Creation time as datetime object or None.

        """
        if self.asserted_time is not None:
            return DTN_EPOCH + dt.timedelta(milliseconds=self.asserted_time)
        return None

    def _unstructure(self) -> list[Any | bool]:
        """Convert StatusAssertion to list for cbor encoding.

        Returns:
            Status assertion as list

        """
        result: list[Any] = [self.status_indicator]
        if self.asserted_time is not None:
            result.append(self.asserted_time)
        return result

    @classmethod
    def _structure(cls, data: list[Any]) -> Self:
        """Convert list of values into Status Assertion.

        Returns:
            Completed StatusAssertion structure

        Raises:
            ValueError: if the status assertion array is empty.

        """
        if not data:
            errmsg = "Status assertion array is empty."
            raise ValueError(errmsg)
        asserted = cls()
        asserted.status_indicator = data[0]
        if len(data) == asserted._max_array_len and data[1] is not None:
            asserted.asserted_time = data[1]
        return asserted


@define
class BundleStatusInformation:
    """Class of all valid bundle status information."""

    recv_bundle: StatusAssertion = field(factory=StatusAssertion)
    fwd_bundle: StatusAssertion = field(factory=StatusAssertion)
    deliv_bundle: StatusAssertion = field(factory=StatusAssertion)
    del_bundle: StatusAssertion = field(factory=StatusAssertion)

    def _unstructure(self) -> list[Any]:
        """Convert BundleStatusInformation to list for CBOR encoding.

        Returns:
            Bundle Status Information as list.

        """
        return [
            bundle_converter.unstructure(self.recv_bundle),
            bundle_converter.unstructure(self.fwd_bundle),
            bundle_converter.unstructure(self.deliv_bundle),
            bundle_converter.unstructure(self.del_bundle),
        ]

    @classmethod
    def _structure(cls, data: list[list[Any]]) -> Self:
        """Convert list of lists into Bundle Status Information.

        Returns:
            Completed BundleStatusInformation class

        Raises:
            ValueError: if the data list contains fewer than 4 elements.

        """
        if len(data) < MIN_BASE_STATUS_REPORT_LEN:
            msg = "BundleStatusInformation requires at least 4 elements"
            raise ValueError(msg)
        return cls(
            recv_bundle=bundle_converter.structure(data[0], StatusAssertion),
            fwd_bundle=bundle_converter.structure(data[1], StatusAssertion),
            deliv_bundle=bundle_converter.structure(data[2], StatusAssertion),
            del_bundle=bundle_converter.structure(data[3], StatusAssertion),
        )


@define
class BaseStatusReport:
    """Information all status reports are to contain."""

    status_info: BundleStatusInformation = field(factory=BundleStatusInformation)
    reason_code: AdminReasonCode = field(
        default=AdminReasonCode(0), converter=AdminReasonCode
    )
    _status_src_eid: list[Any] = field(
        factory=lambda: [1, None],
        converter=Converter(parse_eid_string),  # type: ignore[misc]
    )
    status_creation_time: CreationTime = field(factory=CreationTime)

    @property
    def status_src_eid(self) -> str:
        """Status source EID"""
        return format_eid(self._status_src_eid)

    @status_src_eid.setter
    def status_src_eid(self, value: "EndpointID | str | list[Any]") -> None:
        self._status_src_eid = eid_list_from_value(value)

    def _unstructure(self) -> list[Any]:
        """Convert status report to list for CBOR encoding.

        Returns:
            BaseStatusReport as list

        """
        return [
            bundle_converter.unstructure(self.status_info),
            int(self.reason_code),
            self._status_src_eid,
            bundle_converter.unstructure(self.status_creation_time),
        ]

    @classmethod
    def _structure(cls, data: list[Any]) -> Self:
        """
        Convert list to Base Status Report Information.

        Returns:
            Completed BaseStatusReport class

        Raises:
            ValueError: If the data list contains fewer than 4 elements.

        """
        if len(data) < MIN_BASE_STATUS_REPORT_LEN:
            msg = "BaseStatusReport requires at least 4 elements"
            raise ValueError(msg)
        block = cls(
            status_info=bundle_converter.structure(data[0], BundleStatusInformation),
            reason_code=AdminReasonCode(data[1]),
            status_creation_time=bundle_converter.structure(data[3], CreationTime),
        )
        block.status_src_eid = data[2]
        return block


_PAIR_LEN = 2


def _is_rfc_endpoint_list(value: Any) -> bool:
    """Whether a decoded CBOR value is an RFC 9171 ``[scheme, ssp]`` pair.

    Returns:
        True if the value is typed; False if it must be kept as a raw passthrough

    """
    if not isinstance(value, list) or len(value) != _PAIR_LEN:
        return False
    scheme, ssp = value
    if isinstance(scheme, bool) or not isinstance(scheme, int):
        return False
    if scheme == SchemeCode.DTN:
        return ssp == 0 or (isinstance(ssp, str) and ssp != "none")
    if scheme == SchemeCode.IPN:
        # 2-element FQNN form, or 3-element form with a non-default allocator.
        return (
            isinstance(ssp, list)
            and len(ssp) in {2, 3}
            and all(isinstance(x, int) and not isinstance(x, bool) for x in ssp)
            and (len(ssp) == _PAIR_LEN or ssp[0] != 0)
        )
    return False


@frozen
class EndpointID:
    """Endpoint ID in its CBOR form ``[scheme, ssp]`` (RFC 9171, section 4.2.5.1).

    Build one from a URI string (``"ipn:10.1"``, ``"dtn:none"``) or from a decoded
    CBOR list with :meth:`from_value`; ``str()`` gives the URI and :meth:`to_cbor`
    the list to encode. A CBOR value that is not an RFC-shaped pair (for example
    the legacy ``[1, "none"]``) is kept in ``raw`` and re-encoded unchanged, because
    the library produces non-RFC packets for V&V testing.
    """

    scheme: int | None = None
    ssp: Any = None
    raw: Any = None

    @classmethod
    def from_value(cls, value: "EndpointID | str | list[Any]") -> "EndpointID":
        """Endpoint ID from a URI string, a CBOR list or another EndpointID.

        Returns:
            The endpoint ID; a malformed CBOR value is stored as ``raw``

        """
        if isinstance(value, EndpointID):
            return value
        if isinstance(value, str) or _is_rfc_endpoint_list(value):
            scheme, ssp = parse_eid_string(value)
            return cls(int(scheme), ssp)
        return cls(raw=copy.deepcopy(value))

    def to_cbor(self) -> Any:
        """CBOR value for encoding (2-element IPN form for the default allocator).

        Returns:
            The endpoint ID as a CBOR value

        """
        if self.scheme is None:
            return copy.deepcopy(self.raw)
        return unstructure_eid_list([self.scheme, self.ssp])

    def __str__(self) -> str:
        """URI form of the endpoint ID.

        Returns:
            The endpoint ID as a URI string

        """
        if self.scheme is None:
            return str(self.raw)
        return format_eid([self.scheme, self.ssp])


def eid_list_from_value(value: EndpointID | str | list[Any]) -> list[Any]:
    """Setter input to the stored list form; an EndpointID is first re-encoded.

    Returns:
        A fresh list in the form stored by the EID fields

    """
    if isinstance(value, EndpointID):
        return parse_eid_string(value.to_cbor())
    return parse_eid_string(value)


def _endpoint_id(value: EndpointID | str | list[Any]) -> EndpointID:
    """Attrs converter: any accepted endpoint ID form to an EndpointID.

    Returns:
        The endpoint ID

    """
    return EndpointID.from_value(value)


@define
class CTBundleSequence:
    """Bundle sequence definition for Compressed Custody Signal adminstrative record."""

    dest_seq: EndpointID = field(
        factory=lambda: EndpointID.from_value("dtn:none"),
        converter=_endpoint_id,
    )
    first_seq_num: int = field(default=0)
    seq_range: int | list[int] = field(default=0)


@define
class CRBundleSequence(CTBundleSequence):
    """Bundle sequence definition for Compressed Reporting administrative record."""

    _block_src_admin_eid: list[Any] | None = field(
        factory=lambda: [1, None], converter=optional(parse_eid_string)
    )  # type: ignore[misc]
    max_seq_len: int = 4

    @property
    def block_src_admin_eid(self) -> str | None:
        """Sequence source EID"""
        if self._block_src_admin_eid is not None:
            return format_eid(self._block_src_admin_eid)
        return None

    @block_src_admin_eid.setter
    def block_src_admin_eid(self, value: EndpointID | str | list[Any]) -> None:
        self._block_src_admin_eid = eid_list_from_value(value)
