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
 Modified: 01/26/2026
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

import datetime
from typing import Self

from attrs import define, field
from attrs.converters import optional

from bespokebpv7.block_enum import AdminReasonCode
from bespokebpv7.utils import DTN_EPOCH, bundle_converter, format_eid, parse_eid_string


@define
class BundleRoute:
    """Routing EIDs for a bundle."""

    _dest_eid: list = field(factory=lambda: [1, None])
    _source_eid: list = field(factory=lambda: [1, None])
    _report_to_eid: list = field(factory=lambda: [1, None])

    @property
    def source_eid(self) -> str:
        """Return source EID"""
        return format_eid(self._source_eid)

    @source_eid.setter
    def source_eid(self, value: str | list) -> None:
        if isinstance(value, list):
            self._source_eid = value
        else:
            self._source_eid = parse_eid_string(value)

    @property
    def dest_eid(self) -> str:
        """Return destination EID"""
        return format_eid(self._dest_eid)

    @dest_eid.setter
    def dest_eid(self, value: str | list) -> None:
        if isinstance(value, list):
            self._dest_eid = value
        else:
            self._dest_eid = parse_eid_string(value)

    @property
    def report_to(self) -> str:
        """Return report to EID"""
        return format_eid(self._report_to_eid)

    @report_to.setter
    def report_to(self, value: str | list) -> None:
        if isinstance(value, list):
            self._report_to_eid = value
        else:
            self._report_to_eid = parse_eid_string(value)


@define
class CreationTime:
    """Bundle creation time parameters."""

    timestamp_ms: int = field(default=0)
    sequence: int = field(default=0)

    @property
    def creation_dt(self) -> datetime.datetime:
        """Return creation time as datetime object, does not use sequence number."""
        return DTN_EPOCH + datetime.timedelta(milliseconds=self.timestamp_ms)

    def _unstructure(self) -> list:
        """Convert CreationTime to list for CBOR encoding.

        Returns:
            Creation time as list [timestamp_ms, sequence]

        """
        return [self.timestamp_ms, self.sequence]

    @classmethod
    def _structure(cls, data: list) -> Self:
        """Convert list to CreationTime.

        Returns:
            Completed CreationTime class

        """
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
            dt = datetime.datetime.now(datetime.timezone.utc)
            dt_now = int((dt - DTN_EPOCH).total_seconds() * 1000)
            self.asserted_time = dt_now
        else:
            self.asserted_time = ms

    @property
    def asserted_dt(self) -> datetime.datetime | None:
        """Return creation time as datetime object, does not use sequence number."""
        if self.asserted_time is not None:
            return DTN_EPOCH + datetime.timedelta(milliseconds=self.asserted_time)
        return None

    def _unstructure(self) -> list:
        """Convert StatusAssertion to list for cbor encoding.

        Returns:
            Status assertion as list

        """
        result: list[bool | int | None] = [self.status_indicator]
        if self.asserted_time is not None:
            result.append(self.asserted_time)
        return result

    @classmethod
    def _structure(cls, data: list) -> Self:
        """Convert list of values into Status Assertion.

        Returns:
            Completed StatusAssertion structure

        """
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

    def _unstructure(self) -> list:
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
    def _structure(cls, data: list[list]) -> Self:
        """Convert list of lists into Bundle Status Information.

        Returns:
            Completed BundleStatusInformation class

        """
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
    _status_src_eid: list = field(factory=lambda: [1, None])
    status_creation_time: CreationTime = field(factory=CreationTime)

    @property
    def status_src_eid(self) -> str:
        """Return source EID"""
        return format_eid(self._status_src_eid)

    @status_src_eid.setter
    def status_src_eid(self, value: str | list) -> None:
        if isinstance(value, list):
            self._status_src_eid = value
        else:
            self._status_src_eid = parse_eid_string(value)

    def _unstructure(self) -> list:
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
    def _structure(cls, data: list) -> Self:
        """
        Convert list to Base Status Report Information.

        Returns:
            Completed BaseStatusReport class

        """
        block = cls(
            status_info=bundle_converter.structure(data[0], BundleStatusInformation),
            reason_code=AdminReasonCode(data[1]),
            status_creation_time=bundle_converter.structure(data[3], CreationTime),
        )
        block.status_src_eid = data[2]
        return block


@define
class CTBundleSequence:
    """Bundle sequence definition for Compressed Custody Signal adminstrative record."""

    dest_seq: int | list = field(default=0)
    first_seq_num: int = field(default=0)
    seq_range: int | list[int] = field(default=0)


@define
class CRBundleSequence(CTBundleSequence):
    """Bundle sequence definition for Compressed reporting."""

    _block_src_admin_eid: list | None = field(
        factory=lambda: [1, None], converter=optional(list)
    )


@define
class ReportBundleSequence:
    """Bundle Sequence Collection for Compressed Reporting Signal adminstrative
    record.
    """

    seq_collection: list[CRBundleSequence] = field(factory=list)
