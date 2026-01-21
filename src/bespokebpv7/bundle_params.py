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
 Modified: 01/21/2026
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

from attrs import define, field
from attrs.converters import optional

from bespokebpv7.block_enum import AdminReasonCode
from bespokebpv7.utils import DTN_EPOCH, format_eid, parse_eid_string


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
    _max_assertion_len: int = 2

    def set_asserted_time(self, ms: int | None = None) -> None:
        """Set status report asserted time."""
        if not ms:
            dt = datetime.datetime.now(datetime.timezone.utc)
            dt_now = int((dt - DTN_EPOCH).total_seconds() * 1000)
            self.asserted_time = dt_now
        else:
            self.asserted_time = ms

    def unstructure(self) -> list:
        """Convert class to list for cbor encoding.

        Returns:
            Status assertion as lists

        """
        assertions = []
        for key in self.__slots__:  # pyright: ignore[reportAttributeAccessIssue] pylint: disable=E1101
            if "_" not in key:  # skip private slots
                value = getattr(self, key)
                if value is not None:
                    assertions.append(value)
        return assertions

    @classmethod
    def structure(cls, asserted_list: list) -> "StatusAssertion":
        """Convert list of values into Status Assertion.

        Returns:
            Completed StatusAssertion strucutre

        """
        asserted = cls()
        asserted.status_indicator = asserted_list[0]
        if (
            len(asserted_list) == asserted._max_assertion_len
            and asserted_list[1] is not None
        ):
            asserted.asserted_time = asserted_list[1]
        return asserted

    @property
    def asserted_dt(self) -> datetime.datetime | None:
        """Return creation time as datetime object, does not use sequence number."""
        if self.asserted_time is not None:
            return DTN_EPOCH + datetime.timedelta(milliseconds=self.asserted_time)
        return None


@define
class BundleStatusInformation:
    """Class of all valid bundle status information."""

    recv_bundle: StatusAssertion = field(factory=StatusAssertion)
    fwd_bundle: StatusAssertion = field(factory=StatusAssertion)
    deliv_bundle: StatusAssertion = field(factory=StatusAssertion)
    del_bundle: StatusAssertion = field(factory=StatusAssertion)

    def unstructure(self) -> list:
        """Convert class to list for CBOR encoding.

        Returns:
            Bundle Status Information as list.

        """
        status_information = []
        for key in self.__slots__:  # pyright: ignore[reportAttributeAccessIssue] pylint: disable=E1101
            if "_" not in key:  # skip private slots
                value = getattr(self, key)
                status_information.append(value.unstructure())
        return status_information

    @classmethod
    def structure(cls, status_list: list[list]) -> "BundleStatusInformation":
        """Convert list of lists into Bundle Status Information.

        Returns:
            Completed BundleStatusInformation class

        """
        record = cls()
        for idx, value in enumerate(status_list):
            key = record.__slots__[idx]  # pyright: ignore[reportAttributeAccessIssue] pylint: disable=E1101
            setattr(record, key, StatusAssertion.structure(value))
        return record


@define
class BaseStatusReport:
    """Information all status reports are to contain."""

    status_info: BundleStatusInformation = field(factory=BundleStatusInformation)
    reason_code: AdminReasonCode = field(
        default=AdminReasonCode(0), converter=AdminReasonCode
    )
    _status_src_eid: list = field(factory=lambda: [1, None])
    status_creation_time: CreationTime = field(factory=CreationTime)

    def unstructure(self) -> list:
        """Convert status report to list for CBOR encoding.

        Returns:
            BaseStatus Report as list

        """
        creation_time = [
            self.status_creation_time.timestamp_ms,
            self.status_creation_time.sequence,
        ]
        return [
            self.status_info.unstructure(),
            int(self.reason_code),
            self._status_src_eid,
            creation_time,
        ]

    @classmethod
    def structure(cls, report_list: list) -> "BaseStatusReport":
        """
        Convert list to Base Status Report Information.

        Returns:
            Completed BaseStatusReport class

        """
        status = cls()
        status.status_info = BundleStatusInformation.structure(report_list[0])
        status.reason_code = AdminReasonCode(report_list[1])
        status.status_src_eid = report_list[2]
        creation_list = report_list[3]
        status.status_creation_time.timestamp_ms = creation_list[0]
        status.status_creation_time.sequence = creation_list[1]
        return status

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
