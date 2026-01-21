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
