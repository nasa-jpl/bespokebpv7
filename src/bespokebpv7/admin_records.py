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
 Title: BPv7 Admin Record Classes & helper functions
 Author: Nate Richard
 Modified: 01/21/2026
 Company: JPL
 Date:   01/20/2026

 File: admin_records
 Description:
           Dataclasses for BPv7 adminstrative records and helper functions
           directly related to the records.
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

import cbor2
from attrs import define, field

from bespokebpv7.block_enum import (
    AdminRecordType,
    CustodyAcceptanceCode,
    CustodyRefusalCode,
)
from bespokebpv7.blocks import CanonicalBlock
from bespokebpv7.bundle_params import (
    BaseStatusReport,
    BundleFragmentation,
    CTBundleSequence,
)


@define
class AdminRecord(CanonicalBlock):
    """Base adminstrative record structure."""

    record_type: int = field(default=0)


@define
class BundleStatusReport(AdminRecord):
    """Bundle status report adminstrative record."""

    base_status: BaseStatusReport = field(factory=BaseStatusReport)
    fragmentation: BundleFragmentation | None = field(factory=BundleFragmentation)
    _max_status_report_len: int = 6

    def _proc_out_data(self) -> bytes:
        """
        Conversion to convert BundleStatusReport to CBOR encodable data.

        Returns:
            CBOR Encoded data

        """
        status_data = self.base_status.unstructure()
        if self.fragmentation is not None:
            status_data.extend(
                [self.fragmentation.fragment_offset, self.fragmentation.total_adu_len]
            )
        return cbor2.dumps([self.record_type, status_data])

    def _proc_in_data(self, block_data: bytes) -> None:
        """Conversion to extract Bundle Status Report from CBOR encoded data."""
        self.data = block_data
        admin_record = cbor2.loads(block_data)
        self.record_type = admin_record[0]
        status_report = admin_record[1]
        self.base_status = BaseStatusReport.structure(status_report)
        if len(status_report) == self._max_status_report_len:
            self.fragmentation = BundleFragmentation(
                fragment_offset=status_report[4], total_adu_len=status_report[5]
            )


@define
class CompressedCustodySignal(AdminRecord):
    """Compressed Custody Signal adminstrative record."""

    custody_signal: dict[
        CustodyAcceptanceCode | CustodyRefusalCode, CTBundleSequence
    ] = field(
        factory=dict[CustodyAcceptanceCode | CustodyRefusalCode, CTBundleSequence]
    )

    def set_custody_acceptance(self, seq: CTBundleSequence) -> None:
        """Set custody acceptance for given bundle sequence."""
        self.custody_signal[CustodyAcceptanceCode.CT_ACCEPTED] = seq

    def set_custody_refusal(self, seq: CTBundleSequence) -> None:
        """Set custody refusal for given bundle sequence."""
        self.custody_signal[CustodyRefusalCode.CT_REFUSED] = seq


@define
class CompressedReportSignal(AdminRecord):
    """Compressed Reporting Signal adminstrative record."""


ADMINFUNCTIONS = {
    AdminRecordType.BUNDLE_STATUS_REPORTS: BundleStatusReport,
    AdminRecordType.COMPRESSED_CUSTODY_SIGNAL: CompressedCustodySignal,
    AdminRecordType.COMPRESSED_REPORT_SIGNAL: CompressedReportSignal,
}
