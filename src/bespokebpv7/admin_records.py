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
 Modified: 07/14/2026
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

import sys

from attrs import define, field

from bespokebpv7.block_enum import (
    AdminRecordType,
    BlockType,
    CustodyAcceptanceCode,
    CustodyRefusalCode,
    ReportReason,
)
from bespokebpv7.blocks import CanonicalBlock
from bespokebpv7.bundle_params import (
    BaseStatusReport,
    BundleFragmentation,
    CRBundleSequence,
    CTBundleSequence,
)
from bespokebpv7.utils import bundle_converter, parse_eid_string, unstructure_eid_list

if sys.version_info >= (3, 11):
    from typing import Any, Self
else:
    from typing import Any

    from typing_extensions import Self


@define
class AdminRecord(CanonicalBlock):
    """Base adminstrative record structure."""

    record_type: int = field(default=0)
    record_len: int = 2


@define
class BundleStatusReport(AdminRecord):
    """Bundle status report adminstrative record."""

    base_status: BaseStatusReport = field(factory=BaseStatusReport)
    fragmentation: BundleFragmentation | None = field(factory=BundleFragmentation)
    max_status_report_len: int = 6

    def __attrs_post_init__(self) -> None:
        """Set record type"""
        self.block_type = BlockType.PAYLOAD_BLOCK
        self.record_type = AdminRecordType.BUNDLE_STATUS_REPORT

    @classmethod
    def _structure(cls, data: list[Any]) -> Self:
        """Structure a BundleStatusReport from a CBOR list (Payload Block fields).

        Returns:
            Populated Bundle Status Report

        """
        block = super()._structure(data)

        admin_record = bundle_converter.loads(block.data, list)
        block.record_type = admin_record[0]
        status_report = admin_record[1]

        block.base_status = bundle_converter.structure(status_report, BaseStatusReport)

        if len(status_report) == block.max_status_report_len:  # pylint: disable=E1101
            block.fragmentation = BundleFragmentation(
                fragment_offset=status_report[4], total_adu_len=status_report[5]
            )
        else:
            block.fragmentation = None

        return block

    def _unstructure(self) -> list[Any]:
        """Unstructure the BundleStatusReport into a CBOR list (Payload Block fields).

        Returns:
            Class as list.

        """
        status_data = bundle_converter.unstructure(self.base_status)

        if self.fragmentation is not None:
            status_data.extend(
                [
                    self.fragmentation.fragment_offset,
                    self.fragmentation.total_adu_len,
                ]
            )

        admin_payload = [self.record_type, status_data]
        self.data = bundle_converter.dumps(admin_payload)

        return super()._unstructure()


@define
class CompressedCustodySignal(AdminRecord):
    """Compressed Custody Signal adminstrative record."""

    custody_signal: dict[
        CustodyAcceptanceCode | CustodyRefusalCode, list[CTBundleSequence]
    ] = field(factory=dict)

    def __attrs_post_init__(self) -> None:
        """Set record type"""
        self.block_type = BlockType.PAYLOAD_BLOCK
        self.record_type = AdminRecordType.COMPRESSED_CUSTODY_SIGNAL

    def set_custody_acceptance(
        self,
        seq: CTBundleSequence | list[CTBundleSequence],
        key: CustodyAcceptanceCode = CustodyAcceptanceCode.CT_ACCEPTED,
    ) -> None:
        """Set custody acceptance for given bundle sequence."""
        if key not in self.custody_signal:
            self.custody_signal[key] = []

        if isinstance(seq, list):
            self.custody_signal[key].extend(seq)
        else:
            self.custody_signal[key].append(seq)

    def set_custody_refusal(
        self,
        seq: CTBundleSequence | list[CTBundleSequence],
        key: CustodyRefusalCode = CustodyRefusalCode.CT_REFUSED,
    ) -> None:
        """Set custody refusal for given bundle sequence."""
        if key not in self.custody_signal:
            self.custody_signal[key] = []

        if isinstance(seq, list):
            self.custody_signal[key].extend(seq)
        else:
            self.custody_signal[key].append(seq)

    @classmethod
    def _structure(cls, data: list[Any]) -> Self:
        """Structure a CompressedCustodySignal from a CBOR list.

        Returns:
            Populated Compressed Custody Signal

        """
        block = super()._structure(data)
        admin_data = bundle_converter.loads(block.data, list)
        block.record_type = admin_data[0]
        cbor_map = admin_data[1]

        for key, seq_collection_data in cbor_map.items():
            cs_key = CustodyRefusalCode(key) if key < 0 else CustodyAcceptanceCode(key)
            sequences = []
            for seq_data in seq_collection_data:
                seq = CTBundleSequence(
                    first_seq_num=seq_data[1],
                    seq_range=seq_data[2],
                )
                seq.dest_seq = seq_data[0]
                sequences.append(seq)
            block.custody_signal[cs_key] = sequences
        return block

    def _unstructure(self) -> list[Any]:
        """Unstructure into [type, map].

        Returns:
            Converted class as list

        """
        cbor_map = {}
        for key, seq_list in self.custody_signal.items():
            encoded_collection = []
            for seq in seq_list:
                encoded_seq = [seq.dest_seq, seq.first_seq_num, seq.seq_range]
                encoded_collection.append(encoded_seq)
            cbor_map[int(key)] = encoded_collection

        admin_payload = [self.record_type, cbor_map]
        self.data = bundle_converter.dumps(admin_payload)
        return super()._unstructure()


@define
class CompressedReportSignal(AdminRecord):
    """Compressed Reporting Signal adminstrative record."""

    reports: dict[ReportReason, list[CRBundleSequence]] = field(factory=dict)

    def __attrs_post_init__(self) -> None:
        """Set record type"""
        self.block_type = BlockType.PAYLOAD_BLOCK
        self.record_type = AdminRecordType.COMPRESSED_REPORT_SIGNAL

    def add_report(
        self, key: ReportReason, seq: CRBundleSequence | list[CRBundleSequence]
    ) -> None:
        """Add a report for a given reason and sequence(s)."""
        if key not in self.reports:
            self.reports[key] = []
        if isinstance(seq, list):
            self.reports[key].extend(seq)
        else:
            self.reports[key].append(seq)

    @classmethod
    def _structure(cls, data: list[Any]) -> Self:
        """Structure a CompressedReportSignal from a CBOR list [type, content].

        Returns:
            Populated Compressed Report Signal

        """
        block = super()._structure(data)
        admin_data = bundle_converter.loads(block.data, list)
        block.record_type = admin_data[0]
        cbor_map = admin_data[1]

        for key, seq_collection_data in cbor_map.items():
            sequences = []
            for seq_data in seq_collection_data:
                seq = CRBundleSequence(
                    first_seq_num=seq_data[1],
                    seq_range=seq_data[2],
                )
                seq.dest_seq = seq_data[0]
                if len(seq_data) == seq.max_seq_len:
                    seq.block_src_admin_eid = seq_data[3]
                sequences.append(seq)
            block.reports[ReportReason(key)] = sequences
        return block

    def _unstructure(self) -> list[Any]:
        """Unstructure into [type, map].

        Returns:
            Converted class as list

        """
        cbor_map = {}
        for key, seq_list in self.reports.items():
            encoded_collection = []
            for seq in seq_list:
                encoded_seq = [seq.dest_seq, seq.first_seq_num, seq.seq_range]
                if seq.block_src_admin_eid is not None:
                    parsed_eid = parse_eid_string(seq.block_src_admin_eid)
                    encoded_seq.append(unstructure_eid_list(parsed_eid))
                encoded_collection.append(encoded_seq)
            cbor_map[int(key)] = encoded_collection

        admin_payload = [self.record_type, cbor_map]
        self.data = bundle_converter.dumps(admin_payload)
        return super()._unstructure()


ADMINFUNCTIONS = {
    AdminRecordType.BUNDLE_STATUS_REPORT: BundleStatusReport,
    AdminRecordType.COMPRESSED_CUSTODY_SIGNAL: CompressedCustodySignal,
    AdminRecordType.COMPRESSED_REPORT_SIGNAL: CompressedReportSignal,
}
