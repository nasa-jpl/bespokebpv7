"""
------------------------------------
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
 Title: Bespoke BPv7 test suite for admin_records.py
 Author: Nate Richard
 Modified: 01/27/2026
 Company: JPL
 Date:   01/27/2026

 File: test_admin_records
 Description:
           Tests to verify functionality of admin_records classes & functions
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
from hypothesis import given
from hypothesis import strategies as st
from strategies import (
    base_status_report_strategy,
    cr_sequence_strategy,
    ct_sequence_strategy,
    fragmentation_strategy,
)

from bespokebpv7.admin_records import ( 
    BundleStatusReport,
    CompressedCustodySignal,
    CompressedReportSignal,
)
from bespokebpv7.block_enum import (
    AdminRecordType,
    CustodyAcceptanceCode,
    CustodyRefusalCode,
    ReportReason,
)
from bespokebpv7.bundle_params import ( 
    BaseStatusReport,
    BundleFragmentation,
    CRBundleSequence,
    CTBundleSequence,
)
from bespokebpv7.utils import bundle_converter 


# ==========================================
# Tests for bespokebpv7/admin_record.py
# ==========================================
@given(st.lists(ct_sequence_strategy(), min_size=1))
def test_ccs_acceptance_api(sequences: list[CTBundleSequence]) -> None:
    """Test the set_custody_acceptance helper method."""
    ccs = CompressedCustodySignal()

    ccs.set_custody_acceptance(sequences[0])
    key = CustodyAcceptanceCode.CT_ACCEPTED
    assert key in ccs.custody_signal
    assert len(ccs.custody_signal[key]) == 1
    assert ccs.custody_signal[key][0] == sequences[0]

    if len(sequences) > 1:
        ccs.set_custody_acceptance(sequences[1:])
        assert len(ccs.custody_signal[key]) == len(sequences)


@given(st.lists(ct_sequence_strategy(), min_size=1))
def test_ccs_refusal_api(sequences: list[CTBundleSequence]) -> None:
    """Test the set_custody_refusal helper method."""
    ccs = CompressedCustodySignal()

    ccs.set_custody_refusal(sequences[0])
    key = CustodyRefusalCode.CT_REFUSED
    assert key in ccs.custody_signal
    assert len(ccs.custody_signal[key]) == 1

    if len(sequences) > 1:
        ccs.set_custody_refusal(sequences[1:])
        assert len(ccs.custody_signal[key]) == len(sequences)


@given(
    st.lists(ct_sequence_strategy(), min_size=0),
    st.lists(ct_sequence_strategy(), min_size=0),
)
def test_ccs_roundtrip(
    accept_seqs: list[CTBundleSequence], refuse_seqs: list[CTBundleSequence]
) -> None:
    """Test serialization and deserialization of CompressedCustodySignal."""
    ccs = CompressedCustodySignal()
    if accept_seqs:
        ccs.set_custody_acceptance(accept_seqs)
    if refuse_seqs:
        ccs.set_custody_refusal(refuse_seqs)

    ccs.record_type = AdminRecordType.COMPRESSED_CUSTODY_SIGNAL

    cbor_list = bundle_converter.unstructure(ccs)
    cc_cbor_list = cbor2.loads(cbor_list[-1])

    assert isinstance(cbor_list, list)
    assert len(cbor_list) == ccs.max_array_len
    assert cc_cbor_list[0] == int(AdminRecordType.COMPRESSED_CUSTODY_SIGNAL)
    assert isinstance(cc_cbor_list[1], dict)

    reconstructed = bundle_converter.structure(cbor_list, CompressedCustodySignal)

    assert reconstructed.record_type == ccs.record_type

    if accept_seqs:
        key = CustodyAcceptanceCode.CT_ACCEPTED
        assert key in reconstructed.custody_signal
        assert len(reconstructed.custody_signal[key]) == len(accept_seqs)
        assert reconstructed.custody_signal[key][0].dest_seq == accept_seqs[0].dest_seq

    if refuse_seqs:
        key = CustodyRefusalCode.CT_REFUSED
        assert key in reconstructed.custody_signal
        assert len(reconstructed.custody_signal[key]) == len(refuse_seqs)


@given(st.lists(cr_sequence_strategy(), min_size=1))
def test_crs_add_report_api(sequences: list[CRBundleSequence]) -> None:
    """Test adding reports to CompressedReportSignal."""
    crs = CompressedReportSignal()

    crs.add_report(ReportReason.RECV_REPORT, sequences[0])
    key = ReportReason.RECV_REPORT
    assert key in crs.reports
    assert len(crs.reports[key]) == 1
    assert crs.reports[key][0] == sequences[0]

    if len(sequences) > 1:
        crs.add_report(ReportReason.DELIV_REPORT, sequences[1:])
        key_del = ReportReason.DELIV_REPORT
        assert key_del in crs.reports
        assert len(crs.reports[key_del]) == len(sequences) - 1


@given(
    st.lists(cr_sequence_strategy(), min_size=0),
    st.lists(cr_sequence_strategy(), min_size=0),
)
def test_crs_roundtrip(
    recv_seqs: list[CRBundleSequence], fwd_seqs: list[CRBundleSequence]
) -> None:
    """Test serialization and deserialization of CompressedReportSignal."""
    crs = CompressedReportSignal()
    if recv_seqs:
        crs.add_report(ReportReason.RECV_REPORT, recv_seqs)
    if fwd_seqs:
        crs.add_report(ReportReason.FWD_REPORT, fwd_seqs)

    crs.record_type = AdminRecordType.COMPRESSED_REPORT_SIGNAL

    cbor_list = bundle_converter.unstructure(crs)
    cr_cbor_list = cbor2.loads(cbor_list[-1])

    assert isinstance(cbor_list, list)
    assert len(cbor_list) == crs.max_array_len
    assert cr_cbor_list[0] == int(AdminRecordType.COMPRESSED_REPORT_SIGNAL)
    assert isinstance(cr_cbor_list[1], dict)

    reconstructed = bundle_converter.structure(cbor_list, CompressedReportSignal)
    assert reconstructed.record_type == crs.record_type

    if recv_seqs:
        key = ReportReason.RECV_REPORT
        assert key in reconstructed.reports
        assert len(reconstructed.reports[key]) == len(recv_seqs)
        assert reconstructed.reports[key][0].dest_seq == recv_seqs[0].dest_seq

        # Check Optional field (block_src_admin_eid) logic
        recon_src_eid = reconstructed.reports[key][0].block_src_admin_eid
        if recv_seqs[0].block_src_admin_eid is not None and recon_src_eid is not None:
            orig_eid = recv_seqs[0].block_src_admin_eid
            assert orig_eid == recon_src_eid

    if fwd_seqs:
        key = ReportReason.FWD_REPORT
        assert key in reconstructed.reports
        assert len(reconstructed.reports[key]) == len(fwd_seqs)


@given(
    base_status_report_strategy(),
    st.one_of(st.none(), fragmentation_strategy()),
)
def test_bundle_status_report_roundtrip(
    base_status: BaseStatusReport, fragmentation: BundleFragmentation
) -> None:
    """Test serialization and deserialization of BundleStatusReport.

    Verifies:
    1. Correct handling of the fragmentation field (present vs None).
    2. Correct length of the status report list (6 elements with frag, 4 without).
    3. Data integrity after roundtrip.
    """
    report = BundleStatusReport(
        base_status=base_status,
        fragmentation=fragmentation,
        record_type=AdminRecordType.BUNDLE_STATUS_REPORT,
    )

    cbor_list = bundle_converter.unstructure(report)

    assert isinstance(cbor_list, list)
    assert len(cbor_list) == report.max_array_len

    admin_record = cbor2.loads(cbor_list[-1])
    assert admin_record[0] == int(AdminRecordType.BUNDLE_STATUS_REPORT)
    status_report = admin_record[1]

    if fragmentation is not None:
        assert len(status_report) == report.max_status_report_len
        assert status_report[4] == fragmentation.fragment_offset
        assert status_report[5] == fragmentation.total_adu_len
    else:
        assert len(status_report) == report.max_status_report_len - 2

    reconstructed = bundle_converter.structure(cbor_list, BundleStatusReport)

    assert reconstructed.record_type == report.record_type

    assert reconstructed.base_status.reason_code == base_status.reason_code
    assert reconstructed.base_status.status_src_eid == base_status.status_src_eid
    assert (
        reconstructed.base_status.status_creation_time.timestamp_ms
        == base_status.status_creation_time.timestamp_ms
    )

    assert (
        reconstructed.base_status.status_info.recv_bundle.status_indicator
        == base_status.status_info.recv_bundle.status_indicator
    )

    if fragmentation is not None:
        assert reconstructed.fragmentation is not None
        assert (
            reconstructed.fragmentation.fragment_offset == fragmentation.fragment_offset
        )
        assert reconstructed.fragmentation.total_adu_len == fragmentation.total_adu_len
    else:
        assert reconstructed.fragmentation is None
