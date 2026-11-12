# Changelog

All notable changes to this project will be documented in this file.

## [Unreleased]

### Changed

- **Wire format:** The default BPSec `security_source` now encodes as `[1, 0]` (`dtn:none`) instead of `[1, "none"]`, and `ipn:2.1` encodes as `[2, [2, 1]]`. Legacy decoded `[1, "none"]` values are kept and re-encoded unchanged. Fixes #90.
- **Public API:** `EndpointID` (in `bundle_params`) is exported from `bespokebpv7`. `CTBundleSequence.dest_seq` is an `EndpointID` (was `int | list[Any]`). Encoding is unchanged.
- **EID setters:** The EID setters on `BundleRoute`, `BaseStatusReport`, `CRBundleSequence`, and the extension classes (`PreviousNodeExt`, `CustodyTransferExt`, `CompressedReportingExt`) accept `EndpointID` as well as `str` and list input. Getters still return `str`.
- **`calculate_crc`:** Replaces the CRC field with its null fill (`CRCType.fill_value`) before hashing, as its docstring stated. Callers in `bpv7.py` already passed the fill, so their output is unchanged. `blocks.py` `update_crc` output changes only when the stored CRC was not the null fill. Refs #44.

### Fixed

- `BPv7.unpack` errors for a malformed canonical block name its bundle array index. Refs #45.
- `DataSegment` raises `ValueError` when the payload is shorter than declared. Refs #44.
- `TCPCL.unpack` raises `ValueError` for a zero length. Refs #44.

## [0.6.0] 2026-09-28

### Added

- Add TCPCL v3 & v4 support
- Add LTP report segment support
- Add allocator support

### Changed

- Update imports to allow for simplified imports for BP, LTP, & TCP
- Typing & formatting updates
- Dependency version updates

## [0.5.0] 2026-07-09

### Added

- ION QoS Extension block support
- Native bundle & Segment mangling/modification

### Changed

- Update cbor2 version requirement
- Fix timing issue on status-rpt example

### Added

- Support LTP Data segments
- Support parsing of bundles within Data Segments

## [0.4.1] 2026-04-01

### Added

- Support LTP Data segments
- Support parsing of bundles within Data Segments

## [0.4.0] 2026-03-26

### Added

- Minimal BCB support, all security operations are up to user
- Minimal LTP support, report, cancel, and their respective ACKs
- Documents for Claude and ed3d-plugins

## [0.3.1] 2026-01-30

Repo now has examples of *bespokebpv7* in action

### Changed

- Fix de/serialization of BIB security results
- Fix deliv & recv status bits being flipped

## [0.3.0] 2026-01-27

### Added

- Add support for Adminstrative Records
- Add Bundle Status Report admin record
- Add Custody Transfer Extension Block & its associated admin record
- Add Compressed Reporting Extension Block & its associated admin record

### Changed

- Move CreationTime to separate class to support reuse
- Fix issue populating primary block fragmentation fields
- Change de/serialization to single converter
- Improve endpoint fields handling
- Block & Admin type values now set post init
- Fix typing support under Python 3.10

## [0.2.1] 2026-01-16

Verify GitHub connection update

### Changed

- Cleanup imports

## [0.2.0] 2026-01-16

First formal release

### Changed

- Refactor code to better support data de/serialization
- Change non-BPSec extension blocks to classes
- Fix flag setting in BIB
- Correct security parameter value for BIB

## [0.1.0] 2025-01-08

Initial full working version, not actually released
