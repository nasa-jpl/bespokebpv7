# Changelog

All notable changes to this project will be documented in this file.

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
