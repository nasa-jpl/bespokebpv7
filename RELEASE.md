# Version 0.3.0

## Added

- Add support for Adminstrative Records
- Add Bundle Status Report admin record
- Add Custody Transfer Extension Block & its associated admin record
- Add Compressed Reporting Extension Block & its associated admin record

## Changed

- Move CreationTime to separate class to support reuse
- Fix issue populating primary block fragmentation fields
- Change de/serialization to single converter
- Improve endpoint fields handling
- Block & Admin type values now set post init
- Fix typing support under Python 3.10
