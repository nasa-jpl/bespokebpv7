"""
....................................

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
 Title: Make Release File
 Author: Nate Richard
 Modified: 01/16/2026
 Company: JPL
 Date:   07/10/2020

 File: mk_release
 Description:
           Parses chnge log to create latest release file
           Python 3.12.11

Copyright 2024, by the California Institute of Technology. United States
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
from pathlib import Path

version = sys.argv[1]
result = "# Version " + version + "\n"
RECORD = False

with Path("CHANGELOG.md").open(encoding="utf-8") as f:
    for line in f:
        if "##" in line and "###" not in line and RECORD is True:
            break
        if RECORD is True:
            output_line = line.replace("###", "##") if "###" in line else line
            result += output_line
        if version in line:
            RECORD = True

Path("RELEASE.md").write_text(f"{result.strip()}\n", encoding="utf-8")
