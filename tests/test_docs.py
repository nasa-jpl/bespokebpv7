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
 Title: Documentation and Example README Content Tests
 Author: Nate Richard
 Modified: 10/07/2026
 Company: JPL
 Date:   10/07/2026

 File: test_docs
 Description:
           Checks that examples/README.md has no broken filename references
           and that README.md's Quickstart Python snippets actually execute.
           These checks catch doc-rot that unit tests on library code
           cannot: stale filenames, broken relative links, and
           aspirational-but-non-runnable example snippets.

 Copyright 2026, by the California Institute of Technology. United States
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

import re
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
EXAMPLES_README = REPO_ROOT / "examples" / "README.md"
TOP_README = REPO_ROOT / "README.md"

MARKDOWN_LINK_RE = re.compile(r"\[[^\]]+\]\(([^)]+)\)")
PYTHON_FENCE_RE = re.compile(r"```python\n(.*?)```", re.DOTALL)
MIN_QUICKSTART_SNIPPETS = 3


def test_examples_readme_has_no_broken_filename_refs() -> None:
    """examples/README.md must not reference the stale mitm_test.pys typo."""
    text = EXAMPLES_README.read_text()
    assert "mitm_test.pys" not in text


def test_examples_readme_relative_links_resolve() -> None:
    """Every relative markdown link in examples/README.md must exist on disk."""
    text = EXAMPLES_README.read_text()
    links = MARKDOWN_LINK_RE.findall(text)
    assert links, "expected at least one relative link in examples/README.md"

    for link in links:
        if link.startswith(("http://", "https://", "#")):
            continue
        target = (EXAMPLES_README.parent / link).resolve()
        assert target.exists(), f"broken link in examples/README.md: {link}"


def test_readme_quickstart_snippets_execute() -> None:
    """Every fenced Python block in README.md's Quickstart must execute cleanly.

    This proves the BPv7/LTP/TCPCLStreamParser snippets are runnable, not
    just plausible-looking; content/wording review remains a manual check.
    """
    text = TOP_README.read_text()
    blocks = PYTHON_FENCE_RE.findall(text)
    assert len(blocks) >= MIN_QUICKSTART_SNIPPETS, (
        "expected BPv7, LTP, and TCPCL Quickstart snippets"
    )

    for block in blocks:
        namespace: dict[str, object] = {}
        exec(block, namespace)  # ruff: ignore[exec-builtin]
