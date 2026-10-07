#!/usr/bin/env python3
"""The first two HSS vectors must be byte-for-byte RFC 8554 Appendix F, Test Cases 1 and 2.

    python3 scripts/check_rfc_cases.py rfc8554.txt
"""
import json
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
rfc = json.loads(subprocess.check_output([sys.executable, os.path.join(HERE, "..", "py", "rfc_vectors.py"), sys.argv[1]]))
v = json.load(open(os.path.join(HERE, "..", "test", "vectors", "lms.json")))
for i, case in enumerate(("case1", "case2")):
    assert v["hss_label"][i] == f"rfc8554-{case}"
    for field in ("pub", "msg", "sig"):
        assert v[f"hss_{field}"][i] == "0x" + rfc[case][field], f"{case} {field} differs from the RFC"
print("RFC 8554 Appendix F test cases match the RFC text")
