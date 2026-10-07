#!/usr/bin/env python3
"""Re-check every committed vector in test/vectors/lms.json with both Python implementations:
py/lms_ref.py (this repository's transcription of RFC 8554) and hsslms (independent).
Every vector must verify, and must stop verifying when its message changes.

    pip install hsslms==0.1.3 && python3 scripts/check_vectors.py
"""
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "py"))
import lms_ref  # noqa: E402
from hsslms import HSS_Pub, LMS_Pub  # noqa: E402

v = json.load(open(os.path.join(HERE, "..", "test", "vectors", "lms.json")))
b = lambda s: bytes.fromhex(s[2:])  # noqa: E731
count = 0
for kind, ref, lib in (("lms", lms_ref.lms_verify, LMS_Pub), ("hss", lms_ref.hss_verify, HSS_Pub)):
    for pub, msg, sig, label in zip(v[f"{kind}_pub"], v[f"{kind}_msg"], v[f"{kind}_sig"], v[f"{kind}_label"]):
        pub, msg, sig = b(pub), b(msg), b(sig)
        assert ref(msg, sig, pub), f"lms_ref rejects {label}"
        assert not ref(msg + b"\x00", sig, pub), f"lms_ref accepts a changed message: {label}"
        lib(pub).verify(msg, sig)  # raises on failure
        try:
            lib(pub).verify(msg + b"\x00", sig)
            sys.exit(f"hsslms accepts a changed message: {label}")
        except Exception:
            pass
        count += 1
print(f"{count} vectors verified by lms_ref and hsslms")
