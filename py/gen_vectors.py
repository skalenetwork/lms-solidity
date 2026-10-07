#!/usr/bin/env python3
"""Generate test/vectors/lms.json: LMS and HSS keys and signatures for the Solidity tests.

    pip install hsslms==0.1.3      # an independent RFC 8554 implementation
    python3 py/gen_vectors.py <rfc8554.txt>

Three sources, every vector checked by two independent implementations before it is written:
  - rfc:       the two test cases of RFC 8554 Appendix F (extracted by rfc_vectors.py);
  - hsslms:    real keys and signatures from `hsslms` for every LM-OTS set, both hash widths,
               heights 5 and 10, and HSS hierarchies of 1–3 levels;
  - synthetic: heights 15, 20 and 25, too large to build, as a real LM-OTS leaf with a random
               authentication path and the root it implies (lms_ref.synthetic_lms).
Each vector must verify under lms_ref.py (this repository's transcription of RFC 8554) and,
where hsslms can check it, under hsslms; the generator aborts otherwise.
"""
import json
import os
import random
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import lms_ref  # noqa: E402
from hsslms import HSS_Priv, HSS_Pub, LMS_Priv, LMS_Pub  # noqa: E402
from hsslms import LMOTS_ALGORITHM_TYPE as OT  # noqa: E402
from hsslms import LMS_ALGORITHM_TYPE as LT  # noqa: E402

rng = random.Random(8554)
OUT = os.path.join(HERE, "..", "test", "vectors", "lms.json")


def check_lms(pub, msg, sig, hsslms_too):
    assert lms_ref.lms_verify(msg, sig, pub), "lms_ref rejects"
    assert not lms_ref.lms_verify(msg + b"\x00", sig, pub), "lms_ref accepts a changed message"
    if hsslms_too:
        LMS_Pub(pub).verify(msg, sig)  # raises on failure


def check_hss(pub, msg, sig):
    assert lms_ref.hss_verify(msg, sig, pub), "lms_ref rejects"
    assert not lms_ref.hss_verify(msg + b"\x00", sig, pub), "lms_ref accepts a changed message"
    HSS_Pub(pub).verify(msg, sig)


def main(rfc_txt):
    lms_pub, lms_msg, lms_sig, lms_label = [], [], [], []
    hss_pub, hss_msg, hss_sig, hss_label = [], [], [], []

    def add_lms(label, pub, msg, sig, hsslms_too=True):
        check_lms(pub, msg, sig, hsslms_too)
        lms_pub.append(pub.hex()), lms_msg.append(msg.hex()), lms_sig.append(sig.hex()), lms_label.append(label)

    def add_hss(label, pub, msg, sig):
        check_hss(pub, msg, sig)
        hss_pub.append(pub.hex()), hss_msg.append(msg.hex()), hss_sig.append(sig.hex()), hss_label.append(label)

    # RFC 8554 Appendix F.
    rfc = json.loads(subprocess.check_output([sys.executable, os.path.join(HERE, "rfc_vectors.py"), rfc_txt]))
    for k in ("case1", "case2"):
        add_hss(f"rfc8554-{k}", *(bytes.fromhex(rfc[k][x]) for x in ("pub", "msg", "sig")))

    # hsslms: every LM-OTS set at h = 5, with its own hash width; h = 10 for W4 and W8.
    pairs = []
    for ot in OT:
        n32 = "N32" in ot.name
        pairs.append((LT.LMS_SHA256_M32_H5 if n32 else LT.LMS_SHA256_M24_H5, ot))
    pairs += [(LT.LMS_SHA256_M32_H10, OT.LMOTS_SHA256_N32_W4), (LT.LMS_SHA256_M24_H10, OT.LMOTS_SHA256_N24_W8)]
    for lt, ot in pairs:
        sk = LMS_Priv(lt, ot)
        pub = sk.gen_pub().get_pubkey()
        for msg in (b"", rng.randbytes(32), rng.randbytes(200)):
            add_lms(f"hsslms-{lt.name}-{ot.name}-{len(msg)}", pub, msg, sk.sign(msg))

    # hsslms HSS: 1, 2 and 3 levels.
    for lts, ot in (
        ([LT.LMS_SHA256_M32_H5], OT.LMOTS_SHA256_N32_W8),
        ([LT.LMS_SHA256_M32_H10, LT.LMS_SHA256_M32_H5], OT.LMOTS_SHA256_N32_W4),
        ([LT.LMS_SHA256_M24_H5, LT.LMS_SHA256_M24_H5, LT.LMS_SHA256_M24_H5], OT.LMOTS_SHA256_N24_W2),
    ):
        sk = HSS_Priv(lts, ot)
        pub = sk.gen_pub().get_pubkey()
        msg = rng.randbytes(32)
        add_hss(f"hsslms-hss-L{len(lts)}-{ot.name}", pub, msg, sk.sign(msg))

    # Synthetic trees at the heights nobody builds in a test.
    for lt in (7, 8, 9, 12, 13, 14):
        for ot in ((4, 3) if lt <= 9 else (8, 7)):
            m, h = lms_ref.LMS[lt]
            q = rng.choice([0, 2 ** h - 1, rng.randrange(2 ** h)])
            msg = rng.randbytes(32)
            pub, sig = lms_ref.synthetic_lms(lt, ot, q, msg, rng)
            add_lms(f"synthetic-lms{lt}-ots{ot}-q{q}", pub, msg, sig, hsslms_too=False)

    out = {
        "lms_pub": lms_pub, "lms_msg": lms_msg, "lms_sig": lms_sig, "lms_label": lms_label,
        "hss_pub": hss_pub, "hss_msg": hss_msg, "hss_sig": hss_sig, "hss_label": hss_label,
    }
    # forge's JSON cheatcodes want 0x-prefixed hex for bytes.
    for k in out:
        if not k.endswith("label"):
            out[k] = ["0x" + v for v in out[k]]
    with open(OUT, "w") as f:
        json.dump(out, f, indent=1)
        f.write("\n")
    print(f"wrote {len(lms_pub)} LMS and {len(hss_pub)} HSS vectors to {os.path.relpath(OUT)}")


if __name__ == "__main__":
    main(sys.argv[1])
