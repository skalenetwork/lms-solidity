#!/usr/bin/env python3
"""A line-by-line transcription of RFC 8554 (LMS/HSS) and NIST SP 800-208 (SHA-256/192).

Written from the RFC text, not from any other implementation, so that it can serve as an
independent oracle next to `hsslms` when generating and checking the Solidity test vectors.
Section and algorithm numbers refer to RFC 8554.

Covers the SHA-256 parameter sets: n = m = 32 (RFC 8554 Section 4.1 and 5.1) and
n = m = 24 (SHA-256/192, SP 800-208 Section 4). The SHAKE256 sets of SP 800-208 are not
covered.
"""
import hashlib
import os

D_PBLC = 0x8080
D_MESG = 0x8181
D_LEAF = 0x8282
D_INTR = 0x8383

# typecode -> (n, w, p, ls)        RFC 8554 Table 1; SP 800-208 Table 1
LMOTS = {
    1: (32, 1, 265, 7), 2: (32, 2, 133, 6), 3: (32, 4, 67, 4), 4: (32, 8, 34, 0),
    5: (24, 1, 200, 8), 6: (24, 2, 101, 6), 7: (24, 4, 51, 4), 8: (24, 8, 26, 0),
}
# typecode -> (m, h)               RFC 8554 Table 2; SP 800-208 Table 2
LMS = {
    5: (32, 5), 6: (32, 10), 7: (32, 15), 8: (32, 20), 9: (32, 25),
    10: (24, 5), 11: (24, 10), 12: (24, 15), 13: (24, 20), 14: (24, 25),
}


def H(n, data):
    """SHA-256, truncated to n bytes (n = 24 is SHA-256/192)."""
    return hashlib.sha256(data).digest()[:n]


def u32str(x):
    return x.to_bytes(4, "big")


def u16str(x):
    return x.to_bytes(2, "big")


def u8str(x):
    return x.to_bytes(1, "big")


def strTou32(b):
    return int.from_bytes(b, "big")


def coef(S, i, w):
    """Section 3.1.3."""
    return (2 ** w - 1) & (S[(i * w) // 8] >> (8 - (w * (i % (8 // w)) + w)))


def cksm(S, n, w, ls):
    """Algorithm 2 (Section 4.4)."""
    s = 0
    for i in range(n * 8 // w):
        s = s + (2 ** w - 1) - coef(S, i, w)
    return u16str(s << ls)


# ── LM-OTS (Section 4) ────────────────────────────────────────────────────────


def lmots_keygen(otstype, I, q, seed):
    """Private key x and public key K for leaf q (Algorithms 0 and 1); x from Appendix A."""
    n, w, p, ls = LMOTS[otstype]
    x = [H(n, I + u32str(q) + u16str(i) + u8str(0xFF) + seed) for i in range(p)]
    y = []
    for i in range(p):
        tmp = x[i]
        for j in range(2 ** w - 1):
            tmp = H(n, I + u32str(q) + u16str(i) + u8str(j) + tmp)
        y.append(tmp)
    K = H(n, I + u32str(q) + u16str(D_PBLC) + b"".join(y))
    return x, K


def lmots_sign(otstype, I, q, x, message, C=None):
    """Algorithm 3."""
    n, w, p, ls = LMOTS[otstype]
    if C is None:
        C = os.urandom(n)
    Q = H(n, I + u32str(q) + u16str(D_MESG) + C + message)
    Qc = Q + cksm(Q, n, w, ls)
    y = []
    for i in range(p):
        a = coef(Qc, i, w)
        tmp = x[i]
        for j in range(a):
            tmp = H(n, I + u32str(q) + u16str(i) + u8str(j) + tmp)
        y.append(tmp)
    return u32str(otstype) + C + b"".join(y)


def lmots_candidate(message, sig, pubtype, I, q):
    """Algorithm 4b: the candidate public key, or None if the signature is invalid."""
    if len(sig) < 4:
        return None
    sigtype = strTou32(sig[0:4])
    if sigtype != pubtype:
        return None
    if sigtype not in LMOTS:
        return None
    n, w, p, ls = LMOTS[sigtype]
    if len(sig) != 4 + n * (p + 1):
        return None
    C = sig[4:4 + n]
    y = [sig[4 + n + i * n:4 + n + (i + 1) * n] for i in range(p)]
    Q = H(n, I + u32str(q) + u16str(D_MESG) + C + message)
    Qc = Q + cksm(Q, n, w, ls)
    z = []
    for i in range(p):
        a = coef(Qc, i, w)
        tmp = y[i]
        for j in range(a, 2 ** w - 1):
            tmp = H(n, I + u32str(q) + u16str(i) + u8str(j) + tmp)
        z.append(tmp)
    return H(n, I + u32str(q) + u16str(D_PBLC) + b"".join(z))


# ── LMS (Section 5) ───────────────────────────────────────────────────────────


def lms_root_from(I, q, h, m, Kc, path):
    """Steps 4.b.i–4.b.iii of Algorithm 6a: climb from leaf q to the root."""
    node_num = 2 ** h + q
    tmp = H(m, I + u32str(node_num) + u16str(D_LEAF) + Kc)
    i = 0
    while node_num > 1:
        if node_num % 2 == 1:
            tmp = H(m, I + u32str(node_num // 2) + u16str(D_INTR) + path[i] + tmp)
        else:
            tmp = H(m, I + u32str(node_num // 2) + u16str(D_INTR) + tmp + path[i])
        node_num = node_num // 2
        i = i + 1
    return tmp


def lms_verify(message, sig, pub):
    """Algorithms 6 and 6a."""
    if len(pub) < 8:
        return False
    pubtype = strTou32(pub[0:4])
    if pubtype not in LMS:
        return False
    m, h = LMS[pubtype]
    if len(pub) != 24 + m:
        return False
    otstype = strTou32(pub[4:8])
    I = pub[8:24]
    T1 = pub[24:24 + m]
    if len(sig) < 8:
        return False
    q = strTou32(sig[0:4])
    otssigtype = strTou32(sig[4:8])
    if otssigtype != otstype:
        return False
    if otssigtype not in LMOTS:
        return False
    n, w, p, ls = LMOTS[otssigtype]
    if len(sig) < 12 + n * (p + 1):
        return False
    lmots_sig = sig[4:8 + n * (p + 1)]
    sigtype = strTou32(sig[8 + n * (p + 1):12 + n * (p + 1)])
    if sigtype != pubtype:
        return False
    if q >= 2 ** h or len(sig) != 12 + n * (p + 1) + m * h:
        return False
    # SP 800-208 Section 4 pairs SHA-256/192 OTS keys only with SHA-256/192 trees.
    if n != m:
        return False
    path = [sig[12 + n * (p + 1) + i * m:12 + n * (p + 1) + (i + 1) * m] for i in range(h)]
    Kc = lmots_candidate(message, lmots_sig, otstype, I, q)
    if Kc is None:
        return False
    return lms_root_from(I, q, h, m, Kc, path) == T1


def lms_sig_len(sig, off):
    """Length of the LMS signature that starts at sig[off], read from its own type fields."""
    if len(sig) < off + 8:
        return None
    otstype = strTou32(sig[off + 4:off + 8])
    if otstype not in LMOTS:
        return None
    n, w, p, ls = LMOTS[otstype]
    t = off + 8 + n * (p + 1)
    if len(sig) < t + 4:
        return None
    lmstype = strTou32(sig[t:t + 4])
    if lmstype not in LMS:
        return None
    m, h = LMS[lmstype]
    return 12 + n * (p + 1) + m * h


def lms_pub_len(b, off):
    if len(b) < off + 4:
        return None
    t = strTou32(b[off:off + 4])
    if t not in LMS:
        return None
    return 24 + LMS[t][0]


# ── HSS (Section 6) ───────────────────────────────────────────────────────────


def hss_verify(message, sig, pub):
    """Section 6.3, with the length checks of Section 6.2 applied while parsing."""
    if len(pub) < 4:
        return False
    L = strTou32(pub[0:4])
    if L < 1 or L > 8:
        return False
    if len(sig) < 4:
        return False
    Nspk = strTou32(sig[0:4])
    if Nspk + 1 != L:
        return False
    key = pub[4:]
    off = 4
    for i in range(Nspk):
        sl = lms_sig_len(sig, off)
        if sl is None:
            return False
        siglist_i = sig[off:off + sl]
        off += sl
        pl = lms_pub_len(sig, off)
        if pl is None or len(sig) < off + pl:
            return False
        publist_i1 = sig[off:off + pl]
        off += pl
        if not lms_verify(publist_i1, siglist_i, key):
            return False
        key = publist_i1
    if not lms_verify(message, sig[off:], key):
        return False
    return True


# ── Synthetic trees, for heights too large to build in Python ─────────────────


def synthetic_lms(lmstype, otstype, q, message, rng):
    """An LMS key and a valid signature at leaf q without building the tree.

    The leaf comes from a real LM-OTS key pair; the authentication path is random, and the
    root is whatever the climb from that leaf through that path yields. The result is a
    well-formed (public key, signature) pair that verifies, at any height, exercising every
    level of the climb without materialising 2^h leaves.
    """
    m, h = LMS[lmstype]
    I = rng.randbytes(16)
    x, K = lmots_keygen(otstype, I, q, rng.randbytes(32))
    ots = lmots_sign(otstype, I, q, x, message, C=rng.randbytes(LMOTS[otstype][0]))
    path = [rng.randbytes(m) for _ in range(h)]
    T1 = lms_root_from(I, q, h, m, K, path)
    pub = u32str(lmstype) + u32str(otstype) + I + T1
    sig = u32str(q) + ots + u32str(lmstype) + b"".join(path)
    return pub, sig
