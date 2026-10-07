// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title RFC8554 — a line-by-line transcription of RFC 8554 verification, as the proof's
///        specification
/// @notice Written for readability against the RFC text, not for gas: byte strings are
///         `bytes`, concatenation is `abi.encodePacked`, H is `sha256` truncated to n bytes.
///         Section, algorithm and step numbers are RFC 8554's. SHA-256/192 (n = m = 24) is
///         NIST SP 800-208, Section 4. Nothing here is shared with src/LMS.sol.
library RFC8554 {
    uint16 internal constant D_PBLC = 0x8080;
    uint16 internal constant D_MESG = 0x8181;
    uint16 internal constant D_LEAF = 0x8282;
    uint16 internal constant D_INTR = 0x8383;

    // Table 1 (RFC 8554) and SP 800-208 Table 1.
    function lmotsParams(uint32 t) internal pure returns (bool, uint256 n, uint256 w, uint256 p, uint256 ls) {
        if (t == 1) return (true, 32, 1, 265, 7); // LMOTS_SHA256_N32_W1
        if (t == 2) return (true, 32, 2, 133, 6); // LMOTS_SHA256_N32_W2
        if (t == 3) return (true, 32, 4, 67, 4); //  LMOTS_SHA256_N32_W4
        if (t == 4) return (true, 32, 8, 34, 0); //  LMOTS_SHA256_N32_W8
        if (t == 5) return (true, 24, 1, 200, 8); // LMOTS_SHA256_N24_W1
        if (t == 6) return (true, 24, 2, 101, 6); // LMOTS_SHA256_N24_W2
        if (t == 7) return (true, 24, 4, 51, 4); //  LMOTS_SHA256_N24_W4
        if (t == 8) return (true, 24, 8, 26, 0); //  LMOTS_SHA256_N24_W8
        return (false, 0, 0, 0, 0);
    }

    // Table 2 (RFC 8554) and SP 800-208 Table 2.
    function lmsParams(uint32 t) internal pure returns (bool, uint256 m, uint256 h) {
        if (t == 5) return (true, 32, 5); //   LMS_SHA256_M32_H5
        if (t == 6) return (true, 32, 10); //  LMS_SHA256_M32_H10
        if (t == 7) return (true, 32, 15); //  LMS_SHA256_M32_H15
        if (t == 8) return (true, 32, 20); //  LMS_SHA256_M32_H20
        if (t == 9) return (true, 32, 25); //  LMS_SHA256_M32_H25
        if (t == 10) return (true, 24, 5); //  LMS_SHA256_M24_H5
        if (t == 11) return (true, 24, 10); // LMS_SHA256_M24_H10
        if (t == 12) return (true, 24, 15); // LMS_SHA256_M24_H15
        if (t == 13) return (true, 24, 20); // LMS_SHA256_M24_H20
        if (t == 14) return (true, 24, 25); // LMS_SHA256_M24_H25
        return (false, 0, 0);
    }

    function H(uint256 n, bytes memory data) internal pure returns (bytes memory out) {
        bytes32 d = sha256(data);
        out = new bytes(n);
        for (uint256 k; k < n; k++) {
            out[k] = d[k];
        }
    }

    function u32str(uint256 x) internal pure returns (bytes memory) {
        return abi.encodePacked(uint32(x));
    }

    function u16str(uint256 x) internal pure returns (bytes memory) {
        return abi.encodePacked(uint16(x));
    }

    function u8str(uint256 x) internal pure returns (bytes memory) {
        return abi.encodePacked(uint8(x));
    }

    function strTou32(bytes memory S, uint256 at) internal pure returns (uint32) {
        return uint32(uint8(S[at])) << 24 | uint32(uint8(S[at + 1])) << 16 | uint32(uint8(S[at + 2])) << 8
            | uint32(uint8(S[at + 3]));
    }

    function slice(bytes memory S, uint256 from, uint256 len) internal pure returns (bytes memory out) {
        out = new bytes(len);
        for (uint256 k; k < len; k++) {
            out[k] = S[from + k];
        }
    }

    // Section 3.1.3.
    function coef(bytes memory S, uint256 i, uint256 w) internal pure returns (uint256) {
        return (2 ** w - 1) & (uint8(S[(i * w) / 8]) >> (8 - (w * (i % (8 / w)) + w)));
    }

    // Algorithm 2 (Section 4.4).
    function Cksm(bytes memory S, uint256 n, uint256 w, uint256 ls) internal pure returns (bytes memory) {
        uint256 sum = 0;
        for (uint256 i = 0; i < (n * 8) / w; i = i + 1) {
            sum = sum + (2 ** w - 1) - coef(S, i, w);
        }
        return u16str(sum << ls);
    }

    // Algorithm 4b, step 3's inner loop, for one i.
    function chain(bytes memory I, uint256 q, uint256 i, uint256 a, uint256 w, bytes memory tmp, uint256 n)
        internal
        pure
        returns (bytes memory)
    {
        for (uint256 j = a; j < 2 ** w - 1; j = j + 1) {
            tmp = H(n, abi.encodePacked(I, u32str(q), u16str(i), u8str(j), tmp));
        }
        return tmp;
    }

    // Algorithm 4b: the candidate public key from a message and an LM-OTS signature.
    function lmotsCandidate(bytes memory message, bytes memory sig, uint32 pubtype, bytes memory I, uint256 q)
        internal
        pure
        returns (bool, bytes memory)
    {
        // 1. a.–e.
        if (sig.length < 4) return (false, "");
        uint32 sigtype = strTou32(sig, 0);
        if (sigtype != pubtype) return (false, "");
        (bool known, uint256 n, uint256 w, uint256 p, uint256 ls) = lmotsParams(sigtype);
        if (!known) return (false, "");
        if (sig.length != 4 + n * (p + 1)) return (false, "");
        bytes memory C = slice(sig, 4, n);
        // 2. 3.
        bytes memory Q = H(n, abi.encodePacked(I, u32str(q), u16str(D_MESG), C, message));
        bytes memory Qc = abi.encodePacked(Q, Cksm(Q, n, w, ls));
        bytes memory z;
        for (uint256 i = 0; i < p; i = i + 1) {
            uint256 a = coef(Qc, i, w);
            bytes memory tmp = slice(sig, 4 + n + i * n, n);
            z = abi.encodePacked(z, chain(I, q, i, a, w, tmp, n));
        }
        // 4.
        return (true, H(n, abi.encodePacked(I, u32str(q), u16str(D_PBLC), z)));
    }

    // Algorithm 6a, step 4.b–4.c: the climb from leaf q to the root.
    function lmsRootFrom(bytes memory I, uint256 q, uint256 h, uint256 m, bytes memory Kc, bytes memory path)
        internal
        pure
        returns (bytes memory tmp)
    {
        uint256 node_num = 2 ** h + q;
        tmp = H(m, abi.encodePacked(I, u32str(node_num), u16str(D_LEAF), Kc));
        uint256 i = 0;
        while (node_num > 1) {
            bytes memory pi = slice(path, i * m, m);
            if (node_num % 2 == 1) {
                tmp = H(m, abi.encodePacked(I, u32str(node_num / 2), u16str(D_INTR), pi, tmp));
            } else {
                tmp = H(m, abi.encodePacked(I, u32str(node_num / 2), u16str(D_INTR), tmp, pi));
            }
            node_num = node_num / 2;
            i = i + 1;
        }
    }

    /// Algorithm 6a's header and length checks (steps 1, 2.a–2.i, and the length checks of
    /// 2.c, 2.e, 2.h, 2.i), plus SP 800-208's n == m, as a predicate of the lengths and the
    /// typecode words. lmsVerify below applies it to the fields it reads.
    function lmsHeaderOk(
        uint256 pubLen,
        uint32 pubtype,
        uint32 pubotstype,
        uint256 sigLen,
        uint32 q,
        uint32 otssigtype,
        uint32 sigtype
    ) internal pure returns (bool) {
        if (pubLen < 8) return false;
        (bool knownL, uint256 m, uint256 h) = lmsParams(pubtype);
        if (!knownL) return false;
        if (pubLen != 24 + m) return false;
        if (sigLen < 8) return false;
        if (otssigtype != pubotstype) return false;
        (bool knownO, uint256 n,, uint256 p,) = lmotsParams(otssigtype);
        if (!knownO) return false;
        if (sigLen < 12 + n * (p + 1)) return false;
        if (sigtype != pubtype) return false;
        if (q >= 2 ** h || sigLen != 12 + n * (p + 1) + m * h) return false;
        if (n != m) return false;
        return true;
    }

    // Algorithms 6 and 6a.
    function lmsVerify(bytes memory message, bytes memory sig, bytes memory pub) internal pure returns (bool) {
        if (pub.length < 8 || sig.length < 8) {
            return lmsHeaderOk(pub.length, 0, 0, sig.length, 0, 0, 0);
        }
        uint32 pubtype = strTou32(pub, 0);
        uint32 pubotstype = strTou32(pub, 4);
        uint32 q = strTou32(sig, 0);
        uint32 otssigtype = strTou32(sig, 4);
        (, uint256 n,, uint256 p,) = lmotsParams(otssigtype);
        uint32 sigtype = sig.length >= 12 + n * (p + 1) ? strTou32(sig, 8 + n * (p + 1)) : 0;
        if (!lmsHeaderOk(pub.length, pubtype, pubotstype, sig.length, q, otssigtype, sigtype)) return false;
        (, uint256 m, uint256 h) = lmsParams(pubtype);
        bytes memory I = slice(pub, 8, 16);
        bytes memory T1 = slice(pub, 24, m);
        (bool ok, bytes memory Kc) = lmotsCandidate(message, slice(sig, 4, 4 + n * (p + 1)), pubotstype, I, q);
        if (!ok) return false;
        bytes memory path = slice(sig, 12 + n * (p + 1), m * h);
        return keccak256(lmsRootFrom(I, q, h, m, Kc, path)) == keccak256(T1);
    }

    // Section 6.3.
    function hssVerify(bytes memory message, bytes memory sig, bytes memory pub) internal pure returns (bool) {
        if (pub.length < 4) return false;
        uint256 L = strTou32(pub, 0);
        if (L < 1 || L > 8) return false;
        if (sig.length < 4) return false;
        uint256 Nspk = strTou32(sig, 0);
        if (Nspk + 1 != L) return false;
        bytes memory key = slice(pub, 4, pub.length - 4);
        uint256 off = 4;
        for (uint256 i = 0; i < Nspk; i = i + 1) {
            (bool okS, uint256 sl) = lmsSigLen(sig, off);
            if (!okS || sig.length < off + sl) return false;
            bytes memory siglist_i = slice(sig, off, sl);
            off = off + sl;
            (bool okP, uint256 pl) = lmsPubLen(sig, off);
            if (!okP || sig.length < off + pl) return false;
            bytes memory publist_i1 = slice(sig, off, pl);
            off = off + pl;
            if (!lmsVerify(publist_i1, siglist_i, key)) return false;
            key = publist_i1;
        }
        return lmsVerify(message, slice(sig, off, sig.length - off), key);
    }

    function lmsSigLen(bytes memory sig, uint256 off) internal pure returns (bool, uint256) {
        if (sig.length < off + 8) return (false, 0);
        (bool knownO, uint256 n,, uint256 p,) = lmotsParams(strTou32(sig, off + 4));
        if (!knownO) return (false, 0);
        uint256 t = off + 8 + n * (p + 1);
        if (sig.length < t + 4) return (false, 0);
        (bool knownL, uint256 m, uint256 h) = lmsParams(strTou32(sig, t));
        if (!knownL) return (false, 0);
        return (true, 12 + n * (p + 1) + m * h);
    }

    function lmsPubLen(bytes memory b, uint256 off) internal pure returns (bool, uint256) {
        if (b.length < off + 4) return (false, 0);
        (bool knownL, uint256 m,) = lmsParams(strTou32(b, off));
        if (!knownL) return (false, 0);
        return (true, 24 + m);
    }
}
