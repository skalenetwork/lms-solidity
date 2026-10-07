// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title LMS — RFC 8554 Leighton-Micali (LMS) and HSS signature verification
/// @notice Verification only, for the SHA-256 parameter sets: n = m = 32 (RFC 8554, Tables 1
///         and 2) and n = m = 24, SHA-256/192 (NIST SP 800-208, Section 4). The SHAKE256
///         sets of SP 800-208 are not supported and are refused like any unknown typecode.
///
///         Every entry point returns false — never reverts — on a malformed key or signature:
///         a wrong length, an unknown or mismatched typecode, a leaf index outside the tree,
///         or an HSS signature whose level count disagrees with the key.
///
///         LMS keys are STATEFUL one-time-signature trees: a leaf must never sign twice. This
///         library checks signatures; it does not, and cannot, know which leaves a signer has
///         already used. A caller that grants authority on a signature must record the leaf
///         index `q` (for HSS, the bottom tree's `q` and the chain of signed public keys) as
///         spent and refuse its reuse.
///
///         The functions below the entry points are the steps the proofs in `test/proof`
///         match against a transcription of RFC 8554 (see PROOF.md); the verifier is built
///         from them and nothing else.
/// @author SKALE Labs
library LMS {
    uint256 internal constant D_PBLC = 0x8080;
    uint256 internal constant D_MESG = 0x8181;
    uint256 internal constant D_LEAF = 0x8282;
    uint256 internal constant D_INTR = 0x8383;

    /// Deepest HSS hierarchy RFC 8554 allows (Section 6).
    uint256 internal constant MAX_LEVELS = 8;

    // ── Parameter sets ───────────────────────────────────────────────────────

    /// LM-OTS typecode -> (n, w, p, ls). RFC 8554 Table 1; SP 800-208 Table 1.
    function otsParams(uint256 t) internal pure returns (bool ok, uint256 n, uint256 w, uint256 p, uint256 ls) {
        if (t == 1) return (true, 32, 1, 265, 7);
        if (t == 2) return (true, 32, 2, 133, 6);
        if (t == 3) return (true, 32, 4, 67, 4);
        if (t == 4) return (true, 32, 8, 34, 0);
        if (t == 5) return (true, 24, 1, 200, 8);
        if (t == 6) return (true, 24, 2, 101, 6);
        if (t == 7) return (true, 24, 4, 51, 4);
        if (t == 8) return (true, 24, 8, 26, 0);
        return (false, 0, 0, 0, 0);
    }

    /// LMS typecode -> (m, h). RFC 8554 Table 2; SP 800-208 Table 2.
    function lmsParams(uint256 t) internal pure returns (bool ok, uint256 m, uint256 h) {
        if (t >= 5 && t <= 9) return (true, 32, 5 * (t - 4));
        if (t >= 10 && t <= 14) return (true, 24, 5 * (t - 9));
        return (false, 0, 0);
    }

    // ── Entry points ─────────────────────────────────────────────────────────

    /// @notice HSS verification (RFC 8554, Section 6.3). `publicKey` is the HSS public key
    ///         (u32 L || LMS public key) and `signature` the HSS signature
    ///         (u32 Nspk || (LMS signature || LMS public key) x Nspk || LMS signature).
    function verifyHSS(bytes memory publicKey, bytes memory message, bytes memory signature)
        internal
        view
        returns (bool)
    {
        if (publicKey.length < 4) return false;
        uint256 levels = _u32(_ptr(publicKey));
        if (levels < 1 || levels > MAX_LEVELS) return false;
        if (signature.length < 4) return false;
        uint256 nspk = _u32(_ptr(signature));
        if (nspk + 1 != levels) return false;

        uint256 keyPtr = _ptr(publicKey) + 4;
        uint256 keyLen = publicKey.length - 4;
        uint256 off = 4;
        for (uint256 i; i < nspk; ++i) {
            (bool okSig, uint256 sigLen) = lmsSignatureLength(signature, off);
            if (!okSig || signature.length < off + sigLen) return false;
            uint256 sigPtr = _ptr(signature) + off;
            off += sigLen;
            (bool okPub, uint256 pubLen) = lmsPublicKeyLength(signature, off);
            if (!okPub || signature.length < off + pubLen) return false;
            uint256 pubPtr = _ptr(signature) + off;
            off += pubLen;
            // Each level signs the encoding of the next level's public key.
            if (!_verifyLMS(keyPtr, keyLen, pubPtr, pubLen, sigPtr, sigLen)) return false;
            keyPtr = pubPtr;
            keyLen = pubLen;
        }
        return _verifyLMS(keyPtr, keyLen, _ptr(message), message.length, _ptr(signature) + off, signature.length - off);
    }

    /// @notice Single-tree LMS verification (RFC 8554, Algorithms 6 and 6a).
    function verifyLMS(bytes memory publicKey, bytes memory message, bytes memory signature)
        internal
        view
        returns (bool)
    {
        return _verifyLMS(
            _ptr(publicKey), publicKey.length, _ptr(message), message.length, _ptr(signature), signature.length
        );
    }

    // ── Parsing (Algorithm 6a, steps 1–2 and 3) ──────────────────────────────

    /// The layout of an LMS (public key, signature) pair, once Algorithm 6a's checks pass.
    struct Layout {
        uint256 n;
        uint256 w;
        uint256 p;
        uint256 ls;
        uint256 m;
        uint256 h;
        uint256 q;
    }

    /// Algorithm 6a's acceptance checks on the public key and signature headers and lengths,
    /// in the RFC's order, plus SP 800-208's requirement that the OTS and tree hashes agree
    /// (n == m). Reads typecodes and lengths only; hashes nothing.
    function parseLMS(uint256 pubPtr, uint256 pubLen, uint256 sigPtr, uint256 sigLen)
        internal
        pure
        returns (bool ok, Layout memory lay)
    {
        if (pubLen < 8) return (false, lay);
        uint256 pubtype = _u32(pubPtr);
        bool known;
        (known, lay.m, lay.h) = lmsParams(pubtype);
        if (!known) return (false, lay);
        if (pubLen != 24 + lay.m) return (false, lay);
        uint256 otstype = _u32(pubPtr + 4);
        if (sigLen < 8) return (false, lay);
        lay.q = _u32(sigPtr);
        if (_u32(sigPtr + 4) != otstype) return (false, lay);
        (known, lay.n, lay.w, lay.p, lay.ls) = otsParams(otstype);
        if (!known) return (false, lay);
        uint256 otsLen = lay.n * (lay.p + 1);
        if (sigLen < 12 + otsLen) return (false, lay);
        if (_u32(sigPtr + 8 + otsLen) != pubtype) return (false, lay);
        if (lay.q >= (1 << lay.h) || sigLen != 12 + otsLen + lay.m * lay.h) return (false, lay);
        if (lay.n != lay.m) return (false, lay);
        return (true, lay);
    }

    /// Length of the LMS signature starting at `sig[off]`, from its own typecodes. `ok` is
    /// false if either typecode is unknown or the header runs past the end.
    function lmsSignatureLength(bytes memory sig, uint256 off) internal pure returns (bool ok, uint256 len) {
        if (sig.length < off + 8) return (false, 0);
        (bool okOts, uint256 n,, uint256 p,) = otsParams(_u32(_ptr(sig) + off + 4));
        if (!okOts) return (false, 0);
        uint256 t = off + 8 + n * (p + 1);
        if (sig.length < t + 4) return (false, 0);
        (bool okLms, uint256 m, uint256 h) = lmsParams(_u32(_ptr(sig) + t));
        if (!okLms) return (false, 0);
        return (true, 12 + n * (p + 1) + m * h);
    }

    /// Length of the LMS public key starting at `b[off]`, from its typecode.
    function lmsPublicKeyLength(bytes memory b, uint256 off) internal pure returns (bool ok, uint256 len) {
        if (b.length < off + 4) return (false, 0);
        (bool okLms, uint256 m,) = lmsParams(_u32(_ptr(b) + off));
        if (!okLms) return (false, 0);
        return (true, 24 + m);
    }

    // ── LM-OTS (Algorithm 4b) ────────────────────────────────────────────────

    /// Cksm(Q) of Algorithm 2, before the final u16str: the sum, shifted left by ls.
    function checksum(bytes32 Q, uint256 n, uint256 w, uint256 ls) internal pure returns (uint256 s) {
        uint256 mask = (1 << w) - 1;
        uint256 count = (n * 8) / w;
        for (uint256 i; i < count; ++i) {
            s += mask - digitAt(Q, n, 0, i, w);
        }
        return (s << ls) & 0xffff;
    }

    /// coef(Q || u16str(ck), i, w) of Section 3.1.3: digit i of the n-byte Q followed by
    /// the two checksum bytes. Q is left-aligned (its first byte is the word's top byte).
    function digitAt(bytes32 Q, uint256 n, uint256 ck, uint256 i, uint256 w) internal pure returns (uint256) {
        uint256 byteIdx = (i * w) / 8;
        uint256 b;
        if (byteIdx < n) {
            b = uint8(Q[byteIdx]);
        } else if (byteIdx == n) {
            b = (ck >> 8) & 0xff;
        } else {
            b = ck & 0xff;
        }
        uint256 shift = 8 - (w * (i % (8 / w)) + w);
        return ((1 << w) - 1) & (b >> shift);
    }

    /// One LM-OTS chain from step `a` to step 2^w - 2 (Algorithm 4b, step 3's inner loop):
    /// tmp = H(I || u32str(q) || u16str(i) || u8str(j) || tmp) for j = a .. 2^w - 2.
    /// `buf` is scratch memory of at least 23 + 32 + 32 bytes.
    function chain(bytes16 I, uint256 q, uint256 i, uint256 a, uint256 w, bytes32 tmp, uint256 n, uint256 buf)
        internal
        view
        returns (bytes32)
    {
        uint256 last = (1 << w) - 1;
        bytes32 mask = _mask(n);
        chainPrefix(buf, I, q, i);
        for (uint256 j = a; j < last; ++j) {
            tmp = chainStep(buf, j, tmp, n, mask);
        }
        return tmp;
    }

    /// Writes I || u32str(q) || u16str(i), the part of a chain step's preimage that does not
    /// change from step to step, at `buf`.
    function chainPrefix(uint256 buf, bytes16 I, uint256 q, uint256 i) internal pure {
        assembly ("memory-safe") {
            mstore(buf, I)
            mstore(add(buf, 16), or(shl(224, q), shl(208, i)))
        }
    }

    /// One chain step, after `chainPrefix`: H(I || u32str(q) || u16str(i) || u8str(j) || tmp),
    /// truncated to n bytes by `mask` (the top n bytes of a word).
    function chainStep(uint256 buf, uint256 j, bytes32 tmp, uint256 n, bytes32 mask)
        internal
        view
        returns (bytes32 out)
    {
        assembly ("memory-safe") {
            mstore8(add(buf, 22), j)
            mstore(add(buf, 23), tmp)
            if iszero(staticcall(gas(), 2, buf, add(23, n), 0x00, 32)) { revert(0, 0) }
            out := and(mload(0x00), mask)
        }
    }

    /// Algorithm 4b, steps 1–4: the candidate LM-OTS public key Kc. `ots` points at the
    /// LM-OTS signature's C (after its typecode); `y` follows it.
    function candidateKey(bytes16 I, uint256 q, Layout memory lay, uint256 ots, uint256 msgPtr, uint256 msgLen)
        internal
        view
        returns (bytes32 Kc)
    {
        uint256 n = lay.n;
        bytes32 mask = _mask(n);
        // Q = H(I || u32str(q) || u16str(D_MESG) || C || message)
        bytes32 Q;
        {
            uint256 len = 22 + n + msgLen;
            uint256 buf = _alloc(len + 32);
            assembly ("memory-safe") {
                mstore(buf, I)
                mstore(add(buf, 16), or(shl(224, q), shl(208, 0x8181)))
                mcopy(add(buf, 22), ots, n)
                mcopy(add(add(buf, 22), n), msgPtr, msgLen)
                if iszero(staticcall(gas(), 2, buf, len, 0x00, 32)) { revert(0, 0) }
                Q := and(mload(0x00), mask)
            }
        }
        uint256 ck = checksum(Q, n, lay.w, lay.ls);

        // Kc = H(I || u32str(q) || u16str(D_PBLC) || z[0] || ... || z[p-1])
        uint256 kLen = 22 + n * lay.p;
        uint256 kbuf = _alloc(kLen + 32);
        uint256 cbuf = _alloc(23 + 64);
        assembly ("memory-safe") {
            mstore(kbuf, I)
            mstore(add(kbuf, 16), or(shl(224, q), shl(208, 0x8080)))
        }
        uint256 y = ots + n;
        for (uint256 i; i < lay.p; ++i) {
            bytes32 yi;
            assembly ("memory-safe") {
                yi := and(mload(add(y, mul(i, n))), mask)
            }
            bytes32 z = chain(I, q, i, digitAt(Q, n, ck, i, lay.w), lay.w, yi, n, cbuf);
            assembly ("memory-safe") {
                // z[i] in ascending order: the 32-byte store's tail is overwritten by z[i+1].
                mstore(add(add(kbuf, 22), mul(i, n)), z)
            }
        }
        assembly ("memory-safe") {
            if iszero(staticcall(gas(), 2, kbuf, kLen, 0x00, 32)) { revert(0, 0) }
            Kc := and(mload(0x00), mask)
        }
    }

    // ── LMS (Algorithm 6a, step 4) ───────────────────────────────────────────

    /// Climb from leaf q to the root: steps 4.b–4.c of Algorithm 6a. `path` points at the
    /// h authentication-path nodes of m bytes each; `buf` is scratch of at least 22 + 2m + 32.
    function climb(bytes16 I, uint256 q, uint256 h, uint256 m, bytes32 Kc, uint256 path, uint256 buf)
        internal
        view
        returns (bytes32 tmp)
    {
        bytes32 mask = _mask(m);
        uint256 node = (1 << h) + q;
        assembly ("memory-safe") {
            mstore(buf, I)
            mstore(add(buf, 16), or(shl(224, node), shl(208, 0x8282)))
            mstore(add(buf, 22), Kc)
            if iszero(staticcall(gas(), 2, buf, add(22, m), 0x00, 32)) { revert(0, 0) }
            tmp := and(mload(0x00), mask)
        }
        for (uint256 i; node > 1; ++i) {
            assembly ("memory-safe") {
                mstore(add(buf, 16), or(shl(224, shr(1, node)), shl(208, 0x8383)))
                let pi := and(mload(add(path, mul(i, m))), mask)
                switch and(node, 1)
                case 1 {
                    mstore(add(buf, 22), pi)
                    mstore(add(add(buf, 22), m), tmp)
                }
                default {
                    mstore(add(buf, 22), tmp)
                    mstore(add(add(buf, 22), m), pi)
                }
                if iszero(staticcall(gas(), 2, buf, add(22, mul(2, m)), 0x00, 32)) { revert(0, 0) }
                tmp := and(mload(0x00), mask)
            }
            node >>= 1;
        }
    }

    // ── Composition ──────────────────────────────────────────────────────────

    function _verifyLMS(uint256 pubPtr, uint256 pubLen, uint256 msgPtr, uint256 msgLen, uint256 sigPtr, uint256 sigLen)
        private
        view
        returns (bool)
    {
        (bool ok, Layout memory lay) = parseLMS(pubPtr, pubLen, sigPtr, sigLen);
        if (!ok) return false;
        bytes16 I;
        bytes32 T1;
        bytes32 mask = _mask(lay.m);
        assembly ("memory-safe") {
            I := and(mload(add(pubPtr, 8)), not(sub(shl(128, 1), 1)))
            T1 := and(mload(add(pubPtr, 24)), mask)
        }
        bytes32 Kc = candidateKey(I, lay.q, lay, sigPtr + 8, msgPtr, msgLen);
        uint256 path = sigPtr + 12 + lay.n * (lay.p + 1);
        return climb(I, lay.q, lay.h, lay.m, Kc, path, _alloc(22 + 64 + 32)) == T1;
    }

    // ── Memory helpers ───────────────────────────────────────────────────────

    function _ptr(bytes memory b) private pure returns (uint256 p) {
        assembly ("memory-safe") {
            p := add(b, 32)
        }
    }

    function _u32(uint256 ptr) private pure returns (uint256 v) {
        assembly ("memory-safe") {
            v := shr(224, mload(ptr))
        }
    }

    /// The top n bytes of a word.
    function _mask(uint256 n) private pure returns (bytes32) {
        return bytes32(type(uint256).max << (8 * (32 - n)));
    }

    function _alloc(uint256 len) private pure returns (uint256 p) {
        assembly ("memory-safe") {
            p := mload(0x40)
            mstore(0x40, add(p, and(add(len, 31), not(31))))
        }
    }
}
