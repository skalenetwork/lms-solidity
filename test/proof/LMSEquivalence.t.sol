// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {LMS} from "../../src/LMS.sol";
import {RFC8554} from "./RFC8554.sol";

/// @title Equivalence of src/lms/LMS.sol with RFC 8554 (see PROOF.md)
/// @notice `check_*` functions are symbolic proofs run by Halmos: every argument is symbolic,
///         so a PASS means the assertion holds for ALL inputs, with SHA-256 modelled as an
///         uninterpreted function — the result does not depend on any property of SHA-256.
///         Each lemma compares one step of the verifier with RFC8554.sol, a transcription of
///         the RFC that shares no code with it.
///
///         halmos --match-contract LMSEquivalence --loop 300 --solver-timeout-assertion 0
contract LMSEquivalence is Test {
    function _mask(uint256 n) internal pure returns (bytes32) {
        return bytes32(type(uint256).max << (8 * (32 - n)));
    }

    function _bytes(bytes32 v, uint256 n) internal pure returns (bytes memory out) {
        out = new bytes(n);
        for (uint256 k; k < n; k++) {
            out[k] = v[k];
        }
    }

    function _word(bytes memory b) internal pure returns (bytes32 v) {
        for (uint256 k; k < b.length; k++) {
            v |= bytes32(b[k]) >> (8 * k);
        }
    }

    function _scratch(uint256 len) internal pure returns (uint256 p) {
        bytes memory buf = new bytes(len);
        assembly ("memory-safe") {
            p := add(buf, 32)
        }
    }

    // ── Lemma 1: checksum and digits == Cksm and coef (Algorithm 2, Section 3.1.3) ──

    /// 1a. For every n-byte Q: `checksum` equals the value Cksm(Q) encodes.
    function _checkChecksum(uint32 t, bytes32 Qraw) internal pure {
        (, uint256 n, uint256 w,, uint256 ls) = LMS.otsParams(t);
        bytes32 Q = Qraw & _mask(n);
        bytes memory c = RFC8554.Cksm(_bytes(Q, n), n, w, ls);
        assertEq(LMS.checksum(Q, n, w, ls), uint256(uint8(c[0])) << 8 | uint8(c[1]));
    }

    /// 1b. For every n-byte Q, every 16-bit checksum value ck and every i < p: the verifier's
    /// digit i equals coef(Q || u16str(ck), i, w). With 1a, the digits `candidateKey` uses are
    /// exactly coef(Q || Cksm(Q), i, w).
    function _checkDigits(uint32 t, bytes32 Qraw, uint16 ck) internal pure {
        (, uint256 n, uint256 w, uint256 p,) = LMS.otsParams(t);
        bytes32 Q = Qraw & _mask(n);
        bytes memory Qc = abi.encodePacked(_bytes(Q, n), RFC8554.u16str(ck));
        for (uint256 i; i < p; i++) {
            assertEq(LMS.digitAt(Q, n, ck, i, w), RFC8554.coef(Qc, i, w));
        }
    }

    function check_checksum_N32_W1(bytes32 Q) public pure {
        _checkChecksum(1, Q);
    }

    function check_digits_N32_W1(bytes32 Q, uint16 ck) public pure {
        _checkDigits(1, Q, ck);
    }

    function check_checksum_N32_W2(bytes32 Q) public pure {
        _checkChecksum(2, Q);
    }

    function check_digits_N32_W2(bytes32 Q, uint16 ck) public pure {
        _checkDigits(2, Q, ck);
    }

    function check_checksum_N32_W4(bytes32 Q) public pure {
        _checkChecksum(3, Q);
    }

    function check_digits_N32_W4(bytes32 Q, uint16 ck) public pure {
        _checkDigits(3, Q, ck);
    }

    function check_checksum_N32_W8(bytes32 Q) public pure {
        _checkChecksum(4, Q);
    }

    function check_digits_N32_W8(bytes32 Q, uint16 ck) public pure {
        _checkDigits(4, Q, ck);
    }

    function check_checksum_N24_W1(bytes32 Q) public pure {
        _checkChecksum(5, Q);
    }

    function check_digits_N24_W1(bytes32 Q, uint16 ck) public pure {
        _checkDigits(5, Q, ck);
    }

    function check_checksum_N24_W2(bytes32 Q) public pure {
        _checkChecksum(6, Q);
    }

    function check_digits_N24_W2(bytes32 Q, uint16 ck) public pure {
        _checkDigits(6, Q, ck);
    }

    function check_checksum_N24_W4(bytes32 Q) public pure {
        _checkChecksum(7, Q);
    }

    function check_digits_N24_W4(bytes32 Q, uint16 ck) public pure {
        _checkDigits(7, Q, ck);
    }

    function check_checksum_N24_W8(bytes32 Q) public pure {
        _checkChecksum(8, Q);
    }

    function check_digits_N24_W8(bytes32 Q, uint16 ck) public pure {
        _checkDigits(8, Q, ck);
    }

    // ── Lemma 2: chain == Algorithm 4b, step 3's inner loop ─────────────────

    /// For every I, q, i, starting digit a < 2^w and n-byte y: equal chain ends.
    function _checkChain(uint256 w, uint256 n, bytes16 I, uint32 q, uint16 i, uint8 a, bytes32 tmp) internal view {
        vm.assume(a < (1 << w));
        tmp &= _mask(n);
        bytes32 impl = LMS.chain(I, q, i, a, w, tmp, n, _scratch(96));
        bytes memory s = RFC8554.chain(abi.encodePacked(I), q, i, a, w, _bytes(tmp, n), n);
        assertEq(impl, _word(s));
    }

    function check_chain_W1_N32(bytes16 I, uint32 q, uint16 i, uint8 a, bytes32 y) public view {
        _checkChain(1, 32, I, q, i, a, y);
    }

    function check_chain_W2_N32(bytes16 I, uint32 q, uint16 i, uint8 a, bytes32 y) public view {
        _checkChain(2, 32, I, q, i, a, y);
    }

    function check_chain_W4_N32(bytes16 I, uint32 q, uint16 i, uint8 a, bytes32 y) public view {
        _checkChain(4, 32, I, q, i, a, y);
    }

    /// w = 8 full chains run up to 255 steps; Halmos proves the last 15 of them here (a >= 240),
    /// and lemma 2b proves every single step for every j, so the whole range follows by
    /// induction (PROOF.md, "w = 8 chains").
    function check_chain_W8_N32_last15(bytes16 I, uint32 q, uint16 i, uint8 a, bytes32 y) public view {
        vm.assume(a >= 240);
        _checkChain(8, 32, I, q, i, a, y);
    }

    function check_chain_W1_N24(bytes16 I, uint32 q, uint16 i, uint8 a, bytes32 y) public view {
        _checkChain(1, 24, I, q, i, a, y);
    }

    function check_chain_W2_N24(bytes16 I, uint32 q, uint16 i, uint8 a, bytes32 y) public view {
        _checkChain(2, 24, I, q, i, a, y);
    }

    function check_chain_W4_N24(bytes16 I, uint32 q, uint16 i, uint8 a, bytes32 y) public view {
        _checkChain(4, 24, I, q, i, a, y);
    }

    function check_chain_W8_N24_last15(bytes16 I, uint32 q, uint16 i, uint8 a, bytes32 y) public view {
        vm.assume(a >= 240);
        _checkChain(8, 24, I, q, i, a, y);
    }

    // ── Lemma 2b: one chain step == the RFC's step, for every j ────────────

    /// For every I, q, chain index i, step index j and n-byte tmp: the verifier's step is
    /// H(I || u32str(q) || u16str(i) || u8str(j) || tmp) truncated to n bytes, the body of
    /// Algorithm 4b's inner loop.
    function _checkStep(uint256 n, bytes16 I, uint32 q, uint16 i, uint8 j, bytes32 tmp) internal view {
        tmp &= _mask(n);
        uint256 buf = _scratch(96);
        LMS.chainPrefix(buf, I, q, i);
        bytes32 impl = LMS.chainStep(buf, j, tmp, n, _mask(n));
        bytes memory s = RFC8554.H(
            n,
            abi.encodePacked(abi.encodePacked(I), RFC8554.u32str(q), RFC8554.u16str(i), RFC8554.u8str(j), _bytes(tmp, n))
        );
        assertEq(impl, _word(s));
    }

    function check_chainStep_N32(bytes16 I, uint32 q, uint16 i, uint8 j, bytes32 tmp) public view {
        _checkStep(32, I, q, i, j, tmp);
    }

    function check_chainStep_N24(bytes16 I, uint32 q, uint16 i, uint8 j, bytes32 tmp) public view {
        _checkStep(24, I, q, i, j, tmp);
    }

    // ── Lemma 3: climb == Algorithm 6a, steps 4.b–4.c ───────────────────────

    /// For every I, leaf q < 2^5, leaf key Kc and authentication path: equal roots, at both
    /// hash widths. The climb's code does not depend on h beyond the loop count, so heights
    /// 10–25 run the same instructions more times (PROOF.md).
    function _checkClimb(uint256 m, bytes16 I, uint32 q, bytes32 Kc, bytes32[] memory path) internal view {
        uint256 h = path.length;
        vm.assume(q < (1 << h));
        Kc &= _mask(m);
        bytes memory pathBytes;
        for (uint256 k; k < h; k++) {
            pathBytes = abi.encodePacked(pathBytes, _bytes(path[k], m));
        }
        uint256 pathPtr;
        assembly ("memory-safe") {
            pathPtr := add(pathBytes, 32)
        }
        bytes32 impl = LMS.climb(I, q, h, m, Kc, pathPtr, _scratch(22 + 64 + 32));
        bytes memory s = RFC8554.lmsRootFrom(abi.encodePacked(I), q, h, m, _bytes(Kc, m), pathBytes);
        assertEq(impl, _word(s));
    }

    function _dyn(bytes32[5] memory a) internal pure returns (bytes32[] memory d) {
        d = new bytes32[](5);
        for (uint256 k; k < 5; k++) d[k] = a[k];
    }

    function check_climb_H5_M32(bytes16 I, uint32 q, bytes32 Kc, bytes32[5] memory path) public view {
        _checkClimb(32, I, q, Kc, _dyn(path));
    }

    function check_climb_H5_M24(bytes16 I, uint32 q, bytes32 Kc, bytes32[5] memory path) public view {
        _checkClimb(24, I, q, Kc, _dyn(path));
    }

    // ── Lemma 4: parseLMS == Algorithm 6a's acceptance checks ───────────────

    /// For every public-key length, signature length, typecode and leaf index: the verifier
    /// goes on to hash exactly when the RFC's checks pass, with the same parameters.
    function check_parse(
        uint16 pubLen,
        uint32 pubtype,
        uint32 pubots,
        uint16 sigLen,
        uint32 q,
        uint32 sigots,
        uint32 sigtype
    ) public pure {
        // The public key: typecodes at 0 and 4.
        bytes memory pub = abi.encodePacked(pubtype, pubots, new bytes(56));
        // The signature: q and the OTS typecode up front, and the LMS typecode at the offset
        // each LM-OTS set would place it (8 + n(p+1)); the offsets are distinct.
        bytes memory sig = new bytes(8 + 32 * 266 + 4);
        uint256[8] memory offs = [uint256(8520), 4296, 2184, 1128, 4832, 2456, 1256, 656];
        assembly ("memory-safe") {
            let b := add(sig, 32)
            mstore(b, or(shl(224, q), shl(192, sigots)))
            for { let k := 0 } lt(k, 8) { k := add(k, 1) } {
                let o := add(b, mload(add(offs, mul(k, 32))))
                mstore(o, or(shl(224, sigtype), shr(32, shl(32, mload(add(o, 4))))))
            }
        }
        vm.assume(sigLen <= sig.length);
        uint256 pubPtr;
        uint256 sigPtr;
        assembly ("memory-safe") {
            pubPtr := add(pub, 32)
            sigPtr := add(sig, 32)
        }
        (bool ok, LMS.Layout memory lay) = LMS.parseLMS(pubPtr, pubLen, sigPtr, sigLen);
        bool expected = RFC8554.lmsHeaderOk(pubLen, pubtype, pubots, sigLen, q, sigots, sigtype);
        assertEq(ok, expected);
        if (ok) {
            (, uint256 n, uint256 w, uint256 p, uint256 ls) = RFC8554.lmotsParams(sigots);
            (, uint256 m, uint256 h) = RFC8554.lmsParams(pubtype);
            assertEq(lay.n, n);
            assertEq(lay.w, w);
            assertEq(lay.p, p);
            assertEq(lay.ls, ls);
            assertEq(lay.m, m);
            assertEq(lay.h, h);
            assertEq(lay.q, q);
        }
    }

    // ── Lemma 5: HSS parsing lengths == Section 6.3's parsing ───────────────

    /// For every byte length and typecode: the verifier's lengths of an embedded LMS
    /// signature and public key (which drive HSS parsing) equal the specification's.
    function check_hssLengths(uint16 len, uint32 q, uint32 sigots, uint32 sigtype, uint32 pubtype) public pure {
        bytes memory sig = new bytes(8 + 32 * 266 + 4);
        uint256[8] memory offs = [uint256(8520), 4296, 2184, 1128, 4832, 2456, 1256, 656];
        assembly ("memory-safe") {
            let b := add(sig, 32)
            mstore(b, or(shl(224, q), shl(192, sigots)))
            for { let k := 0 } lt(k, 8) { k := add(k, 1) } {
                let o := add(b, mload(add(offs, mul(k, 32))))
                mstore(o, or(shl(224, sigtype), shr(32, shl(32, mload(add(o, 4))))))
            }
        }
        vm.assume(len <= sig.length);
        assembly ("memory-safe") {
            mstore(sig, len)
        }
        (bool okI, uint256 lenI) = LMS.lmsSignatureLength(sig, 0);
        (bool okS, uint256 lenS) = RFC8554.lmsSigLen(sig, 0);
        assertEq(okI, okS);
        assertEq(lenI, lenS);

        bytes memory pub = abi.encodePacked(pubtype, new bytes(60));
        vm.assume(len <= pub.length);
        assembly ("memory-safe") {
            mstore(pub, len)
        }
        (okI, lenI) = LMS.lmsPublicKeyLength(pub, 0);
        (okS, lenS) = RFC8554.lmsPubLen(pub, 0);
        assertEq(okI, okS);
        assertEq(lenI, lenS);
    }
}
