// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test, console} from "forge-std/Test.sol";
import {LMS} from "../src/LMS.sol";
import {RFC8554} from "./proof/RFC8554.sol";

/// External entry points, so gas is measured per call and memory starts fresh.
contract LMSHarness {
    function verifyLMS(bytes calldata pub, bytes calldata message, bytes calldata sig) external view returns (bool) {
        return LMS.verifyLMS(pub, message, sig);
    }

    function verifyHSS(bytes calldata pub, bytes calldata message, bytes calldata sig) external view returns (bool) {
        return LMS.verifyHSS(pub, message, sig);
    }
}

/// The specification, behind the same kind of entry point.
contract SpecHarness {
    function verifyLMS(bytes calldata pub, bytes calldata message, bytes calldata sig) external pure returns (bool) {
        return RFC8554.lmsVerify(message, sig, pub);
    }

    function verifyHSS(bytes calldata pub, bytes calldata message, bytes calldata sig) external pure returns (bool) {
        return RFC8554.hssVerify(message, sig, pub);
    }
}

/// Vectors: test/vectors/lms.json, from py/gen_vectors.py — the two test cases
/// of RFC 8554 Appendix F, keys and signatures from the independent `hsslms` implementation,
/// and synthetic trees at heights 15–25, each checked by two Python implementations before
/// it was written.
contract LMSTest is Test {
    LMSHarness internal impl;
    SpecHarness internal spec;

    bytes[] internal lmsPub;
    bytes[] internal lmsMsg;
    bytes[] internal lmsSig;
    string[] internal lmsLabel;
    bytes[] internal hssPub;
    bytes[] internal hssMsg;
    bytes[] internal hssSig;
    string[] internal hssLabel;

    function setUp() public {
        impl = new LMSHarness();
        spec = new SpecHarness();
        string memory j = vm.readFile("test/vectors/lms.json");
        lmsPub = vm.parseJsonBytesArray(j, ".lms_pub");
        lmsMsg = vm.parseJsonBytesArray(j, ".lms_msg");
        lmsSig = vm.parseJsonBytesArray(j, ".lms_sig");
        lmsLabel = vm.parseJsonStringArray(j, ".lms_label");
        hssPub = vm.parseJsonBytesArray(j, ".hss_pub");
        hssMsg = vm.parseJsonBytesArray(j, ".hss_msg");
        hssSig = vm.parseJsonBytesArray(j, ".hss_sig");
        hssLabel = vm.parseJsonStringArray(j, ".hss_label");
    }

    // ── Valid signatures ─────────────────────────────────────────────────────

    function test_rfc8554TestCasesVerify() public view {
        // The first two HSS vectors are RFC 8554 Appendix F, Test Cases 1 and 2.
        assertEq(hssLabel[0], "rfc8554-case1");
        assertEq(hssLabel[1], "rfc8554-case2");
        for (uint256 k; k < 2; k++) {
            assertTrue(impl.verifyHSS(hssPub[k], hssMsg[k], hssSig[k]), hssLabel[k]);
            assertFalse(impl.verifyHSS(hssPub[k], bytes.concat(hssMsg[k], "x"), hssSig[k]), hssLabel[k]);
        }
    }

    function test_everyLmsVectorVerifies() public view {
        assertGt(lmsPub.length, 40);
        for (uint256 k; k < lmsPub.length; k++) {
            assertTrue(impl.verifyLMS(lmsPub[k], lmsMsg[k], lmsSig[k]), lmsLabel[k]);
            assertFalse(impl.verifyLMS(lmsPub[k], bytes.concat(lmsMsg[k], "x"), lmsSig[k]), lmsLabel[k]);
        }
    }

    function test_everyHssVectorVerifies() public view {
        for (uint256 k; k < hssPub.length; k++) {
            assertTrue(impl.verifyHSS(hssPub[k], hssMsg[k], hssSig[k]), hssLabel[k]);
            assertFalse(impl.verifyHSS(hssPub[k], bytes.concat(hssMsg[k], "x"), hssSig[k]), hssLabel[k]);
        }
    }

    /// The specification the proofs compare against accepts the same vectors: it is a
    /// transcription of the RFC, not a strawman.
    function test_specificationAcceptsTheVectors() public view {
        for (uint256 k; k < lmsPub.length; k += 5) {
            assertTrue(spec.verifyLMS(lmsPub[k], lmsMsg[k], lmsSig[k]), lmsLabel[k]);
        }
        for (uint256 k; k < 2; k++) {
            assertTrue(spec.verifyHSS(hssPub[k], hssMsg[k], hssSig[k]), hssLabel[k]);
        }
    }

    // ── Every byte of a signature and key matters ────────────────────────────

    /// Flipping any single bit of the signature, at a sample of offsets covering every field
    /// (q, the LM-OTS typecode, C, each y block, the LMS typecode, each path node), rejects.
    function test_anyBitFlipInTheSignatureRejects() public view {
        for (uint256 k; k < lmsPub.length; k += 7) {
            bytes memory sig = lmsSig[k];
            uint256 step = sig.length / 97 + 1;
            for (uint256 off; off < sig.length; off += step) {
                bytes memory bad = bytes.concat(sig);
                bad[off] = bad[off] ^ 0x01;
                assertFalse(impl.verifyLMS(lmsPub[k], lmsMsg[k], bad), lmsLabel[k]);
            }
        }
    }

    function test_anyBitFlipInThePublicKeyRejects() public view {
        for (uint256 k; k < lmsPub.length; k += 7) {
            bytes memory pub = lmsPub[k];
            for (uint256 off; off < pub.length; off++) {
                bytes memory bad = bytes.concat(pub);
                bad[off] = bad[off] ^ 0x80;
                assertFalse(impl.verifyLMS(bad, lmsMsg[k], lmsSig[k]), lmsLabel[k]);
            }
        }
    }

    function test_truncatedOrExtendedRejects() public view {
        bytes memory pub = lmsPub[0];
        bytes memory sig = lmsSig[0];
        assertFalse(impl.verifyLMS(pub, lmsMsg[0], bytes.concat(sig, hex"00")));
        bytes memory short = new bytes(sig.length - 1);
        for (uint256 i; i < short.length; i++) short[i] = sig[i];
        assertFalse(impl.verifyLMS(pub, lmsMsg[0], short));
        assertFalse(impl.verifyLMS(bytes.concat(pub, hex"00"), lmsMsg[0], sig));
        assertFalse(impl.verifyLMS(pub, lmsMsg[0], ""));
        assertFalse(impl.verifyLMS("", lmsMsg[0], sig));
        assertFalse(impl.verifyLMS(hex"00000005", lmsMsg[0], hex"0000000000000004"));
    }

    // ── HSS structure ────────────────────────────────────────────────────────

    function test_hssLevelCountMustMatch() public view {
        bytes memory pub = hssPub[0]; // L = 2
        bytes memory sig = hssSig[0]; // Nspk = 1
        bytes memory pubL3 = bytes.concat(pub);
        pubL3[3] = 0x03;
        assertFalse(impl.verifyHSS(pubL3, hssMsg[0], sig));
        bytes memory sigN0 = bytes.concat(sig);
        sigN0[3] = 0x00;
        assertFalse(impl.verifyHSS(pub, hssMsg[0], sigN0));
        bytes memory pubL0 = bytes.concat(pub);
        pubL0[3] = 0x00;
        assertFalse(impl.verifyHSS(pubL0, hssMsg[0], sig));
        bytes memory pubL9 = bytes.concat(pub);
        pubL9[3] = 0x09;
        assertFalse(impl.verifyHSS(pubL9, hssMsg[0], sig));
    }

    /// A bit flip in the signed lower-level public key (inside the HSS signature) rejects,
    /// although the bottom signature is unchanged and valid for the flipped key's... nothing.
    function test_hssSignedPublicKeyIsBound() public view {
        bytes memory pub = hssPub[0];
        bytes memory sig = hssSig[0];
        (, uint256 sl) = RFC8554.lmsSigLen(sig, 4);
        uint256 pubOff = 4 + sl;
        for (uint256 off = pubOff; off < pubOff + 56; off += 5) {
            bytes memory bad = bytes.concat(sig);
            bad[off] = bad[off] ^ 0x01;
            assertFalse(impl.verifyHSS(pub, hssMsg[0], bad));
        }
    }

    /// SP 800-208: a SHA-256/192 OTS signature inside a SHA-256 tree is refused even when the
    /// lengths are consistent.
    function test_mixedHashWidthsRejected() public view {
        // pub: LMS_SHA256_M32_H5 (5) with LMOTS_SHA256_N24_W8 (8).
        bytes memory pub = bytes.concat(bytes4(uint32(5)), bytes4(uint32(8)), bytes16(0), bytes32(0));
        bytes memory sig = new bytes(12 + 24 * 27 + 32 * 5);
        sig[7] = 0x08;
        sig[8 + 24 * 27 + 3] = 0x05;
        assertFalse(impl.verifyLMS(pub, "m", sig));
        assertFalse(spec.verifyLMS(pub, "m", sig));
    }

    // ── Agreement with the specification on arbitrary input ─────────────────

    /// On arbitrary bytes, the verifier never reverts and agrees with the specification.
    function testFuzz_agreesWithSpecificationOnArbitraryInput(bytes calldata pub, bytes calldata msg_, bytes calldata sig)
        public
        view
    {
        assertEq(impl.verifyLMS(pub, msg_, sig), spec.verifyLMS(pub, msg_, sig));
        assertEq(impl.verifyHSS(pub, msg_, sig), spec.verifyHSS(pub, msg_, sig));
    }

    /// Single-byte mutations of a real signature: never a revert, always the specification's
    /// answer (which, for any change, is rejection).
    function testFuzz_mutatedSignatureAgreesWithSpecification(uint256 which, uint256 off, uint8 x) public view {
        uint256 k = (which % (lmsPub.length / 3)) * 3;
        bytes memory sig = bytes.concat(lmsSig[k]);
        off = off % sig.length;
        sig[off] = bytes1(x);
        bool expected = spec.verifyLMS(lmsPub[k], lmsMsg[k], sig);
        assertEq(impl.verifyLMS(lmsPub[k], lmsMsg[k], sig), expected);
    }

    // ── Gas ──────────────────────────────────────────────────────────────────

    function test_gas() public view {
        for (uint256 k; k < lmsPub.length; k++) {
            if (lmsMsg[k].length != 32) continue;
            uint256 g = gasleft();
            impl.verifyLMS(lmsPub[k], lmsMsg[k], lmsSig[k]);
            console.log(lmsLabel[k], g - gasleft());
        }
        for (uint256 k; k < hssPub.length; k++) {
            uint256 g = gasleft();
            impl.verifyHSS(hssPub[k], hssMsg[k], hssSig[k]);
            console.log(hssLabel[k], g - gasleft());
        }
    }
}
