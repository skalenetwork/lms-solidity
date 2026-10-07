# What is proven about `src/LMS.sol`

This page states exactly what the formal proofs establish, what is argued by hand on top of
them, and what is only tested. Read it before relying on the word "proven".

## Setting

- **Specification.** `test/proof/RFC8554.sol` is a line-by-line Solidity transcription of
  RFC 8554's verification algorithms, with SP 800-208's SHA-256/192 parameter sets. It is
  written for readability against the RFC text: `bytes`, `abi.encodePacked`, and `sha256`
  truncated to n bytes. It shares no code with `src/LMS.sol`. It accepts the same test vectors
  (`test_specificationAcceptsTheVectors`).
- **Tool.** Halmos 0.3.3, with the SHA-256 model fix the CI applies, symbolically executing
  the bytecode of solc 0.8.37 (via-IR, optimizer 200 runs, EVM `cancun`) pinned in
  `foundry.toml`. A different compiler or setting is a different program and needs a new run.
- **Hash model.** SHA-256 is an *uninterpreted function*: the proofs assume nothing about it,
  not even collision resistance. A lemma therefore shows that the verifier hashes exactly the
  byte strings the RFC hashes, in the same order, and combines the results the same way.
- **Run.** `halmos --match-contract LMSEquivalence --loop 300 --solver-timeout-assertion 0`,
  on a clean build (`forge clean` first: artifacts from `forge test` lack the AST Halmos
  needs). The full run takes about 12 minutes, most of it the two w = 1 checksum lemmas.
  `scripts/check_proof_run.py` fails the run if any lemma did not pass, if a lemma explored no
  path, if the loop bound does not exceed p = 265 (the longest loop), or if this file does not
  state the pinned solc version.

## Lemmas (`test/proof/LMSEquivalence.t.sol`)

Every argument is symbolic: a PASS means the property holds for **all** values.

| Lemma | Statement | Parameter sets |
|---|---|---|
| 1a `check_checksum_*` | For every n-byte Q, `checksum` equals the value Cksm(Q) encodes (Algorithm 2). | All 8 LM-OTS sets |
| 1b `check_digits_*` | For every n-byte Q, every 16-bit checksum value ck and every i < p, `digitAt(Q, n, ck, i, w)` = coef(Q ‖ u16str(ck), i, w) (Section 3.1.3). With 1a, the digits the verifier uses are coef(Q ‖ Cksm(Q), i, w). | All 8 LM-OTS sets |
| 2 `check_chain_*` | For every I, q, chain index i, starting digit a < 2^w and n-byte y, `chain` returns what Algorithm 4b's inner loop returns: H applied for j = a … 2^w − 2 with the RFC's preimage. | w = 1, 2, 4, both n; w = 8 for a ≥ 240 (see below) |
| 2b `check_chainStep_*` | For every I, q, i, step index j and n-byte tmp, one step (`chainPrefix`, then `chainStep`) is H(I ‖ u32str(q) ‖ u16str(i) ‖ u8str(j) ‖ tmp) truncated to n bytes. | Both n, every j |
| 3 `check_climb_*` | For every I, leaf q < 2^5, leaf key Kc and authentication path, `climb` returns Algorithm 6a's root (steps 4.b–4.c), including the left/right choice at every level. | h = 5, m = 32 and 24 |
| 4 `check_parse` | For every public-key length, signature length, typecode and leaf index, `parseLMS` accepts exactly when Algorithm 6a's checks pass (in the RFC's order, plus SP 800-208's n = m). When it accepts, it extracts the same n, w, p, ls, m, h and q. | All typecodes (symbolic) |
| 5 `check_hssLengths` | For every byte length and typecode, the lengths HSS parsing derives for an embedded LMS signature and public key equal the specification's. | All typecodes (symbolic) |

### w = 8 chains, and heights above 5

A w = 8 chain runs up to 255 steps. Proving the full chain symbolically for every starting
digit nests up to 255 hash applications per path, which the solver did not finish in hours.
So the full range is covered in two parts:

- **Lemma 2 for w = 8 with a ≥ 240.** The verifier's loop matches the RFC's for the last 15
  steps, from every starting point in that window.
- **Lemma 2b for every step j.** `chain` is literally `chainPrefix` followed by
  `for (j = a; j < 2^w − 1; ++j) tmp = chainStep(buf, j, tmp, n, mask)`, the same loop shape
  and range as the RFC's.

Since both loops apply the same proven step over the same j range, the full chain follows by
induction on the number of steps. Lemma 2 at w = 1, 2 and 4 confirms that the loop's range and
order are right for every starting digit.

Likewise, `climb`'s loop body does not depend on h, only how often it runs. Lemma 3 proves
every left/right pattern over five levels. A height-10 instance (1,024 paths) was attempted and
abandoned as too slow. Heights 10–25 are covered by that structural argument and by the test
vectors, which include h = 10 from `hsslms` and synthetic trees at h = 15, 20 and 25.

## The proofs have teeth

A proof that passes no matter what the code does proves nothing. `scripts/check_teeth.sh`
plants seven bugs, one at a time, in a scratch copy of `src/LMS.sol`, and requires the lemma
that covers each one to fail with a counterexample. Every one is caught:

| Planted bug | Caught by |
|---|---|
| An odd node puts its own hash on the left instead of the right | `check_climb_H5_M32` |
| A chain step hashes one byte too few | `check_chainStep_N32` |
| Digits are read from the wrong end of the byte | `check_digits_N32_W4` |
| The checksum sums the digits instead of their complements | `check_checksum_N32_W8` |
| SP 800-208's n = m check is dropped | `check_parse` |
| Leaf q = 2^h is accepted | `check_parse` |
| An embedded LMS signature is measured 4 bytes too long | `check_hssLengths` |

## Argued by hand, on top of the lemmas

- **The candidate key (Algorithm 4b).** `candidateKey` builds Q's preimage
  I ‖ u32str(q) ‖ u16str(D_MESG) ‖ C ‖ message. It takes every digit from `digitAt` with
  `checksum`'s value (lemmas 1a and 1b) and every z[i] from `chain` at that digit (lemmas 2
  and 2b). It writes z[0..p−1] in order after I ‖ u32str(q) ‖ u16str(D_PBLC) and hashes the
  result: steps 2–4 of Algorithm 4b. The p-fold loop runs p = 26 to 265 chains, each from a symbolic digit, and
  is not run symbolically end to end, because the paths multiply. It is a straight loop with
  no data-dependent control flow beyond what lemmas 1 and 2 cover. The fuzz and vector tests
  run it end to end.
- **`verifyLMS`.** This is `parseLMS` (lemma 4), then `candidateKey` on the signature's
  LM-OTS part, then `climb` (lemma 3) on its path, compared with T1. Those are Algorithm 6a's
  steps 3 and 4 in order.
- **`verifyHSS`.** It walks the signature with the lengths of lemma 5, verifies each level's
  signature over the next level's encoded public key, and verifies the message at the bottom:
  Section 6.3.

## Tested, not proven

- RFC 8554 Appendix F's two test cases, and 45 vectors that two independent implementations
  accept: `hsslms` and `py/lms_ref.py`. They cover every LM-OTS set at both hash widths,
  heights 5–25 and HSS with 1–3 levels. See the README.
- Agreement of the whole verifier with the specification: on fuzzed arbitrary input, on
  fuzzed single-byte mutations of real signatures, and on every vector.

## Not covered

- **Statefulness.** Leaf reuse is the signer's and the calling contract's responsibility.
  Nothing here can detect it.
- The SHAKE256 parameter sets of SP 800-208.
- Properties of SHA-256 itself, the EVM, the compiler beyond the pinned configuration, and
  the Halmos model.
