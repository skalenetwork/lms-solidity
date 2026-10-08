# lms-solidity

LMS and HSS signature verification in Solidity: the Leighton-Micali hash-based signatures of
[RFC 8554](https://www.rfc-editor.org/rfc/rfc8554), including the SHA-256/192 parameter sets of
[NIST SP 800-208](https://csrc.nist.gov/pubs/sp/800/208/final).

```solidity
import {LMS} from "lms-solidity/LMS.sol";

bool ok = LMS.verifyHSS(publicKey, message, signature); // RFC 8554 Section 6.3
bool ok = LMS.verifyLMS(publicKey, message, signature); // RFC 8554 Algorithms 6 and 6a
```

Keys and signatures use the RFC's byte encodings unchanged, so anything an RFC 8554
implementation produces verifies as is. That includes HSMs and libraries such as `hash-sigs`
and `hsslms`. Malformed input of any kind makes verification return `false`, never revert.

> **Unaudited.** This is new cryptographic code. It passes the RFC's own test cases, agrees
> with an independent implementation, and is formally proven step by step against a
> transcription of the RFC ([PROOF.md](PROOF.md)), but no third party has reviewed it.

> **LMS is stateful.** Each leaf of an LMS tree is a one-time key, and signing twice with one
> leaf lets an attacker forge. This library verifies signatures; it cannot know which leaves a
> signer has used. A contract that grants authority on an LMS signature must record each leaf
> it accepts (the bottom tree's `q`, under that tree's public key) and refuse it the second
> time.
>
> For the same reason this library does **not** implement
> [`IPQVerifier`](https://github.com/skalenetwork/pq-verifier-interface), the interface shared by
> the stateless verifiers (ML-DSA, SLH-DSA, FN-DSA). The interface's bare yes/no answer would let a
> caller treat an LMS signature like a stateless one and accept a reused leaf. LMS keeps its
> own API, whose callers must do the bookkeeping above.

## Parameter sets

| | Typecodes | Hash |
|---|---|---|
| LM-OTS, n = 32, w = 1, 2, 4, 8 | 1–4 | SHA-256 |
| LM-OTS, n = 24, w = 1, 2, 4, 8 | 5–8 | SHA-256/192 |
| LMS trees, m = 32, heights 5, 10, 15, 20, 25 | 5–9 | SHA-256 |
| LMS trees, m = 24, heights 5, 10, 15, 20, 25 | 10–14 | SHA-256/192 |
| HSS | 1 to 8 levels | |

An LM-OTS set and a tree must use the same hash width (SP 800-208); a mixed pair is rejected.
The SHAKE256 sets of SP 800-208 are not supported.

## Gas

Single-tree verification with a 32-byte message, measured by `forge test` (the figures include
copying the call data):

| LM-OTS | n = 32 | n = 24 |
|---|---|---|
| W1 | 1.07M | 0.71M |
| W2 | 0.61M | 0.42M |
| W4 | 0.49M | 0.36M |
| W8 | 1.95M | 1.44M |

Tree height adds only about 1,000–2,000 gas per level. The RFC's two-level HSS test cases cost 3.4M
(W8) and 2.3M (W4).

## How it is checked

- **The RFC's own test cases.** Both test cases of RFC 8554 Appendix F verify. CI re-extracts
  them from the RFC text and compares byte for byte (`scripts/check_rfc_cases.py`).
- **Two independent Python implementations.** Every committed vector, 47 in all, verifies
  under [`hsslms`](https://pypi.org/project/hsslms/) and under `py/lms_ref.py`, a line-by-line
  transcription of the RFC written for this repository. Each also fails under both once its
  message changes (`scripts/check_vectors.py`). The vectors cover every LM-OTS set at both hash
  widths, heights 5 and 10, HSS with 1–3 levels, and synthetic trees at heights 15–25. A
  synthetic tree is a real LM-OTS leaf with a random authentication path and the root it
  implies, which exercises every level without building 2^25 leaves.
- **Formal proofs.** Halmos proves, for all inputs, that each step of the verifier equals the
  same step of `test/proof/RFC8554.sol`, a Solidity transcription of the RFC that shares no
  code with it. The steps are the checksum and digits, every chain, the tree climb, and header
  and length parsing. [PROOF.md](PROOF.md) says exactly what is proven and what is argued.
- **Negative and agreement tests.** A single bit flip anywhere in a signature or key, any
  truncation or extension, mismatched HSS level counts and mixed hash widths all fail. Fuzzing
  shows the verifier never reverts and always agrees with the transcription.

```
forge test
pip install hsslms==0.1.3 && python3 scripts/check_vectors.py
halmos --match-contract LMSEquivalence --loop 300 --solver-timeout-assertion 0
```

The full proof run needs more than 16 GB of memory, so CI proves 28 of the 30 lemmas and the
two w = 1 checksum lemmas are run locally ([PROOF.md](PROOF.md)).

## License

MIT, see [LICENSE](LICENSE).
