#!/usr/bin/env python3
"""Guard the Halmos proof run against silent failure.

1. Loop bound: Halmos unrolls loops up to --loop and proves properties of the unrolled
   program without failing when a loop is cut short. The bound must exceed the longest loop
   the lemmas run: p = 265 LM-OTS digits (LMOTS_SHA256_N32_W1).
2. Every lemma ran and passed: each check_ function in the proof file appears as [PASS].
3. Vacuity: each lemma explored at least one path (a vm.assume that excludes every input
   would pass on nothing).
4. The proof is of bytecode from one compiler configuration; PROOF.md must state it.

With --ci, the run is CI's: the two w = 1 checksum lemmas need more memory than a hosted
runner has and are run locally (PROOF.md). Exactly those two may be absent; every other
lemma must pass.

Usage: check_proof_run.py [--ci] <loop-bound> <halmos-output-file>
"""
import os
import re
import sys

CI_SKIPPED = {"check_checksum_N24_W1", "check_checksum_N32_W1"}

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.join(HERE, "..")
args = sys.argv[1:]
ci = args[:1] == ["--ci"]
if ci:
    args = args[1:]
loop_bound = int(args[0])
out = re.sub(r"\x1b\[[0-9;]*m", "", open(args[1]).read())

if loop_bound <= 265:
    sys.exit(f"--loop {loop_bound} does not exceed p = 265: Halmos would truncate the digit loop")

toml = open(os.path.join(ROOT, "foundry.toml")).read()
pinned = re.search(r'solc_version\s*=\s*"([^"]+)"', toml).group(1)
if f"solc {pinned}" not in open(os.path.join(ROOT, "PROOF.md")).read():
    sys.exit(f"foundry.toml pins solc {pinned} but PROOF.md does not state that version")

proof_src = open(os.path.join(ROOT, "test", "proof", "LMSEquivalence.t.sol")).read()
# Under an uninterpreted hash an inequality between hash outputs is unprovable; lemmas must
# be equalities.
if re.search(r"assertNotEq\s*\(", proof_src):
    sys.exit("assertNotEq in the proof file: a hash inequality cannot be proven")
checks = set(re.findall(r"function (check_\w+)\(", proof_src))
passed = dict(re.findall(r"\[PASS\] (check_\w+)\([^)]*\) \(paths: (\d+)", out))
missing = checks - set(passed)
if ci:
    if not CI_SKIPPED <= checks:
        sys.exit(f"--ci skips lemmas that are not in the proof file: {sorted(CI_SKIPPED - checks)}")
    if missing != CI_SKIPPED:
        sys.exit(f"lemmas that did not PASS: {sorted(missing - CI_SKIPPED)}; "
                 f"CI must skip exactly {sorted(CI_SKIPPED)}, and skipped {sorted(missing)}")
elif missing:
    sys.exit(f"lemmas that did not PASS: {sorted(missing)}")
empty = sorted(c for c, n in passed.items() if int(n) < 1)
if empty:
    sys.exit(f"lemmas that explored no path: {empty}")
if re.search(r"\[(FAIL|ERROR|TIMEOUT)\]", out):
    sys.exit("the run reports a FAIL, ERROR or TIMEOUT")
print(f"{len(checks) - len(missing)} lemmas passed at --loop {loop_bound}"
      + (f" (CI; run locally: {sorted(missing)})" if missing else ""))
