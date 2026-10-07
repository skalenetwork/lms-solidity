#!/usr/bin/env python3
"""Guard the Halmos proof run against silent failure.

1. Loop bound: Halmos unrolls loops up to --loop and proves properties of the unrolled
   program without failing when a loop is cut short. The bound must exceed the longest loop
   the lemmas run: p = 265 LM-OTS digits (LMOTS_SHA256_N32_W1).
2. Every lemma ran and passed: each check_ function in the proof file appears as [PASS].
3. Vacuity: each lemma explored at least one path (a vm.assume that excludes every input
   would pass on nothing).
4. The proof is of bytecode from one compiler configuration; PROOF.md must state it.

Usage: check_proof_run.py <loop-bound> <halmos-output-file>
"""
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.join(HERE, "..")
loop_bound = int(sys.argv[1])
out = re.sub(r"\x1b\[[0-9;]*m", "", open(sys.argv[2]).read())

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
missing = sorted(checks - set(passed))
if missing:
    sys.exit(f"lemmas that did not PASS: {missing}")
empty = sorted(c for c, n in passed.items() if int(n) < 1)
if empty:
    sys.exit(f"lemmas that explored no path: {empty}")
if re.search(r"\[(FAIL|ERROR|TIMEOUT)\]", out):
    sys.exit("the run reports a FAIL, ERROR or TIMEOUT")
print(f"{len(checks)} lemmas passed at --loop {loop_bound}")
