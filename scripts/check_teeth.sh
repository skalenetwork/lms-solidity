#!/bin/bash
# The proofs have teeth: plant one bug at a time in a scratch copy of src/LMS.sol and require
# the lemma that covers it to FAIL (a counterexample, not a PASS). Run from the repository root.
#
#   scripts/check_teeth.sh
set -u
ROOT=$(pwd)
caught=0; survived=0
run() { # description, lemma, old text, new text
  T=$(mktemp -d)
  cp -r "$ROOT/src" "$ROOT/test" "$ROOT/foundry.toml" "$ROOT/remappings.txt" "$T/" && ln -s "$ROOT/lib" "$T/lib"
  python3 - "$T/src/LMS.sol" "$3" "$4" <<'PY'
import sys
p, old, new = sys.argv[1:]
s = open(p).read()
assert s.count(old) == 1, old
open(p, "w").write(s.replace(old, new))
PY
  (cd "$T" && timeout 900 halmos --match-contract LMSEquivalence --function "^$2\$" --loop 300 \
     --solver-timeout-assertion 0 > out.log 2>&1)
  if sed 's/\x1b\[[0-9;]*m//g' "$T/out.log" | grep -qE "^\[FAIL\]|^Counterexample"; then
    echo "caught    $1  ($2)"; caught=$((caught + 1))
  else
    echo "SURVIVED  $1  ($2)"; survived=$((survived + 1))
  fi
  rm -rf "$T"
}
run "climb: an odd node puts tmp on the left" check_climb_H5_M32 \
  $'case 1 {\n                    mstore(add(buf, 22), pi)\n                    mstore(add(add(buf, 22), m), tmp)' \
  $'case 1 {\n                    mstore(add(buf, 22), tmp)\n                    mstore(add(add(buf, 22), m), pi)'
run "chainStep: hashes one byte short" check_chainStep_N32 \
  'staticcall(gas(), 2, buf, add(23, n), 0x00, 32)' 'staticcall(gas(), 2, buf, add(22, n), 0x00, 32)'
run "digitAt: digits read from the wrong end of the byte" check_digits_N32_W4 \
  'uint256 shift = 8 - (w * (i % (8 / w)) + w);' 'uint256 shift = w * (i % (8 / w));'
run "checksum: sums digits instead of their complements" check_checksum_N32_W8 \
  's += mask - digitAt(Q, n, 0, i, w);' 's += digitAt(Q, n, 0, i, w);'
run "parseLMS: n == m not enforced" check_parse '        if (lay.n != lay.m) return (false, lay);' ''
run "parseLMS: leaf q = 2^h accepted" check_parse 'lay.q >= (1 << lay.h)' 'lay.q > (1 << lay.h)'
run "lmsSignatureLength: 4 bytes too long" check_hssLengths \
  'return (true, 12 + n * (p + 1) + m * h);' 'return (true, 16 + n * (p + 1) + m * h);'
echo "$caught caught, $survived survived"
[ "$survived" -eq 0 ]
