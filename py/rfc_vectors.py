#!/usr/bin/env python3
"""Extract the two test cases of RFC 8554 Appendix F from the RFC text.

Usage: rfc_vectors.py <rfc8554.txt>   (https://www.rfc-editor.org/rfc/rfc8554.txt)
Prints a JSON object {"case1": {"pub", "msg", "sig"}, "case2": {...}} of hex strings.
"""
import json
import re
import sys

HEXTOK = re.compile(r"^[0-9a-f]+$")


def collect(lines):
    out = []
    for line in lines:
        s = line.strip()
        if not s or s.startswith("-") or s.startswith("RFC 8554") or s.startswith("McGrew"):
            continue
        s = s.split("#")[0]
        s = re.sub(r"\|.*\|\s*$", "", s)
        for tok in s.split():
            if HEXTOK.match(tok) and len(tok) % 2 == 0 and len(tok) >= 2:
                out.append(tok)
    return bytes.fromhex("".join(out))


def main(path):
    text = open(path).read().splitlines()
    start = next(i for i, l in enumerate(text) if l.startswith("Appendix F."))
    text = text[start:]
    heads = [(i, l.strip()) for i, l in enumerate(text) if re.match(r"^\s+Test Case \d ", l)]
    sections = {}
    for k, (i, name) in enumerate(heads):
        end = heads[k + 1][0] if k + 1 < len(heads) else len(text)
        # The last section runs to the end of Appendix F.
        body = text[i + 1:end]
        if k + 1 == len(heads):
            body = [l for l in body if not l.startswith("Acknowledgements")]
            stop = next((j for j, l in enumerate(body) if l.startswith("Acknowledgements")), len(body))
            body = body[:stop]
        sections[name] = collect(body)
    out = {}
    for c in (1, 2):
        out[f"case{c}"] = {
            "pub": sections[f"Test Case {c} Public Key"].hex(),
            "msg": sections[f"Test Case {c} Message"].hex(),
            "sig": sections[f"Test Case {c} Signature"].hex(),
        }
    json.dump(out, sys.stdout, indent=1)


if __name__ == "__main__":
    main(sys.argv[1])
