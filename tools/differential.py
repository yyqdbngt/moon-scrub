#!/usr/bin/env python3
"""Library-level differential: MoonBit vs the Python reference.

Regenerates the exact corpus of examples/findings-dump with the same
Lehmer generator, runs the Python reference (scanner + redaction),
runs the MoonBit side via `moon run examples/findings-dump`, and
compares both blocks line by line. Any divergence is a finding-level
incompatibility between the two implementations.

Usage: python3 tools/differential.py [moon args, e.g. --target native]
"""

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))
import reference_scan as ref  # noqa: E402


def lcg(state):
    return (state * 48271) % 2147483647


def make_word(state, length):
    letters = "abcdefghijklmnopqrstuvwxyz"
    out = []
    for _ in range(length):
        state = lcg(state)
        out.append(letters[state % 26])
    return "".join(out), state


def corpus():
    lines = []
    state = 77
    for i in range(40):
        w, state = make_word(state, 8)
        shape = i % 8
        if shape == 0:
            lines.append(f"mail {w}@example.com")
        elif shape == 1:
            lines.append(f"password={w}value")
        elif shape == 2:
            lines.append(f"token=ghp_{w}{w}1234")
        elif shape == 3:
            lines.append(f"ip 10.0.{i % 200}.7 v1.2.3.4")
        elif shape == 4:
            lines.append("card 4111 1111 1111 1111")
        elif shape == 5:
            lines.append(f"auth: Bearer {w}{w}")
        elif shape == 6:
            lines.append("id 110105199001010010")
        else:
            lines.append(f"plain {w} request")
    return lines


def python_side():
    lines = corpus()
    blocks = []
    for line in lines:
        found = ref.non_overlapping(ref.scan_all(line, "config"))
        if not found:
            blocks.append("-")
        else:
            blocks.append("".join(f"{k} {s} {e} {c};" for k, s, e, c in found))
    for line in lines:
        blocks.append("R|" + ref.redact(line, style="typed", mode="config")[0])
    return blocks


def main():
    target = []
    if "--target" in sys.argv:
        i = sys.argv.index("--target")
        target = ["--target", sys.argv[i + 1]]
    run = subprocess.run(
        ["moon", "run", "examples/findings-dump"] + target,
        cwd=ROOT, capture_output=True, text=True, check=True,
    )
    moonbit_side = run.stdout.strip().split("\n")
    expected = python_side()
    if moonbit_side == expected:
        print(f"differential OK: {len(expected)} lines identical")
        return 0
    print("DIFFERENTIAL MISMATCH")
    for i, (m, p) in enumerate(zip(moonbit_side, expected)):
        if m != p:
            print(f"line {i}: moonbit={m!r} python={p!r}")
    return 1


if __name__ == "__main__":
    sys.exit(main())
