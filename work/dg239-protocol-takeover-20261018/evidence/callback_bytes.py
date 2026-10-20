"""Local native receive-callback arithmetic/copy proof, not a full CFG proof."""
import json
from pathlib import Path
from binary_evidence import Sample

MASK = (1 << 64) - 1
EXPECTED = {
    0x1003A9CD0: "6b0140f98e0140f96d012e8a6c012eaaec032caa8c7d0d9b6d010e8a6b010eaa6b7d0d9b6b010c8b4b0100f94a0140f94a0100f1ea179f1a",
    0x1003A9550: "6b5640f96a1a40f9694a40f9685240f9080140f96c0140f908010c8b08014039290140f94a0140f96c0140f90b0080d26a010aeb6b010ceb4a010b8b29010aeb28010039",
    0x1003A9E48: "686640f96a3a40f9691a40f96b3240f92b0100f9290140f94a0140f922010a8b000140f9c84000b0019543f9483f00f0085d41f900013fd6",
}


def count(a, b):
    a, b = a & MASK, b & MASK
    # ORN operand is ~b: MVN(OR(a, ~b)) is ~a & b, not ~(a | b).
    return ((a & ~b) * (~(a | (~b & MASK)) & MASK) + (a | b) * (a & b)) & MASK


def build(sample):
    windows = []
    for va, expected in EXPECTED.items():
        w = sample.window(va, len(bytes.fromhex(expected)))
        if w["bytes"] != expected:
            raise ValueError(f"callback original bytes mismatch at {va:#x}")
        windows.append(w)
    selectors = {hex(va): sample.selector(va) for va in [0x100BC2728, 0x100BC1550, 0x100BC1568]}
    if list(selectors.values()) != ["setLength:", "length", "mutableBytes"]:
        raise ValueError("callback selector mismatch")
    return {"sample_sha256": sample.sha256, "windows": windows, "selectors": selectors,
            "count_identity": {"A": "a & ~b", "B": "~a & b", "C": "a & b",
                               "disjoint": "A,B,C pairwise bit-disjoint",
                               "equalities": ["a=A+C", "b=B+C", "a|b=A+B+C",
                                              "A*B+(A+B+C)*C=(A+C)*(B+C)"],
                               "width": "all arithmetic modulo 2^64"},
            "local_effects": ["setLength(oldLength+count), not appendBytes",
                              "byte loop writes dest[oldLength+i]=source[i]",
                              "call-free copy window has no implicit source copy"],
            "open": ["full CFF reachability and zero/failure branches",
                     "overflow checks and allocation-failure behavior",
                     "source/destination aliasing across setLength mutation",
                     "actual request-handle/callback/context identity",
                     "received bytes to parser input conversion"]}


if __name__ == "__main__":
    result = build(Sample())
    path = Path(__file__).resolve().parents[1] / "report/callback-bytes.json"
    path.write_text(json.dumps(result, indent=2) + "\n")
    print("Verified 3 original byte windows and 3 selector slots; full callback remains open")
