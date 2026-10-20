"""Original call arguments only; storeStrong effects and path order stay open."""
import json
from pathlib import Path

from receive_slices import Sample

PINS = {
    0x100843FB0: "60b248f9010080d290700a94",
    0x100849B48: "60b248f961ba41f9aa590a94",
}


def build(sample):
    windows = []
    for va, pin in PINS.items():
        window = sample.window(va, len(bytes.fromhex(pin)))
        if window["bytes"] != pin or len(window["instructions"]) != 3:
            raise ValueError(f"original call window changed at {va:#x}")
        windows.append(window)
    stub = sample.stub_symbol(0x100AE01F8)
    if stub["name"] != "_objc_storeStrong":
        raise ValueError("storeStrong import identity changed")
    return {
        "sample_sha256": sample.sha256,
        "windows": windows,
        "import": stub,
        "scope": "Two prepared calls, not executed writes or a connected CFG",
        "target_argument": "x0 is loaded from current frame+0x1160",
        "value_arguments": {"0x100843fb0": "zero", "0x100849b48": "current frame+0x370"},
        "call_barriers": ["0x100843fb8", "0x100849b50"],
        "effects_proven": False,
        "same_request_order_proven": False,
        "parser_input_identity_proven": False,
    }


if __name__ == "__main__":
    target = Path(__file__).resolve().parents[1] / "report/parser-slot-writers.json"
    with target.open("x") as out:
        json.dump(build(Sample()), out, indent=2)
        out.write("\n")
