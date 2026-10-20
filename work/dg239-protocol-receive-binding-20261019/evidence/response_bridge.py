"""Pinned response-object bridges; independent epochs stop at every call."""
import json
from pathlib import Path

from receive_slices import Sample, import_slot

PINS = {
    0x1003A99EC: "685e40f9000140f9600e00f9483f00f0086541f900013fd6",
    0x1003A9A04: "6a6640f9690e40f9687640f9490100f9",
    0x100850BEC: "6b0140f96b6202f94a0140f96a6602f928dd03b9",
    0x100845FD4: "626642f9606242f921e2845206420194",
    0x1008C7044: "00008052e80740f909210091e90700f9080140f9682201f9",
    0x100834BE0: "680e5cf969b248f960ae48f9200100f9000140f9ff4300d1e9030091a8dbff9008712c91280100f961c58952667c0294ff430091",
    0x1008C7078: "e80740f909210091e90700f9080140f9685a01f900008052081000b4e803003268d602b9030a0014",
    0x1008C19AC: "a32241f9e10340b2e00314aae20318aa20033fd6",
    0x1008C19D4: "a32a41f9e10340b2e00314aae20318aa40033fd6",
    0x1008C2534: "600240f9085841f9c80600f9880000d008e13291085801f9082041f9c80a00f9132001f9a11200d0214437915afbff97",
    0x1008C2120: "080140f9090540f9895b01f9090940f9892301f9",
    0x10084968C: "68f643f960b643f969b248f9ca1b0090410942f9220140f9230080d2040080d200013fd660be07f9",
    0x1005D0888: "680255f960fe54f969b65bf98a2f00b0410942f9220140f9230080d2040080d200013fd6",
    0x10037C850: "a80354f8a48353f8a30353f8a28352f8a10352f8a08351f800013fd6a08314f8",
}


def build(sample):
    windows = []
    for va, pin in PINS.items():
        window = sample.window(va, len(bytes.fromhex(pin)))
        if window["bytes"] != pin:
            raise ValueError(f"original bytes changed at {va:#x}")
        if len(window["instructions"]) * 4 != len(bytes.fromhex(pin)):
            raise ValueError("incomplete disassembly")
        windows.append(window)
    selector = sample.selector(0x100BC1410)
    retain = import_slot(sample, 0x100B942C8)
    if selector != "JSONObjectWithData:options:error:" or retain["name"] != "_objc_retain":
        raise ValueError("selector or import identity changed")
    table = sample.read(0x1008C9BC4, 4)
    target = 0x1008C9BC4 + int.from_bytes(table, "little", signed=True)
    if table.hex() != "80d4ffff" or target != 0x1008C7044:
        raise ValueError("userdata table entry changed")
    return {
        "sample_sha256": sample.sha256,
        "kind": "original-byte local response bridges, not endpoint closure",
        "windows": windows, "json_selector": selector, "retain_import": retain,
        "userdata_table_entry": {"va": "0x1008c9bc4", "bytes": table.hex(), "target": hex(target)},
        "call_barriers": ["0x1003a9a00", "0x100845fe0", "0x1008c19bc", "0x1008c19e4",
                          "0x1008c2560", "0x1008496ac", "0x1005d08a8", "0x10037c868"],
        "open_edges": [
            "Full CFG from registration to each invocation and parser is not proved.",
            "Handle +0x240/+0x2b0 can be saved, replaced and restored; invocation epoch is required.",
            "Callback frame+0x18 and receiver-slot address are sampled after an external call.",
            "Receiver methods and all external-call writes, errors and lifetimes remain unbound.",
            "Parser input slot has intervening storeStrong call sites; slot identity is not object identity.",
            "Shared recharged parser trampoline is not an endpoint-specific live response.",
        ],
        "endpoint_attributed_live_responses_added": 0, "full_decoders_closed": 0,
        "full_callback_cfg_proven": False, "external_call_effects_proven": False,
        "baidu_omission_proven": False, "data3_empty_return_proven": False,
    }


if __name__ == "__main__":
    result = build(Sample())
    target = Path(__file__).resolve().parents[1] / "report/response-bridge.json"
    with target.open("x") as out:
        json.dump(result, out, indent=2)
        out.write("\n")
