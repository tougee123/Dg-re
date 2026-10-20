"""Offline parser-call provenance. Export metadata only, never response bodies."""
import hashlib
import json
from pathlib import Path

from binary_evidence import ROOT, Sample
from event_ledger import analyze_calls, metadata, module_base, parse_jsonl

WINDOWS = {
    0x1006618A0: "684652f9604a42f9698a53f90a2b0090410942f9220140f9230080d2040080d200013fd660ee15f92771ff17",
    0x1008496B0: "68f643f960b643f969b248f9ca1b0090410942f9220140f9230080d2040080d200013fd660be07f975c2ff17",
    0x10037C86C: "fc6fc2a8c0035fd6a80354f8a48353f8a30353f8a28352f8a10352f8a08351f800013fd6a08314f869000014",
    0x1005D08AC: "680255f960fe54f969b65bf98a2f00b0410942f9220140f9230080d2040080d200013fd6608a16f9dea20014",
    0x1005DA5AC: "683e50f9603a50f9696a59f92a2f00f0410942f9220140f9230080d2040080d200013fd6604a10f94effff17",
    0x1005CEFC0: "681256f9600e56f969025af98a2f00f0410942f9220140f9230080d2040080d200013fd6601616f9bc050014",
    0x100592BE4: "087969f800011fd668364ef962a649f961a249f960e249f9230080d2040080d200013fd660420ff910b6ff17",
}
SELECTOR = "JSONObjectWithData:options:error:"
HOOK_DECLARATION = "NSJSONSerialization + " + SELECTOR
SOURCES = ["work/dg-correlated-start-once-20261017/raw-events.jsonl",
           "work/dg-gap-once-20261017/raw-events.jsonl"]


def validate_row(row, windows):
    """Conjunctive checks; one incorrect field must reject the whole row."""
    return (row["unslid_caller"] in windows
            and row["selector_observed"] == SELECTOR
            and row["hook_declaration"] == HOOK_DECLARATION
            and 0 < row["hook_line"] < row["enter_line"]
            and row["options"] == "0x1" and row["error_out"] == "0x0"
            and row["complete_call"] and row["source_call_errors"] == 0
            and row["enter_line"] < row["event_line"] < row["return_line"]
            and row["event_tid"] == row["entry_tid"])


def build(sample, sources):
    windows = {}
    for caller, expected in WINDOWS.items():
        window = sample.window(caller - 36, 44)
        if window["bytes"] != expected:
            raise ValueError(f"original parser window mismatch at {caller:#x}")
        op = sample.insns(caller - 4, 4)[0]
        if (op.mnemonic, op.op_str) != ("blr", "x8"):
            raise ValueError("caller does not immediately follow BLR x8")
        windows[hex(caller)] = window
    if sample.selector(0x100BC1410) != SELECTOR:
        raise ValueError("selector slot mismatch")
    output = []
    for name, raw in sources:
        events, coverage, parse_errors = parse_jsonl(raw)
        calls, errors, incomplete = analyze_calls(events)
        base = module_base(events, calls)
        if base is None or parse_errors:
            raise ValueError("unverified module base or malformed source")
        declarations = [line for line, event, _ in events
                        if event["event"] == "HOOK"
                        and event.get("value") == HOOK_DECLARATION]
        if len(declarations) != 1:
            raise ValueError("missing or ambiguous parser hook declaration")
        # This event is emitted by the named ObjC method hook, not a socket hook.
        rows = []
        for line, event, _ in events:
            if event["event"] != "JSON-resp":
                continue
            call = calls[event["call"]]
            entry = call["entry"]
            registers = entry["registers"]
            row = {"event_line": line, "call_id": event["call"],
                   "entry_tid": entry["tid"], "event_tid": event["tid"],
                   "parent_call_id": entry["parent"],
                   "enter_line": call["enter_line"], "return_line": call.get("return_line", 0),
                   "complete_call": event["call"] not in incomplete,
                   "source_call_errors": len(errors),
                   "unslid_caller": hex(int(entry["caller"], 16) - base + 0x100000000),
                   "target": entry["target"], "selector_pointer": registers[1],
                   "selector_observed": SELECTOR,
                   "hook_line": declarations[0], "hook_declaration": HOOK_DECLARATION,
                   "selector_basis": "raw HOOK declaration, not an independent runtime selector read",
                   "input_object_pointer": registers[2], "result_object_pointer": call.get("result"),
                   "options": registers[3], "error_out": registers[4],
                   "endpoint": None, "wire_response_proven": False,
                   "meaning": "parsed output description; neither input bytes nor final HTTP response",
                   **metadata(event.get("value"))}
            row["accepted_local_observation"] = validate_row(row, windows)
            if not row["accepted_local_observation"]:
                raise ValueError("parser observation failed local identity checks")
            rows.append(row)
        output.append({"source": name, "sha256": hashlib.sha256(raw).hexdigest(),
                       "coverage": coverage, "parse_errors": parse_errors,
                       "call_errors": errors, "rows": rows})
    return {"sample_sha256": sample.sha256, "windows": windows, "sources": output,
            "limits": ["No endpoint assignment from chronology or thread ID",
                       "Pointers have no allocation or mutation epoch proof",
                       "ObjC descriptions do not prove JSON scalar wire types",
                       "HOOK declares the probe name; loaded script bytes and runtime selector identity remain unproven",
                       "No native receive-buffer to parser-input causal bridge"]}


def main():
    result = build(Sample(), [(p, (ROOT / p).read_bytes()) for p in SOURCES])
    output = Path(__file__).resolve().parents[1] / "report/parser-stages.json"
    output.write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps({"sources": len(result["sources"]),
                      "local_observations": sum(len(s["rows"]) for s in result["sources"]),
                      "endpoint_attributions": 0}))


if __name__ == "__main__":
    main()
