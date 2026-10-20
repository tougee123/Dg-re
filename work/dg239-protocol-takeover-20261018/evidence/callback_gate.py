"""Local callback predicates from original bytes; no external-call success stubs."""
import json
from pathlib import Path

from capstone.arm64 import ARM64_OP_IMM, ARM64_OP_REG

from binary_evidence import Sample

PINS = {
    0x1005BBEAC: "60fa1ef961fe1ef962021ff9e00303aa63065ff9600a1ff9",
    0x1005CAE8C: "60c25af961025ff91f0000f9d8541494610a5ff960ca5af91f0000f9d4541494",
    0x1005CAEAC: "6bfa5ef96cc65af96aca5af9689a75b969065ff98b0100f94a0140f94a0100f1ea079f1a6a9e35b9",
    0x1005E1928: "6aca5af908780090081947b90b7800906b1d47b908010b6bec4c9b522c9bb7720b010c4a08010c2a08012b0aabea9b526b20bd72087d0b1b2be69f52cb35b9720809cb1a4b869f528b08b77208010b6be8079f1a",
    0x1005E197C: "4a0140f94a0100f1ea079f1a6a9e2fb9",
    0x1005FBB74: "69065ff9689e75b928fd10b9288148f929fd90b9087969f800011fd6",
    0x1005CC86C: "69065ff9689e6fb9286d10b9283948f9296d90b9087969f800011fd6",
    0x1005BCA5C: "a87d009008613d91688008f9",
    0x1005BCAD0: "a87d009008213f91683808f9",
    0x100AE01F8: "f0060090103245f900021fd6",
    0x1005CE924: "001140f9604616f9",
    0x1005FC164: "614e56f9604656f9c82c0090085d41f900013fd660f20df9",
}
TABLES = {0x101570F58: (0x1005F7BB8, 0x1005E8588),
          0x101570FC8: (0x1005D5490, 0x10060428C)}
MASK = (1 << 64) - 1


def run_local(sample, va, raw, registers, words):
    """Execute only supported local load/store/predicate/dispatch instructions.

    Words are explicit fixture memory, not real process memory. Calls, unknown
    registers and missing memory fail closed instead of supplying return values.
    """
    regs, memory = dict(registers), dict(words)
    decoded = list(sample.cs.disasm(raw, va))
    if len(decoded) * 4 != len(raw):
        raise ValueError("incomplete instruction decoding")
    flags = None
    branch = None

    def read(name):
        if name in {"xzr", "wzr"}:
            return 0
        value = regs["x" + name[1:]]
        return value & ((1 << (32 if name.startswith("w") else 64)) - 1)

    for ins in decoded:
        if ins.mnemonic not in {"ldr", "ldrsw", "str", "mov", "adrp", "add", "subs", "cset", "br"}:
            raise ValueError(f"unsupported instruction {ins.mnemonic}")
        ops = ins.operands
        name = ins.reg_name(ops[0].reg)
        width = 32 if name.startswith("w") else 64

        def operand(index):
            op = ops[index]
            if op.type == ARM64_OP_IMM:
                return op.imm
            if op.type == ARM64_OP_REG and not op.ext and not op.shift.value:
                return read(ins.reg_name(op.reg))
            raise ValueError("unsupported operand")

        if ins.mnemonic in {"ldr", "ldrsw", "str"}:
            op = ops[1]
            if op.ext or ins.writeback:
                raise ValueError("unsupported memory addressing")
            loc = read(ins.reg_name(op.mem.base)) + op.mem.disp
            if op.mem.index:
                loc += read(ins.reg_name(op.mem.index)) << op.shift.value
            loc &= MASK
            if ins.mnemonic == "str":
                memory[loc] = read(name)
                continue
            value = memory[loc]
            if ins.mnemonic == "ldrsw":
                value &= 0xFFFFFFFF
                value = value - (1 << 32) if value & (1 << 31) else value
        elif ins.mnemonic in {"mov", "adrp"}:
            value = operand(1)
        elif ins.mnemonic in {"add", "subs"}:
            a, b = operand(1), operand(2)
            value = a + b if ins.mnemonic == "add" else a - b
            if ins.mnemonic == "subs":
                flags = value & ((1 << width) - 1)
        elif ins.mnemonic == "cset":
            condition = ins.op_str.split(", ")[1]
            if flags is None or condition not in {"ne", "eq"}:
                raise ValueError("unsupported flags consumer")
            value = int((flags != 0) if condition == "ne" else (flags == 0))
        elif ins.mnemonic == "br":
            branch = read(name)
            if ins != decoded[-1]:
                raise ValueError("instructions after branch")
            continue
        else:
            raise ValueError(f"unsupported instruction {ins.mnemonic}")
        regs["x" + name[1:]] = value & ((1 << width) - 1)
    return {"registers": regs, "words": memory, "branch": branch}


def table_memory(sample, table):
    return {table + i * 8: sample.pointer(table + i * 8) for i in range(2)}


def build(sample):
    windows = []
    for va, expected in PINS.items():
        window = sample.window(va, len(bytes.fromhex(expected)))
        if window["bytes"] != expected:
            raise ValueError(f"callback bytes changed at {va:#x}")
        windows.append(window)
    for table, expected in TABLES.items():
        if tuple(table_memory(sample, table).values()) != expected:
            raise ValueError("dispatch table changed")
    imports = [sample.stub_symbol(va) for va in (0x100AE01F8, 0x100AE00E4)]
    if [entry["name"] for entry in imports] != ["_objc_storeStrong", "_objc_autoreleaseReturnValue"]:
        raise ValueError("unexpected imported symbol")
    # The intervening opaque arithmetic cannot redefine X10 or call a writer.
    middle = sample.insns(0x1005E192C, 0x50)
    for ins in middle:
        if ins.mnemonic in {"bl", "blr", "br", "b", "str", "stp"}:
            raise ValueError("unmodeled control or memory write in resample gap")
        if any(ins.reg_name(r) in {"x10", "w10"} for r in ins.regs_access()[1]):
            raise ValueError("X10 overwritten in resample gap")
    frame, context, slot, self_slot = 0x200000000, 0x300000000, 0x400000000, 0x500000000
    cases = []
    for first, second in [(0, 0), (0, 0x1234), (0x1234, 0), (MASK, MASK)]:
        memory = {frame + 0x3DF0: 0x600000000, frame + 0x3588: self_slot,
                  frame + 0x3590: slot, frame + 0x3598: 0,
                  frame + 0x3E08: context, slot: first}
        a = run_local(sample, 0x1005CAEAC, bytes.fromhex(PINS[0x1005CAEAC]), {"x19": frame}, memory)
        index1 = a["words"][frame + 0x359C]
        first_memory = a["words"] | {context + 0x1100: 0x101570F58} | table_memory(sample, 0x101570F58)
        dispatch1 = run_local(sample, 0x1005FBB74, bytes.fromhex(PINS[0x1005FBB74]), {"x19": frame}, first_memory)
        b = run_local(sample, 0x1005E197C, bytes.fromhex(PINS[0x1005E197C]),
                      {"x19": frame, "x10": slot}, a["words"] | {slot: second})
        index2 = b["words"][frame + 0x2F9C]
        second_memory = b["words"] | {context + 0x1070: 0x101570FC8} | table_memory(sample, 0x101570FC8)
        dispatch2 = run_local(sample, 0x1005CC86C, bytes.fromhex(PINS[0x1005CC86C]), {"x19": frame}, second_memory)
        if index1 != int(first != 0) or index2 != int(second != 0):
            raise ValueError("predicate mismatch")
        cases.append({"epoch1_value": hex(first), "epoch2_value": hex(second),
                      "first_index": index1, "second_index": index2,
                      "first_target": hex(dispatch1["branch"]), "second_target": hex(dispatch2["branch"]),
                      "meaning": "independent local fixtures, NOT a sequential callback path"})
    return {"sample_sha256": sample.sha256, "windows": windows, "imports": imports,
            "tables": {hex(t): {"bytes": sample.read(t, 16).hex(), "targets": list(map(hex, v))}
                       for t, v in TABLES.items()},
            "argument_slots": {"entry_x0": "frame+3DF0", "entry_x1": "frame+3DF8",
                               "entry_x2": "frame+3E00", "entry_x3": "frame+3E10"},
            "external_write_boundaries": ["5CAE98: AE01F8(slot3580, entry_x2)",
                                          "5CAEA8: AE01F8(slot3590, entry_x3)"],
            "first_read": "5CAEC4 dereferences frame3590; NE predicate stored frame359C",
            "second_read": "5E1928 loads frame3590; 5E197C dereferences it in a separate memory epoch",
            "captured_body": "5CE924 loads saved entry_x0+20 -> frame2C88; 5FC168 loads receiver from frame2C88",
            "local_cases": cases,
            "limits": ["AE01F8 imports objc_storeStrong; symbol identity does not establish runtime implementation, aliasing or lifetime effects",
                       "No proof the two reads observe equal pointer slots or equal pointee epochs",
                       "Context tables and alias-free fixture words are explicit local preconditions",
                       "Argument positions alone do not prove actual runtime URLSession callback identity",
                       "Capture+20 is not callback response data; no nil/error/HTTP behavior is assumed",
                       "No whole-path reachability, request omission equivalence, authorization or UI success proof"]}


if __name__ == "__main__":
    out = Path(__file__).resolve().parents[1] / "report/callback-gate.json"
    out.write_text(json.dumps(build(Sample()), indent=2) + "\n")
