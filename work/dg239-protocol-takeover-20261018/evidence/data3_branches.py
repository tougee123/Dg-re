"""Bounded, byte-pinned predicate proofs, not a whole-function feasibility model."""
import json

import z3
from capstone.arm64 import ARM64_OP_IMM, ARM64_OP_REG

from binary_evidence import Sample

MASK = (1 << 32) - 1
FRAME = 0x200000000
PINS = {
    0x1003C1CCC: "683e42f96c4a45b9898800d029594ab98a8800d04a5d4ab929010a6b8b01290a8a4f82526ab6aa722a010a0a4a7d0b1b2b010c0a29010c2a297d0b1b29010a0b6a5881520a73af7229010a0b2aeb8e52caddad7229010a6b0bdb8152abdea77229010b6b29010a0b0afc9a52ca52ad7229010a6be9379f1a699603b9000140f960c201f9883e00f0086541f900013fd66cbe41f96ac241f96bc641f9699643b9689242f98a0100f92a0080526a0100b9690610b908f944f9690690b9087969f800011fd6",
    0x1003C38D8: "689242f9698642f9609a40f9200100f9290140f9290500f1e9879f1a692610b9080945f9692690b9087969f800011fd6",
    0x1003C5DE4: "689242f9698800d02a514ab9698800d029554ab9e903292a2a012a2a0900801229012a0a4a659c52cad9aa7229010a0b6bd39352ab73bc7229010b6b29010a6bea2595522a99b3722b010a4a6a050011e9249252c9ceaf7229012b2a29010a0baa109052ea55bb7229010a6be9179f1a691610b9080145f9691690b9087969f800011fd6",
    0x1003C0F60: "689242f96b5245b96d4e45b9898800f029614ab98a8800f04a654ab929010a4a8a1b8d52ca68bd7229010a4a2a010d4aac012a0a4a0080524c7d0c1b8c010d6b29010c6b2c010b4a6c012c0a4a7d0c1b4a010b6b29010a6bea7b8f522ae5a47229010a6be9979f1a69e60fb908e944f969e68fb9087969f800011fd6",
}


def fit(value, width):
    if isinstance(value, int):
        return z3.BitVecVal(value, width)
    if value.size() < width:
        return z3.ZeroExt(width - value.size(), value)
    return z3.Extract(width - 1, 0, value) if value.size() > width else value


def predicate(sample, address, memory):
    """Interpret the actual straight-line ARM64 window through its first CSET."""
    raw = sample.read(address, len(bytes.fromhex(PINS[address])))
    if raw.hex() != PINS[address]:
        raise ValueError(f"predicate byte mismatch at {address:#x}")
    regs = {"x19": z3.BitVecVal(FRAME, 64)}
    memory = dict(memory)
    last_sub = None

    def read(name):
        return fit(regs["x" + name[1:]], 32 if name.startswith("w") else 64)

    for ins in sample.insns(address, len(raw)):
        ops = ins.operands
        name = ins.reg_name(ops[0].reg)
        width = 32 if name.startswith("w") else 64

        def arg(index):
            op = ops[index]
            if (op.shift.value or op.ext) and ins.mnemonic != "movk":
                raise ValueError("unsupported shifted/extended operand")
            if op.type == ARM64_OP_IMM:
                return fit(op.imm, width)
            if op.type == ARM64_OP_REG:
                return fit(read(ins.reg_name(op.reg)), width)
            raise ValueError("unsupported arithmetic operand")

        if ins.mnemonic in {"ldr", "str"}:
            mem = ops[1].mem
            if mem.index:
                raise ValueError("indexed load before predicate")
            base = z3.simplify(read(ins.reg_name(mem.base)))
            location = base.as_long() + mem.disp
            if ins.mnemonic == "str":
                memory[location] = read(name)
                continue
            value = fit(memory[location], width)
        elif ins.mnemonic in {"adrp", "mov"}:
            value = arg(1)
        elif ins.mnemonic == "movk":
            shift = ops[1].shift.value
            value = (read(name) & fit(~(0xFFFF << shift), width)) | (arg(1) << shift)
        elif ins.mnemonic == "mvn":
            value = ~arg(1)
        elif ins.mnemonic in {"orn", "bic", "and", "orr", "eor", "add", "subs", "mul"}:
            a, b = arg(1), arg(2)
            value = {"orn": lambda: a | ~b, "bic": lambda: a & ~b,
                     "and": lambda: a & b, "orr": lambda: a | b,
                     "eor": lambda: a ^ b, "add": lambda: a + b,
                     "subs": lambda: a - b, "mul": lambda: a * b}[ins.mnemonic]()
            if ins.mnemonic == "subs":
                last_sub = a, b
        elif ins.mnemonic == "cset":
            if last_sub is None:
                raise ValueError("no flags producer")
            a, b = last_sub
            condition = ins.op_str.split(", ")[1]
            if condition == "eq":
                return a == b
            if condition == "hi":
                return z3.UGT(a, b)
            if condition == "hs":
                return z3.UGE(a, b)
            if condition == "ls":
                return z3.ULE(a, b)
            raise ValueError("unsupported condition")
        else:
            raise ValueError(f"unexpected instruction {ins.mnemonic}")
        regs["x" + name[1:]] = fit(value, 64)
    raise ValueError("no CSET")


def short_reference(a, b):
    x = (((a & b) - 0xE39D9E9B) & MASK) ^ 0x9CC9A92F
    return (0x7E769127 & x) == 0xDAAF8085


def long_reference(a, b, p, q):
    return ((a ^ b ^ 0xEB4668DC ^ p ^ q) & MASK) > 0x27297BDF


def dispatcher_expression(a, b, initializer):
    delta = a - b
    value = ((delta | initializer) * (delta & initializer)
             + (delta & 0x55B3127C) * (initializer & ~delta)
             + 0x7B980AC3 - 0x3EF50ED8)
    return value


def dispatcher_model(sample, initializer=0xAA4CED83):
    a, b = z3.BitVecs("dispatch_globalA dispatch_globalB", 32)
    condition = predicate(sample, 0x1003C1CCC,
                          {FRAME + 0x478: 0x400000000, FRAME + 0x548: initializer,
                           0x1014D3A58: a, 0x1014D3A5C: b})
    return a, b, condition


def models(sample):
    a, b, p, q = z3.BitVecs("globalA globalB frame54C frame550", 32)
    base = {FRAME + 0x520: 0x300000000}
    short = predicate(sample, 0x1003C5DE4, base | {0x1014D3A50: a, 0x1014D3A54: b})
    long = predicate(sample, 0x1003C0F60, base | {0x1014D3A60: a, 0x1014D3A64: b,
                                               FRAME + 0x54C: p, FRAME + 0x550: q})
    return (a, b, p, q), short, long


def solve(condition):
    solver = z3.Solver()
    solver.set(timeout=10000)
    solver.add(z3.simplify(condition))
    return str(solver.check())


def build(sample):
    symbols, short, long = models(sample)
    a, b, p, q = symbols
    simplified = z3.UGT(a ^ b ^ 0xEB4668DC ^ p ^ q, z3.BitVecVal(0x27297BDF, 32))
    length = z3.BitVec("key_object_length", 64)
    gate_predicate = predicate(sample, 0x1003C38D8,
                               {FRAME + 0x520: 0x300000000, FRAME + 0x508: 0x400000000,
                                FRAME + 0x130: length})
    results = {"length_gate_mismatch": solve(gate_predicate != z3.Or(length == 0, length == 1)),
               "short_index1_feasible": solve(short),
               "long_formula_mismatch": solve(long != simplified),
               "long_index0_feasible": solve(z3.Not(long)),
               "long_index1_feasible": solve(long)}
    if results != {"length_gate_mismatch": "unsat", "short_index1_feasible": "unsat", "long_formula_mismatch": "unsat",
                   "long_index0_feasible": "sat", "long_index1_feasible": "sat"}:
        raise ValueError("unexpected bounded proof result")
    da, db, dispatcher = dispatcher_model(sample)
    expression = dispatcher_expression(da, db, z3.BitVecVal(0xAA4CED83, 32))
    dispatch_results = {"formula_mismatch": solve(dispatcher != z3.UGE(expression, 0x6A96D7E0)),
                        "index0_feasible": solve(z3.Not(dispatcher)),
                        "index1_feasible": solve(dispatcher)}
    if dispatch_results != {"formula_mismatch": "unsat", "index0_feasible": "sat", "index1_feasible": "sat"}:
        raise ValueError("unexpected short dispatcher proof result")
    gate = sample.window(0x1003C38D8, len(bytes.fromhex(PINS[0x1003C38D8])))
    if gate["bytes"] != PINS[0x1003C38D8]:
        raise ValueError("length gate changed")
    table = {hex(va): hex(sample.pointer(va)) for va in range(0x101551148, 0x101551188, 8)}
    expected = [0x1003C0F60, 0x1003C5DE4, 0x1003C1CCC, 0x1003C2460,
                0x1003C1CCC, 0x1003C3A30, 0x1003C1FB4, 0x1003C13EC]
    if list(table.values()) != [hex(x) for x in expected]:
        raise ValueError("dispatch table changed")
    cleanup_slot = 0x1014F6050 + 0xCCA * 8
    if sample.pointer(cleanup_slot) != 0x1003C5E7C:
        raise ValueError("short cleanup slot changed")
    return {"sample_sha256": sample.sha256, "proofs": results,
            "short_dispatcher_proofs": dispatch_results,
            "short_dispatcher_assumption": "frame548 == 0xAA4CED83 from 3C002C; no whole-path alias proof",
            "short_dispatcher_initializer": sample.window(0x1003C0024, 0x28),
            "short_dispatcher_index1_target": sample.window(0x1003C3A30, 0x14),
            "cleanup_table_base": sample.window(0x1003C011C, 0x14),
            "cleanup_table_setup": sample.window(0x1003C03CC, 0x10),
            "cleanup_slot": {"va": hex(cleanup_slot), "bytes": sample.read(cleanup_slot, 8).hex(),
                             "target": hex(sample.pointer(cleanup_slot))},
            "cleanup_window": sample.window(0x1003C5E7C, 0x64),
            "short_dispatcher_routes": {"index0": "3C1CCC (self dispatcher)",
                                        "index1": "3C3A30 -> [1014F6050+CCA*8] -> 3C5E7C; conditional on intact setup"},
            "windows": [sample.window(va, len(bytes.fromhex(raw))) for va, raw in PINS.items()],
            "table_initializers": sample.window(0x1003C03A8, 0x40), "table": table,
            "length_return": sample.window(0x1003C6830, 20),
            "short_formula": "(0x7E769127 & (((A&B)-0xE39D9E9B)^0x9CC9A92F)) == 0xDAAF8085; uint32",
            "short_impossible_bits": hex(0xDAAF8085 & (~0x7E769127 & MASK)),
            "long_formula": "uint32(A^B^0xEB4668DC^frame54C^frame550)>0x27297BDF",
            "conditional_routes": {"key_length_0_or_1": "3C5DE4 -> 3C1CCC (index 0)",
                                   "key_length_gt_1": "3C0F60 -> 3C1FB4 or 3C13EC (residual)"},
            "limits": ["Assumes listed local table initializers reach dispatch without overwrite",
                       "Length is EB008-derived key object's return, not data3 input length",
                       "Not a whole-function route, return, empty-data3 proof, or live global binding",
                       "Short target 3C1CCC is another dispatcher, not a proven return",
                       "3C1D58 indirect call write set and live B942C8 target are unresolved",
                       "3C3A30 additionally depends on table+9E0 and frameFF4; not an empty-input result"]}


if __name__ == "__main__":
    from pathlib import Path
    out = Path(__file__).resolve().parent.parent / "report/data3-branches.json"
    out.write_text(json.dumps(build(Sample()), indent=2) + "\n")
