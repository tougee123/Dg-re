"""Offline linear slices only. External calls stop before any assumed effects."""
import json
import struct
import sys
from pathlib import Path

BASELINE = Path(__file__).resolve().parents[2] / "dg239-protocol-takeover-20261018"
sys.path.insert(0, str(BASELINE / "evidence"))
from binary_evidence import Sample
from capstone.arm64 import ARM64_OP_IMM, ARM64_OP_MEM, ARM64_OP_REG

MASK = (1 << 64) - 1
PINS = {
    0x1003A9CC0: "110000f9700100f98f0100f9cd0100f96b0140f98e0140f96d012e8a6c012eaaec032caa8c7d0d9b6d010e8a6b010eaa6b7d0d9b6b010c8b4b0100f94a0140f94a0100f1ea179f1a6a2600b9",
    0x1003A9550: "6b5640f96a1a40f9694a40f9685240f9080140f96c0140f908010c8b08014039290140f94a0140f96c0140f90b0080d26a010aeb6b010ceb4a010b8b29010aeb28010039",
    0x1003A9F6C: "4a0140f9ae0140f94a010e8b4a0140396b0140f98c0140f9ae0140f90d0080d2ad010eeb8c010deb6b010c8b6a010039",
    0x1003A9054: "685640f96a5240f9694e40f96b4a40f9604640f9600100f9290140f9490100f91f0100f9",
    0x1003A909C: "695640f96a8e40f9280140f908010a8b0805009108010aeb280100f9",
    0x1003A9E48: "686640f96a3a40f9691a40f96b3240f92b0100f9290140f94a0140f922010a8b000140f9c84000b0019543f9483f00f0085d41f900013fd6",
    0x1003AA080: "606640f9693e40f9683a40f9080140f9280100f9010080d258d81c94",
    0x1003A9200: "603640f91ed91c94617240f9606e40f9483f00f0085d41f900013fd6603200f9",
    0x1003A94FC: "612640f9602240f9483f00f0085d41f900013fd6604600f9a7feff17",
}


class CallBarrier(RuntimeError):
    def __init__(self, pc, registers):
        super().__init__(f"external call at {pc:#x}; effects and continuation unknown")
        self.pc, self.registers = pc, dict(registers)


class BytesState:
    def __init__(self, registers=None):
        self.regs, self.memory, self.events = dict(registers or {}), {}, []
        self.zero = None

    def put(self, address, value, size=8):
        for k, byte in enumerate((value & ((1 << (size * 8)) - 1)).to_bytes(size, "little")):
            self.memory[(address + k) & MASK] = byte

    def get(self, address, size=8):
        return int.from_bytes(bytes(self.memory[(address + k) & MASK] for k in range(size)), "little")

    def reg(self, name):
        if name in ("xzr", "wzr"):
            return 0
        value = self.regs["x" + name[1:] if name.startswith("w") else name]
        return value & (0xFFFFFFFF if name.startswith("w") else MASK)

    def setreg(self, name, value):
        if name in ("xzr", "wzr"):
            return
        self.regs["x" + name[1:] if name.startswith("w") else name] = value & (
            0xFFFFFFFF if name.startswith("w") else MASK)


def run(sample, va, raw, state):
    if len(raw) % 4:
        raise ValueError("incomplete instruction")
    insns = list(sample.cs.disasm(raw, va))
    if len(insns) * 4 != len(raw):
        raise ValueError("undecoded bytes")
    for insn in insns:
        op, args = insn.mnemonic, insn.operands
        if op in ("bl", "blr"):
            raise CallBarrier(insn.address, state.regs)
        if any(a.shift.value or a.ext for a in args):
            raise ValueError("unsupported operand modifier")

        def name(a):
            return insn.reg_name(a.reg)

        def val(a):
            if a.type == ARM64_OP_REG:
                return state.reg(name(a))
            if a.type == ARM64_OP_IMM:
                return a.imm
            raise ValueError("unsupported value")

        if op in ("ldr", "ldrb", "str", "strb"):
            if args[1].type != ARM64_OP_MEM or args[1].mem.index or insn.writeback:
                raise ValueError("unsupported memory addressing")
            address = (state.reg(insn.reg_name(args[1].mem.base)) + args[1].mem.disp) & MASK
            size = 1 if op.endswith("b") else (4 if name(args[0]).startswith("w") else 8)
            if op.startswith("ld"):
                value = state.get(address, size)
                state.setreg(name(args[0]), value)
                kind = "read"
            else:
                value = val(args[0]) & ((1 << (8 * size)) - 1)
                state.put(address, value, size)
                kind = "write"
            state.events.append({"pc": hex(insn.address), "kind": kind, "address": address,
                                 "size": size, "value": value, "event": len(state.events)})
        elif op in ("mov", "adrp", "mvn"):
            value = val(args[1])
            state.setreg(name(args[0]), ~value if op == "mvn" else value)
        elif op == "cset":
            if insn.op_str.split(", ")[-1] != "eq" or state.zero is None:
                raise ValueError("unsupported or undefined condition")
            state.setreg(name(args[0]), int(state.zero))
        elif op in ("add", "subs", "bic", "orn", "and", "orr", "mul"):
            a, b = val(args[1]), val(args[2])
            if op == "add": value = a + b
            elif op == "subs": value = a - b
            elif op == "bic": value = a & ~b
            elif op == "orn": value = a | ~b
            elif op == "and": value = a & b
            elif op == "orr": value = a | b
            else: value = a * b
            state.setreg(name(args[0]), value)
            if op == "subs":
                state.zero = state.reg(name(args[0])) == 0
        else:
            raise ValueError(f"unsupported instruction {op}")
    return state


def import_slot(sample, va):
    """Resolve file import identity, not the loader's live pointer value."""
    offset = 32
    for _ in range(struct.unpack_from("<I", sample.raw, 16)[0]):
        cmd, size = struct.unpack_from("<II", sample.raw, offset)
        if cmd == 0x19:
            count = struct.unpack_from("<I", sample.raw, offset + 64)[0]
            for k in range(count):
                pos = offset + 72 + k * 80
                base, length = struct.unpack_from("<QQ", sample.raw, pos + 32)
                flags, first = struct.unpack_from("<II", sample.raw, pos + 64)
                if flags & 0xFF not in (6, 7) or not base <= va < base + length:
                    continue
                if (va - base) % 8:
                    raise ValueError("unaligned import slot")
                table, nentries = sample.indirect
                index = first + (va - base) // 8
                if index >= nentries:
                    raise ValueError("indirect table bounds")
                p = table + 4 * index
                symbol = struct.unpack_from("<I", sample.raw, p)[0]
                symoff, nsyms, stroff, strsize = sample.symtab
                if symbol >= nsyms:
                    raise ValueError("not a symbol")
                sympos = symoff + 16 * symbol
                strindex = struct.unpack_from("<I", sample.raw, sympos)[0]
                if strindex >= strsize or stroff + strsize > len(sample.raw):
                    raise ValueError("symbol string bounds")
                end = sample.raw.find(b"\0", stroff + strindex, stroff + strsize)
                if end < 0:
                    raise ValueError("unterminated symbol")
                return {"slot_va": hex(va), "file_bytes": sample.read(va, 8).hex(),
                        "indirect_index": index, "indirect_fileoff": p,
                        "indirect_bytes": sample.raw[p:p + 4].hex(), "symbol_index": symbol,
                        "symbol_fileoff": sympos, "symbol_bytes": sample.raw[sympos:sympos + 16].hex(),
                        "string_fileoff": stroff + strindex,
                        "name": sample.raw[stroff + strindex:end].decode("ascii"),
                        "live_target_proven": False}
        offset += size
    raise ValueError("not an import slot")


def build(sample):
    windows = []
    for va, pin in PINS.items():
        window = sample.window(va, len(bytes.fromhex(pin)))
        if window["bytes"] != pin:
            raise ValueError(f"original bytes changed at {va:#x}")
        windows.append(window)
    imports = [import_slot(sample, va) for va in (0x100B942B8, 0x100B942C8)]
    stubs = [sample.stub_symbol(va) for va in (0x100AE01B0, 0x100AE01F8, 0x100ADF67C)]
    expected = ["_objc_msgSend", "_objc_retain", "_objc_retainAutorelease", "_objc_storeStrong", "__Unwind_Resume"]
    if [x["name"] for x in imports + stubs] != expected:
        raise ValueError("import identity changed")
    selectors = {hex(a): sample.selector(a) for a in (0x100BC1550, 0x100BC1568, 0x100BC2728)}
    if list(selectors.values()) != ["length", "mutableBytes", "setLength:"]:
        raise ValueError("selector changed")
    return {"sample_sha256": sample.sha256, "kind": "conditional original-byte linear slices",
            "windows": windows, "imports": imports, "stubs": stubs, "selectors": selectors,
            "full_callback_cfg_proven": False, "external_call_effects_proven": False,
            "endpoint_attributed_live_responses_added": 0, "full_decoders_closed": 0}


if __name__ == "__main__":
    # Exclusive creation prevents a repeat invocation from changing frozen evidence.
    target = Path(__file__).resolve().parents[1] / "report/receive-bytes.json"
    result = build(Sample())
    with target.open("x") as f:
        json.dump(result, f, indent=2)
        f.write("\n")
