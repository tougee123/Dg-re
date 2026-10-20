"""Read-only original-sample access; virtual addresses never imply file offsets."""
import hashlib
import struct
from pathlib import Path

from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN

ROOT = Path(__file__).resolve().parents[3]
SAMPLE = ROOT / "work/dgassistant-237-239-diff/2.3.9/DGAssistant"
EXPECTED_SHA = "3841f080d158a9a9f942eb0ca7f38ec8ba7e1677c23c1b92054fb82452e5cf78"


class Sample:
    def __init__(self):
        self.raw = SAMPLE.read_bytes()
        self.sha256 = hashlib.sha256(self.raw).hexdigest()
        if self.sha256 != EXPECTED_SHA:
            raise ValueError("sample SHA256 mismatch")
        if struct.unpack_from("<I", self.raw)[0] != 0xFEEDFACF:
            raise ValueError("expected thin little-endian Mach-O 64")
        self.segments = []
        self.stub_sections = []
        self.symtab = None
        self.indirect = None
        offset = 32
        for _ in range(struct.unpack_from("<I", self.raw, 16)[0]):
            cmd, size = struct.unpack_from("<II", self.raw, offset)
            if size < 8 or offset + size > len(self.raw):
                raise ValueError("invalid load command")
            if cmd == 0x19:
                self.segments.append(struct.unpack_from("<QQQQ", self.raw, offset + 24))
                count = struct.unpack_from("<I", self.raw, offset + 64)[0]
                if 72 + count * 80 > size:
                    raise ValueError("truncated section headers")
                for index in range(count):
                    pos = offset + 72 + index * 80
                    flags, reserved1, reserved2 = struct.unpack_from("<III", self.raw, pos + 64)
                    if flags & 0xFF == 8:
                        base, length = struct.unpack_from("<QQ", self.raw, pos + 32)
                        self.stub_sections.append((base, length, reserved1, reserved2))
            elif cmd == 2:
                self.symtab = struct.unpack_from("<IIII", self.raw, offset + 8)
            elif cmd == 11:
                self.indirect = struct.unpack_from("<II", self.raw, offset + 56)
            offset += size
        self.cs = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
        self.cs.detail = True

    def read(self, va, size):
        for base, _, fileoff, filesize in self.segments:
            if base <= va and va + size <= base + filesize:
                start = fileoff + va - base
                return self.raw[start:start + size]
        raise ValueError(f"not file-backed: {va:#x}+{size}")

    def pointer(self, va):
        return struct.unpack("<Q", self.read(va, 8))[0]

    def selector(self, va):
        return self.read(self.pointer(va), 128).split(b"\0", 1)[0].decode("ascii")

    def stub_symbol(self, va):
        if self.symtab is None or self.indirect is None:
            raise ValueError("missing symbol tables")
        symoff, nsyms, stroff, strsize = self.symtab
        indirectoff, indirectcount = self.indirect
        for base, size, first, stride in self.stub_sections:
            if not (base <= va < base + size):
                continue
            if not stride or (va - base) % stride:
                raise ValueError("not a stub entry")
            index = first + (va - base) // stride
            if index >= indirectcount:
                raise ValueError("indirect symbol index out of bounds")
            pos = indirectoff + index * 4
            symbol = struct.unpack_from("<I", self.raw, pos)[0]
            if symbol >= nsyms:
                raise ValueError("non-symbol or invalid indirect entry")
            entry = symoff + symbol * 16
            strindex = struct.unpack_from("<I", self.raw, entry)[0]
            if strindex >= strsize or stroff + strsize > len(self.raw):
                raise ValueError("symbol string out of bounds")
            end = self.raw.find(b"\0", stroff + strindex, stroff + strsize)
            if end < 0:
                raise ValueError("unterminated symbol name")
            return {"stub_va": hex(va), "stub_bytes": self.read(va, stride).hex(),
                    "indirect_index": index, "indirect_fileoff": pos,
                    "indirect_bytes": self.raw[pos:pos + 4].hex(),
                    "symbol_index": symbol, "symbol_fileoff": entry,
                    "symbol_bytes": self.raw[entry:entry + 16].hex(),
                    "string_fileoff": stroff + strindex,
                    "name": self.raw[stroff + strindex:end].decode("ascii")}
        raise ValueError("not in a symbol-stub section")

    def insns(self, va, size):
        return list(self.cs.disasm(self.read(va, size), va))

    def window(self, va, size):
        raw = self.read(va, size)
        return {"va": hex(va), "bytes": raw.hex(),
                "instructions": [f"{i.address:#x}: {i.mnemonic} {i.op_str}"
                                 for i in self.insns(va, size)]}
