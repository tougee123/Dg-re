"""Read original standard dyld binds; no live dispatch or object effects implied."""
import hashlib
import json
import struct
import sys
from pathlib import Path

BASE = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(BASE / "dg239-protocol-takeover-20261018/evidence"))
from binary_evidence import Sample

MASK = (1 << 64) - 1
EXPECTED = {
    0x100BC28F8: "_OBJC_CLASS_$_NSMutableData",
    0x100BC2828: "_OBJC_CLASS_$_NSString",
    0x100B942B8: "_objc_msgSend",
}


def metadata(raw):
    segments, libraries, stream = [], [], None
    position = 32
    for _ in range(struct.unpack_from("<I", raw, 16)[0]):
        command, size = struct.unpack_from("<II", raw, position)
        if size < 8 or position + size > len(raw):
            raise ValueError("invalid load command")
        if command == 0x19:
            name = raw[position + 8:position + 24].split(b"\0")[0].decode("ascii")
            address, length = struct.unpack_from("<QQ", raw, position + 24)
            segments.append((name, address, length))
        elif command in (0xC, 0x80000018, 0x8000001F, 0x20, 0x80000023):
            offset = struct.unpack_from("<I", raw, position + 8)[0]
            end = raw.find(b"\0", position + offset, position + size)
            if offset < 24 or end < 0:
                raise ValueError("invalid dylib name")
            libraries.append(raw[position + offset:end].decode("ascii"))
        elif command in (0x22, 0x80000022):
            stream = struct.unpack_from("<II", raw, position + 16)
        position += size
    if stream is None or stream[0] + stream[1] > len(raw):
        raise ValueError("invalid standard bind stream")
    return segments, libraries, stream


def decode(stream, segments, libraries, fileoff=0):
    position = 0
    segment = ordinal = symbol = bind_type = None
    address_offset = addend = 0
    records, operations = [], []

    def leb(signed=False):
        nonlocal position
        value = shift = 0
        while True:
            if position >= len(stream) or shift >= 70:
                raise ValueError("truncated or oversized LEB")
            byte = stream[position]
            position += 1
            value |= (byte & 0x7F) << shift
            shift += 7
            if not byte & 0x80:
                if signed and byte & 0x40:
                    value -= 1 << shift
                if not signed and value > MASK:
                    raise ValueError("ULEB exceeds uint64")
                return value

    def emit(opcode_position):
        if segment is None or symbol is None or ordinal is None or bind_type != 1:
            raise ValueError("incomplete or unsupported pointer bind")
        name, base, length = segments[segment]
        if address_offset + 8 > length:
            raise ValueError("bind outside segment")
        if ordinal <= 0 or ordinal > len(libraries):
            raise ValueError("unsupported library ordinal")
        records.append({"va": hex(base + address_offset), "symbol": symbol,
                        "ordinal": ordinal, "library": libraries[ordinal - 1],
                        "segment": name, "addend": addend,
                        "bind_opcode_fileoff": fileoff + opcode_position,
                        "state_operations": list(operations)})

    while position < len(stream):
        start = position
        byte = stream[position]
        position += 1
        opcode, immediate = byte & 0xF0, byte & 15
        if opcode == 0:
            if byte != 0 or any(stream[position:]):
                raise ValueError("invalid standard-bind terminator")
            return records
        if opcode == 0x10:
            ordinal = immediate
        elif opcode == 0x20:
            ordinal = leb()
        elif opcode == 0x30:
            ordinal = immediate - 16 if immediate else 0
        elif opcode == 0x40:
            end = stream.find(b"\0", position)
            if end < 0:
                raise ValueError("unterminated bind symbol")
            symbol = stream[position:end].decode("ascii")
            position = end + 1
        elif opcode == 0x50:
            bind_type = immediate
        elif opcode == 0x60:
            addend = leb(True)
        elif opcode == 0x70:
            segment, address_offset = immediate, leb()
            if segment >= len(segments):
                raise ValueError("unknown bind segment")
        elif opcode == 0x80:
            # This sample encodes backwards movement as unsigned 64-bit deltas.
            address_offset = (address_offset + leb()) & MASK
        elif opcode in (0x90, 0xA0, 0xB0, 0xC0):
            if opcode == 0xC0:
                count, skip = leb(), leb()
            else:
                count = 1
                skip = leb() if opcode == 0xA0 else immediate * 8 if opcode == 0xB0 else 0
            if count > len(stream) * 8:
                raise ValueError("excessive bind repeat")
            operations.append({"fileoff": fileoff + start, "bytes": stream[start:position].hex()})
            for _ in range(count):
                emit(start)
                address_offset = (address_offset + 8 + skip) & MASK
            continue
        else:
            raise ValueError(f"unsupported bind opcode {opcode:#x}")
        operations.append({"fileoff": fileoff + start, "bytes": stream[start:position].hex()})
    raise ValueError("missing standard-bind terminator")


def build(sample):
    segments, libraries, (offset, size) = metadata(sample.raw)
    stream = sample.raw[offset:offset + size]
    records = decode(stream, segments, libraries, offset)
    selected = []
    for address, symbol in EXPECTED.items():
        matches = [r for r in records if r["va"] == hex(address)]
        if len(matches) != 1 or matches[0]["symbol"] != symbol or matches[0]["addend"] != 0:
            raise ValueError(f"unexpected binding at {address:#x}")
        selected.append(matches[0])
    return {"sample_sha256": sample.sha256, "stream_fileoff": offset,
            "stream_bytes": size, "stream_sha256": hashlib.sha256(stream).hexdigest(),
            "total_pointer_bind_records": len(records), "bindings": selected,
            "live_target_proven": False, "allocation_result_proven": False,
            "same_transaction_decoder_proven": False}


if __name__ == "__main__":
    print(json.dumps(build(Sample()), indent=2))
