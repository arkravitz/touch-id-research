#!/usr/bin/env python3
"""Resolve this build's kernelcache chained vtable pointers from saved copies.

Not a general fixup decoder: uses the observed low-32-bit image-base offset.
"""
import argparse
import json
import struct
from pathlib import Path


def resolve(image, symbols_file, vtable, slots, image_base=0xfffffe0007004000):
    data = Path(image).read_bytes()
    if data[:4] != bytes.fromhex('cffaedfe'):
        raise ValueError('requires a little-endian 64-bit Mach-O')
    segments = []
    pos = 32
    for _ in range(struct.unpack_from('<I', data, 16)[0]):
        command, size = struct.unpack_from('<II', data, pos)
        if command == 0x19:
            _, va, _, offset, file_size = struct.unpack_from('<16sQQQQ', data, pos+8)
            segments.append((va, file_size, offset))
        pos += size
    symbols = {}
    for line in Path(symbols_file).read_text().splitlines():
        fields = line.split()
        if len(fields) == 3:
            try:
                symbols[int(fields[0], 16)] = fields[2]
            except ValueError:
                pass
    result = []
    for slot in slots:
        address = vtable + 16 + slot
        offset = next(o+address-v for v, n, o in segments if v <= address and address+8 <= v+n)
        encoded = struct.unpack_from('<Q', data, offset)[0]
        target = image_base + (encoded & 0xffffffff) if encoded else None
        result.append(dict(vtable=hex(vtable), slot=hex(slot), encoded=hex(encoded),
                           target=hex(target) if target else None, symbol=symbols.get(target)))
    return result


if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('image')
    p.add_argument('symbols')
    p.add_argument('vtable', type=lambda x: int(x, 0))
    p.add_argument('slots', nargs='+', type=lambda x: int(x, 0))
    a = p.parse_args()
    print(json.dumps(resolve(a.image, a.symbols, a.vtable, a.slots), indent=2))
