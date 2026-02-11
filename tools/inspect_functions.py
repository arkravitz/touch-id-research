#!/usr/bin/env python3
"""Slice saved disassembly by symbol substring; never touches live drivers."""
import argparse
import re
from pathlib import Path


def functions(path):
    result = {}
    for block in re.split(r'(?=^__[^\n]*:\n)', Path(path).read_text(), flags=re.M):
        lines = block.splitlines()
        if block.startswith('__') and len(lines) > 1:
            result.setdefault(lines[0][:-1], lines)
    return result


if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('query', nargs='+')
    p.add_argument('--file', default='evidence/AppleTrustedAccessory-kernel-disassembly.txt')
    p.add_argument('--start', type=int, default=0)
    p.add_argument('--count', type=int, default=150)
    p.add_argument('--calls', action='store_true')
    args = p.parse_args()
    for name, lines in functions(args.file).items():
        if '.cold.' not in name and any(q in name for q in args.query):
            print(name + ':')
            selected = lines[1:]
            if args.calls:
                selected = [l for l in selected if '\tbl\t' in l or '\tblraa\t' in l or re.search(r'\bmov\s+w[1234567], #', l)]
            print('\n'.join(selected[args.start:args.start + args.count]))
