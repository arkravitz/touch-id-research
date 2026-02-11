#!/usr/bin/env python3
"""Index direct generic-transfer calls in the saved trusted-accessory disassembly.

An opcode candidate is the last immediate w1 assignment in a bounded window;
this is a discovery aid, not a control-flow/data-flow proof.
"""
import argparse
import json
import re
from inspect_functions import functions


def index(path):
    result=[]
    for name,lines in functions(path).items():
        if '.cold.' in name:continue
        for i,line in enumerate(lines):
            if 'AppleSEPGenericTransfer' not in line or not any(x in line for x in ['8transact','14transactToIOMD']):
                continue
            window=lines[max(1,i-22):i+2]
            matches=[re.search(r'\bmov\s+w1, #0x([0-9a-f]+)',item) for item in window]
            candidates=[int(item.group(1),16) for item in matches if item]
            result.append(dict(symbol=name,call_address=line.split(':')[0],
                               opcode_candidate=candidates[-1] if candidates else None,context=window))
    return result


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('source',nargs='?',default='evidence/AppleTrustedAccessory-kernel-disassembly.txt')
    args=p.parse_args()
    print(json.dumps(index(args.source),indent=2))
