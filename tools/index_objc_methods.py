#!/usr/bin/env python3
"""Resolve relative ObjC method names using otool's ordered selector list.

Input is saved `otool -ov` text. Supply the __objc_selrefs address and entry
count from the same binary's load commands; mismatches fail closed.
"""
import argparse
import json
import re
from pathlib import Path


def index(path, selrefs_base, selrefs_count):
    lines=Path(path).read_text().splitlines();selectors=[];active=False
    for line in lines:
        if 'Contents of' in line:
            active='__objc_selrefs' in line
        elif active:
            match=re.match(r'    0x[0-9a-f]+ (.*)',line)
            if match:selectors.append(match.group(1))
    if len(selectors)!=selrefs_count:raise ValueError('selector entry count does not match load commands')
    names={selrefs_base+8*i:name for i,name in enumerate(selectors)}
    result=[];class_name=None
    for i,line in enumerate(lines[:-2]):
        cls=re.match(r'        name\s+0x[0-9a-f]+ (\S+)$',line)
        if cls:class_name=cls.group(1)
        name=re.match(r'            name\s+0x[0-9a-f]+ \((0x[0-9a-f]+)\)',line)
        types=re.match(r'            types\s+0x[0-9a-f]+ \(0x[0-9a-f]+\) (.*)',lines[i+1])
        imp=re.match(r'            imp\s+0x[0-9a-f]+ \((0x[0-9a-f]+)\)',lines[i+2])
        if name and types and imp:
            ref=int(name.group(1),16)
            result.append(dict(class_name=class_name,selector=names.get(ref),selector_reference=hex(ref),
                               encoding=types.group(1),implementation=imp.group(1)))
    return result


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('source')
    p.add_argument('--selrefs-base',required=True,type=lambda x:int(x,0))
    p.add_argument('--selrefs-count',required=True,type=lambda x:int(x,0))
    args=p.parse_args()
    print(json.dumps(index(args.source,args.selrefs_base,args.selrefs_count),indent=2))
