#!/usr/bin/env python3
"""Compare full host buffers against Apple's memory-only serializer on this Mac."""
import hashlib
import json
from pathlib import Path
import random
import subprocess
import sys
import tempfile

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from touchid_lab.codec import HostCommand


def main():
    rng=random.Random(20261019)
    lengths=[0,1,2,7,8,512,16375,16376,16377,32768,65536]+[rng.randrange(2049) for _ in range(100)]
    cases=[dict(command=rng.randrange(65536),version=rng.randrange(65536),in_value=rng.randrange(65536),
                payload_hex=rng.randbytes(n).hex()) for n in lengths]
    with tempfile.TemporaryDirectory(prefix='touchid-pack-') as tmp:
        binary=str(Path(tmp)/'oracle')
        subprocess.run(['xcrun','clang','-fobjc-arc','-framework','Foundation',str(ROOT/'tools/native_pack_oracle.m'),'-o',binary],check=True)
        run=subprocess.run([binary],input=json.dumps(cases),capture_output=True,text=True,check=True)
    outputs=json.loads(run.stdout)
    results=[]
    for case,out in zip(cases,outputs,strict=True):
        command=HostCommand(case['command'],case['version'],case['in_value'],bytes.fromhex(case['payload_hex']))
        native=bytes.fromhex(out['buffer_hex'])
        encoded=command.encode(buffer_size=out['buffer_length'])
        if native!=encoded:raise AssertionError(f'native mismatch at payload length {len(command.payload)}')
        results.append(dict(payload_length=len(command.payload),buffer_length=len(native),
                            sha256=hashlib.sha256(native).hexdigest(),equal=True))
    report=dict(provenance='executed Apple TAManagerProxy base initializer and memory-only prepareCommand method; fresh object per case',
                seed=20261019,cases=len(results),all_equal=True,results=results)
    path=ROOT/'evidence/native-serializer-comparison.json'
    path.write_text(json.dumps(report,indent=2)+'\n')
    print(f'{len(results)} complete native buffers match. Report: {path}')


if __name__=='__main__':main()
