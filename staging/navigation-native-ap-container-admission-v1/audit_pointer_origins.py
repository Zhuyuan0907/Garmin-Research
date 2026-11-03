#!/usr/bin/env python3
"""Final 68B pointer-origin audit, with no search/capture suite replay."""
from pathlib import Path
import hashlib
import json
import capstone

ROOT=Path('/root/garmin');HERE=Path(__file__).resolve().parent


def stat(p):
    s=p.stat();return[s.st_dev,s.st_ino,s.st_size,s.st_mtime_ns,s.st_ctime_ns]


def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()


def main():
    path=ROOT/'evidence/firmware-analysis/main_02bd.bin';before=stat(path)
    cs=capstone.Cs(capstone.CS_ARCH_ARM,capstone.CS_MODE_THUMB);fragments=[]
    with path.open('rb')as f:
        for address,size,purpose in [(0x1e8050,32,'Input buffer argument stored into saved header pointers'),
                                    (0x1e8150,36,'Header-relative 61 and60 pointer construction')]:
            f.seek(address-0x50000);b=f.read(size);assert len(b)==size
            insns=[dict(address=hex(i.address),bytes=i.bytes.hex(),mnemonic=i.mnemonic,operands=i.op_str)
                   for i in cs.disasm(b,address)]
            assert sum(len(bytes.fromhex(i['bytes']))for i in insns)==size
            fragments.append(dict(runtime_start=hex(address),load_start=hex(address),bytes=size,
                                  purpose=purpose,raw_hex=b.hex(),instructions=insns))
    assert stat(path)==before
    rows={int(i['address'],16):i for fr in fragments for i in fr['instructions']}
    assert rows[0x1e8152]['bytes']=='6130'
    assert rows[0x1e8154]['bytes']=='2a90'
    assert rows[0x1e8170]['bytes']=='6030'
    assert rows[0x1e8172]['bytes']=='2590'
    result=dict(schema='bounded-supplemental-pointer-origin-audit/v1',
                source_sha256=sha(Path(__file__)),MAIN_stat_before=before,MAIN_stat_after=stat(path),
                actual_explicit_read_operations=2,actual_explicit_read_bytes=68,
                fragments=fragments,
                interpretation='Header base saved at SP+68. Add61→SP+a8; add60→SP+94. '
                               'The geometry witness reads SP+94 offset1/2 = header61/62 '
                               'and SP+a8 offset2/3 = header63/64.',
                audit_note='The earlier supporting fragment named shared_header_pointer_origins '
                           'actually covers partition-offset computation; this supplement captures '
                           'the exact exponent-pointer constructions. Five-witness count unchanged.',
                AP_binding=False,CPU_executed=False,handles_closed=True)
    out=HERE/'supplemental-pointer-origin-proof.json';assert not out.exists()
    out.write_text(json.dumps(result,indent=2)+'\n')
    proof=HERE/'proof.json';prior=proof.read_bytes()
    (HERE/'proof-before-pointer-audit.json').write_bytes(prior)
    d=json.loads(prior)
    d['supplemental_pointer_origin_audit']=dict(path=str(out.relative_to(ROOT)),sha256=sha(out),
          actual_read_bytes=68,exact_header61_62_origin_bound=True,
          source=str(Path(__file__).relative_to(ROOT)),source_sha256=sha(Path(__file__)))
    d['prior_prepare_proof_sha256']=hashlib.sha256(prior).hexdigest()
    proof.write_text(json.dumps(d,indent=2,ensure_ascii=False)+'\n')
    print(json.dumps(dict(audit_explicit_read_bytes=68,operations=2,MAIN_stat_stable=True,
                          proof_sha256=sha(proof),handles_closed=True)))


if __name__=='__main__':main()
