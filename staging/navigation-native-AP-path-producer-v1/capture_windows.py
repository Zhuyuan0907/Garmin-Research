#!/usr/bin/env python3
"""Bounded adaptive code-window reads via frozen startup-copy metadata only."""
from pathlib import Path
import argparse
import hashlib
import json
import struct
import capstone
from capstone.arm import ARM_OP_MEM, ARM_REG_PC

ROOT=Path('/root/garmin');HERE=Path(__file__).resolve().parent
MAIN=ROOT/'evidence/firmware-analysis/main_02bd.bin'
SECTIONS=ROOT/'evidence/firmware-analysis/native-sections.json'
EXPECTED='10ab7e1f864f3e9b39806b7d3b7c7eb11ba597fdd8cfc0796e281f509c5a54a8'
LIMIT=24576


def stat(p):
    s=p.stat();return[s.st_dev,s.st_ino,s.st_size,s.st_mtime_ns,s.st_ctime_ns]


def main():
    ap=argparse.ArgumentParser();ap.add_argument('--tag',required=True);ap.add_argument('--specs',required=True)
    ns=ap.parse_args();specs=json.loads(ns.specs)
    assert ns.tag.isalnum()
    sb=SECTIONS.read_bytes();sections=json.loads(sb);assert sections['stock_sha256']==EXPECTED
    ledger=HERE/'read-ledger.json';previous=json.loads(ledger.read_bytes())if ledger.exists()else dict(bytes=0,operations=0,batches=[],MAIN_stat=stat(MAIN))
    before=stat(MAIN);assert before==previous['MAIN_stat']
    windows=[];receipts=[];literalcache={};budget=previous['bytes']
    def locate(address,count):
        hits=[s for s in sections['copies']if s['runtime_start']<=address and address+count<=s['runtime_end']]
        assert len(hits)==1,(hex(address),count)
        sec=hits[0];load=sec['load_start']+address-sec['runtime_start']
        return load,sec['conditional']
    with MAIN.open('rb')as f:
        def read(address,count,purpose):
            nonlocal budget
            assert count>0 and budget+count<=LIMIT,(budget,count)
            load,conditional=locate(address,count);f.seek(load-0x50000);b=f.read(count);assert len(b)==count
            budget+=count;receipts.append(dict(runtime=hex(address),load=hex(load),bytes=count,purpose=purpose,conditional_copy=conditional))
            return b
        for spec in specs:
            name,address,count,mode,depth,parent=spec
            address=int(address,0);assert mode in ['Thumb','ARM','DATA'];assert 0<=depth<=3
            b=read(address,count,name)
            cs=capstone.Cs(capstone.CS_ARCH_ARM,capstone.CS_MODE_THUMB if mode=='Thumb'else capstone.CS_MODE_ARM);cs.detail=True
            rows=[]
            for i in ([] if mode=='DATA' else cs.disasm(b,address)):
                row=dict(address=hex(i.address),bytes=i.bytes.hex(),mnemonic=i.mnemonic,operands=i.op_str)
                if i.mnemonic=='ldr'and len(i.operands)==2 and i.operands[1].type==ARM_OP_MEM and i.operands[1].mem.base==ARM_REG_PC:
                    lit=((i.address+4)&~3)+i.operands[1].mem.disp if mode=='Thumb'else i.address+8+i.operands[1].mem.disp
                    if address<=lit and lit+4<=address+count:lb=b[lit-address:lit-address+4]
                    elif lit in literalcache:lb=literalcache[lit]
                    else:
                        try:lb=read(lit,4,'PC-relative literal for '+hex(i.address));literalcache[lit]=lb
                        except AssertionError:row['literal_unbacked']=hex(lit);rows.append(row);continue
                    row.update(literal_address=hex(lit),literal_value=hex(struct.unpack('<I',lb)[0]))
                rows.append(row)
            windows.append(dict(name=name,runtime_start=hex(address),bytes=count,mode=mode,depth=depth,parent=parent,
                                sha256=hashlib.sha256(b).hexdigest(),raw_hex=b.hex(),instructions=rows,
                                decoded_prefix_bytes=sum(len(bytes.fromhex(i['bytes']))for i in rows),
                                linear_disasm_not_a_controlflow_proof=True))
    assert stat(MAIN)==before
    output=HERE/('windows-'+ns.tag+'.json');assert not output.exists()
    result=dict(schema='bounded-AP-path-producer-window-capture/v1',source_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                MAIN_SHA_inherited=EXPECTED,MAIN_stat_before=before,MAIN_stat_after=stat(MAIN),
                sections_metadata_sha256=hashlib.sha256(sb).hexdigest(),explicit_read_bytes=budget-previous['bytes'],
                explicit_read_operations=len(receipts),cumulative_explicit_read_bytes=budget,limit_bytes=LIMIT,
                windows=windows,actual_read_receipts=receipts,no_MAIN_or_IMG_hash=True,no_MAIN_string_search=True,
                CPU_executed=False,device_or_IMG_access=False,handles_closed=True)
    output.write_text(json.dumps(result,indent=2)+'\n')
    previous['bytes']=budget;previous['operations']+=len(receipts);previous['batches'].append(dict(path=str(output.relative_to(ROOT)),sha256=hashlib.sha256(output.read_bytes()).hexdigest()))
    ledger.write_text(json.dumps(previous,indent=2)+'\n')
    for w in windows:
        print(json.dumps(dict(name=w['name'],start=w['runtime_start'],bytes=w['bytes'],decoded=w['decoded_prefix_bytes'],
                             calls=[i for i in w['instructions']if i['mnemonic']in ['bl','blx','bx']],
                             memory_operations=[i for i in w['instructions']if i['mnemonic']in ['ldr','str','ldrb','strb','ldrh','strh']and '[sp'not in i['operands']]),ensure_ascii=False))
    print(json.dumps(dict(output=str(output),read_bytes=result['explicit_read_bytes'],cumulative=budget,handles_closed=True)))


if __name__=='__main__':main()
