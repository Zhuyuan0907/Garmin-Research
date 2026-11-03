#!/usr/bin/env python3
"""Narrow exact map/container string and pointer search; no whole MAIN hash."""
from pathlib import Path
import hashlib
import json
import mmap
import struct
from capstone import Cs,CS_ARCH_ARM,CS_MODE_THUMB

ROOT=Path('/root/garmin');HERE=Path(__file__).resolve().parent
MAIN=ROOT/'evidence/firmware-analysis/main_02bd.bin';SECTION=ROOT/'evidence/firmware-analysis/native-sections.json';BASE=0x50000
TERMS=[b'DSKIMG',b'DSDIMG',b'GARMIN\0',b'gmapprom1',b'gmapprom',b'.img\0',b'.IMG\0',b'GMP\0',b'.System',b'map.img']


def stat(path):
    s=path.stat();return[s.st_dev,s.st_ino,s.st_size,s.st_mtime_ns,s.st_ctime_ns]


def main():
    before=stat(MAIN);section_raw=SECTION.read_bytes();sections=json.loads(section_raw)
    assert sections['stock_sha256']=='10ab7e1f864f3e9b39806b7d3b7c7eb11ba597fdd8cfc0796e281f509c5a54a8'
    def runtime(load):
        matches=[s for s in sections['copies']if s['load_start']<=load<s['load_end']]
        assert len(matches)==1
        s=matches[0];return s['runtime_start']+load-s['load_start']
    md=Cs(CS_ARCH_ARM,CS_MODE_THUMB);rows=[]
    with MAIN.open('rb')as f,mmap.mmap(f.fileno(),0,access=mmap.ACCESS_READ)as m:
        for term in TERMS:
            positions=[];at=0
            while True:
                at=m.find(term,at)
                if at<0:break
                positions.append(at);at+=1
            assert len(positions)<=100,'Exact map-specific term hit budget'
            for at in positions:
                load=BASE+at;address=runtime(load);key=struct.pack('<I',address);refs=[];cursor=0
                while True:
                    cursor=m.find(key,cursor)
                    if cursor<0:break
                    if cursor%4==0:
                        literal_load=BASE+cursor;literal=runtime(literal_load);uses=[]
                        for off in range(max(0,cursor-1024),cursor,2):
                            word=struct.unpack_from('<H',m,off)[0]
                            if word&0xf800!=0x4800:continue
                            ins_load=BASE+off;ins=runtime(ins_load)
                            if ((ins+4)&~3)+(word&255)*4==literal:
                                uses.append(dict(runtime=hex(ins),load=hex(ins_load),bytes=m[off:off+2].hex(),instruction=next(md.disasm(m[off:off+2],ins)).mnemonic+' '+next(md.disasm(m[off:off+2],ins)).op_str))
                        refs.append(dict(runtime_literal=hex(literal),load=hex(literal_load),bytes=key.hex(),candidate_thumb_PC_literal_users=uses))
                    cursor+=1
                assert len(refs)<=100,'Map-specific aligned pointer budget'
                rows.append(dict(term=term.decode('ascii').replace('\0','\\0'),load=hex(load),runtime=hex(address),bytes=term.hex(),aligned_runtime_pointer_references=refs))
    assert stat(MAIN)==before
    result=dict(schema='narrow-exact-map-string-pointer-search/v1',main_sha256_inherited_not_recomputed=sections['stock_sha256'],
        source_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),MAIN_stat_before=before,MAIN_stat_after=stat(MAIN),
        section_proof_sha256=hashlib.sha256(section_raw).hexdigest(),exact_terms=[t.hex()for t in TERMS],findings=rows,
        pointer_literal_users_are_candidates_not_AP_controlflow_proof=True,old_parser_CPU_or_device_not_run=True)
    p=HERE/'exact-map-string-search.json';assert not p.exists();p.write_text(json.dumps(result,indent=2)+'\n')
    for r in rows:print(json.dumps(dict(term=r['term'],runtime=r['runtime'],pointers=len(r['aligned_runtime_pointer_references']),users=[u['runtime']for ref in r['aligned_runtime_pointer_references']for u in ref['candidate_thumb_PC_literal_users']])),flush=True)


if __name__=='__main__':main()
