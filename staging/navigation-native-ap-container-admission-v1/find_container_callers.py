#!/usr/bin/env python3
"""Exact-target ARM/Thumb direct branches plus seven UTF16 map strings only."""
from pathlib import Path
import hashlib
import json
import mmap
import struct

ROOT=Path('/root/garmin');HERE=Path(__file__).resolve().parent;BASE=0x50000
TARGETS={0x1e7e40,0x1e8046,0x1e86ce,0xfea50,0xfeb36}
WIDE=['gmapprom','gmapprom1.img','.img','.IMG','gmapsupp','Map/','Garmin/Map']


def sign(x,n):return x-(1<<n)if x&(1<<(n-1))else x


def stat(p):
    q=p.stat();return[q.st_dev,q.st_ino,q.st_size,q.st_mtime_ns,q.st_ctime_ns]


def main():
    path=ROOT/'evidence/firmware-analysis/main_02bd.bin';before=stat(path);sections=json.loads((ROOT/'evidence/firmware-analysis/native-sections.json').read_bytes());branches=[];strings=[]
    with path.open('rb')as f,mmap.mmap(f.fileno(),0,access=mmap.ACCESS_READ)as m:
        for sec in sections['copies']:
            if sec['runtime_start']in [0xf00000,0xffff0000]:continue
            start=sec['load_start']-BASE;end=sec['load_end']-BASE;delta=sec['runtime_start']-sec['load_start']
            for off in range(start,end-3,2):
                first=struct.unpack_from('<H',m,off)[0]
                if first&0xf800!=0xf000:continue
                second=struct.unpack_from('<H',m,off+2)[0]
                if second&0xf800 not in [0xf800,0xe800]:continue
                address=off+BASE+delta;target=address+4+(sign(first&0x7ff,11)<<12)+((second&0x7ff)<<1)
                if second&0xf800==0xe800:target&=~3
                if target in TARGETS:branches.append(dict(runtime=hex(address),load=hex(off+BASE),target=hex(target),mode='Thumb',bytes=m[off:off+4].hex(),conditional_code_copy=sec['conditional']))
            for off in range(start,end-3,4):
                word=struct.unpack_from('<I',m,off)[0]
                if word&0x0f000000!=0x0b000000:continue
                address=off+BASE+delta;target=address+8+(sign(word&0xffffff,24)<<2)
                if target in TARGETS:branches.append(dict(runtime=hex(address),load=hex(off+BASE),target=hex(target),mode='ARM',bytes=m[off:off+4].hex(),conditional_code_copy=sec['conditional']))
        for text in WIDE:
            term=text.encode('utf-16le');cursor=0;hits=[]
            while True:
                cursor=m.find(term,cursor)
                if cursor<0:break
                load=cursor+BASE;sec=next(s for s in sections['copies']if s['load_start']<=load<s['load_end'])
                hits.append(dict(load=hex(load),runtime=hex(sec['runtime_start']+load-sec['load_start'])));cursor+=1
            assert len(hits)<=100,'Only bounded exact wide-map-string hits';strings.append(dict(UTF16_text=text,hits=hits))
    assert stat(path)==before
    result=dict(schema='narrow-original-container-direct-branch-search/v1',source_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        main_identity_inherited=sections['stock_sha256'],main_full_sha_not_recomputed=True,MAIN_stat_before=before,MAIN_stat_after=stat(path),
        exact_targets=[hex(t)for t in sorted(TARGETS)],direct_branch_candidates=branches,wide_map_string_findings=strings,
        potential_data_false_positives_need_actual_instruction_context=True,no_CPU_device_or_old_suite_executed=True)
    p=HERE/'container-direct-call-search.json';assert not p.exists();p.write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps(dict(branch_candidates=branches,wide_string_findings=strings)),flush=True)


if __name__=='__main__':main()
