#!/usr/bin/env python3
"""NEW finite execution of original primary comparator 1AC788; no actual query caller."""
import hashlib,json,datetime,struct
from pathlib import Path
from probe_original_sort_units_v4 import Probe,NativeImage,ROOT,BASE,DESC,ITER,STRING,extract,EXPECTED
pairs=[('㐀路','一街'),('䴀路','䴁路'),('民權路','民和路'),('A民權路','B民和路'),('民權A路','民和B路'),('𠀀路','民權路')]
host={}
for line in (BASE/'taxonomy-host-keys-v1.tsv').read_text().splitlines():
 name,key=line.split('\t');host[name]=bytes.fromhex(key)
image=NativeImage();items=extract(ROOT/'staging/navigation-search-encoding-v1/fixture-patched-new-id/gmapsupp.img');srt=next(v for k,v in items.items() if k.endswith('.SRT'));p=Probe(image,srt);res,tr=p.load(19,7052);assert res==0;p.trace.clear();cases=[]
for a,b in pairs:
 p.u.mem_write(STRING,a.encode()+b'\0');p.u.mem_write(STRING+512,b.encode()+b'\0');p.u.mem_write(ITER,struct.pack('<3I',DESC,STRING,STRING+512)+bytes(84))
 res,tr=p.call(0x1ac788,[ITER,4096,0,0]);signed=res if res<0x80000000 else res-0x100000000;assert signed in (-1,0,1)
 hs=(host[a]>host[b])-(host[a]<host[b])
 cases.append({'left':a,'right':b,'actual_native_primary_compare':signed,'official_r4924_sort_key_compare':hs,'same_order':signed==hs,'native_instructions':len(tr),'used_original_memzero_and_comparator':True});p.trace.clear()
proof={'checked_utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),'stock_main_sha256':EXPECTED,'source_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'native_entry':'0x1ac788','all_passed':True,'pairs':cases,'actual_query_or_hardware_verified':False,'limits':'Primary comparator takes synthetic iterator and memory-kind2 SRT descriptor. Counterexamples establish sorting disagreement, not actual MDR/UI caller reachability or navigation symptom cause.'}
(BASE/'native-host-compare-proof-v1.json').write_text(json.dumps(proof,ensure_ascii=False,indent=2)+'\n')
print(json.dumps({'all_passed':True,'pairs':cases},ensure_ascii=False))
