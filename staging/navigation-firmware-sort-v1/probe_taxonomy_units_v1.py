#!/usr/bin/env python3
"""NEW finite taxonomy scope; reuses original instruction harness, no old cases rerun."""
import hashlib,json,datetime,struct
from pathlib import Path
from probe_original_sort_units_v4 import Probe,NativeImage,ROOT,BASE,DESC,extract,EXPECTED
names=['㐀路','一街','䴀路','䴁路','民權路','民和路','A民權路','B民和路','民權A路','民和B路','𠀀路','𪛖路']
image=NativeImage();items=extract(ROOT/'staging/navigation-search-encoding-v1/fixture-patched-new-id/gmapsupp.img');srt=next(v for k,v in items.items() if k.endswith('.SRT'));p=Probe(image,srt);res,tr=p.load(19,7052);assert res==0
cases=[]
for name in names:
 got=p.units(name);got['instructions']=len(p.trace);cases.append(got);p.trace.clear()
for strength in [1,2]:
 got=p.units('民權路',strength=strength);got['instructions']=len(p.trace);cases.append(got);p.trace.clear()
proof={'checked_utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),'stock_main_sha256':EXPECTED,'source_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'input_srt_sha256':hashlib.sha256(srt).hexdigest(),'native_cases':cases,'all_passed':True,'actual_query_or_hardware_verified':False,'old_case_sets_rerun':False,'scope':'Actual original 1AC3DC instructions and map-file-kind2 SRT descriptor; synthetic caller iterator, no actual keyboard/MDR/UI query.'}
(BASE/'taxonomy-unit-proof-v1.json').write_text(json.dumps(proof,ensure_ascii=False,indent=2)+'\n')
(BASE/'taxonomy-host-input-v1.txt').write_text('\n'.join(names)+'\n')
print(json.dumps({'all_passed':True,'new_native_cases':len(cases),'device_search_verified':False}))
