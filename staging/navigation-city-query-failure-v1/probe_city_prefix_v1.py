#!/usr/bin/env python3
"""NEW finite city prefix cases; no old label/pair controls repeated."""
import sys,json,struct,hashlib,datetime
from pathlib import Path
ROOT=Path('/root/garmin');sys.dont_write_bytecode=True
sys.path.insert(0,str(ROOT/'staging/navigation-firmware-sort-v1'))
from probe_original_sort_units_v4 import Probe,NativeImage,DESC,ITER,STRING,EXPECTED
BASE=Path(__file__).resolve().parent
SRT=ROOT/'staging/navigation-firmware-sort-v1/packed-fixture-aligned-v2.SRT'
image=NativeImage();p=Probe(image,SRT.read_bytes());res,tr=p.load(19,4);assert res==0;p.trace.clear();cases=[]
for left,right,limit in [('台中','臺中市',4),('臺中','臺中市',4),('臺中市','臺中市',6),('台中市','臺中市',6),('臺','臺中市',2),('台','臺中市',2),('台中','臺中市',4096),('臺中','臺中市',4096)]:
 p.u.mem_write(STRING,left.encode()+b'\0');p.u.mem_write(STRING+512,right.encode()+b'\0');p.u.mem_write(ITER,struct.pack('<3I',DESC,STRING,STRING+512)+bytes(84));res,tr=p.call(0x1ac788,[ITER,limit,0,0]);sign=res if res<0x80000000 else res-0x100000000;assert sign in (-1,0,1)
 cases.append({'input':left,'city_index_label':right,'primary_unit_limit':limit,'actual_original_comparator_sign':sign,'prefix_units_equal_with_this_limit':sign==0,'native_instructions':len(tr),'input_is_synthetic_UTF8':True});p.trace.clear()
proof={'checked_utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),'stock_MAIN_sha256':EXPECTED,'source_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'input_SRT_sha256':hashlib.sha256(SRT.read_bytes()).hexdigest(),'native_entry':'0x1ac788','all_completed':True,'cases':cases,'actual_address_query_caller_or_keyboard_conversion_executed':False,'normalization_before_comparator_excluded':False,'old_23_pairs_48_labels_repeated':False,'device_IO':False,'limits':'Shows raw comparator distinguishes 台/臺 and recognizes matching bounded primary prefix. Actual city manager caller, prefix-unit-limit choice, map/provider eligibility and pre-comparison alias normalization remain unproved.'}
(BASE/'city-prefix-original-instruction-proof-v1.json').write_text(json.dumps(proof,ensure_ascii=False,indent=2)+'\n');print(json.dumps({'cases':cases,'actual_query_caller_verified':False},ensure_ascii=False))
