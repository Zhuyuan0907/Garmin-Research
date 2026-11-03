#!/usr/bin/env python3
"""Ordinary small proof/source capture only; no IMG/guest/producer execution."""
import base64,gzip,hashlib,json
from pathlib import Path
ROOT=Path('/root/garmin');OUT=Path(__file__).resolve().parent
COW=ROOT/'staging/navigation-native-lane-tree-cow-append-v1';UP=ROOT/'staging/navigation-v3-L6-exact-record-reuse-upper-bound-v1'
RAW_CAP=6*1024*1024;DEC_CAP=64*1024*1024;receipts=[];blobs={};raw_total=decoded_total=0
PINS={'upper/proof.json':'4afaafa7acddd900b63d648eedc22f1af0ac418ff4325051032b8758ad676a12',
 'upper/sealed-files.json':'f116357618c853f8b50628cc290035c2fe4dcfd0b98439590155a2c82348888d',
 'upper/result-summary.json':'4315cbbeb88143b9efe75748b165fa6a8e6da95dfcd833544378e9d7c8fab814'}
def st(p):
 s=p.stat();return [s.st_dev,s.st_ino,s.st_size,s.st_mtime_ns,s.st_ctime_ns]
try:
 assert not (OUT/'small-input-capture.json.gz').exists(),'Fresh unique source capture'
 for tag,base,names in [('cow',COW,['proof.json','sealed-files.json','prepare_lane_cow_appends.py','append_api.py','appends.json','actual-writer-API-binding-proof.json','output-readback-proof.json','derive_new_tree_paths.py','new-tree-path-proof.json']),
                        ('upper',UP,['proof.json','sealed-files.json','result-summary.json','measure_upper_bound.py','output-audit.json','actual-tool-receipts.json'])]:
  for name in names:
   p=base/name;before=st(p);assert before[2]<=65536 and raw_total+before[2]<=RAW_CAP and decoded_total+before[2]<=DEC_CAP
   b=p.read_bytes();raw_total+=len(b);decoded_total+=len(b);assert st(p)==before
   key=tag+'/'+name;digest=hashlib.sha256(b).hexdigest()
   if key in PINS:assert digest==PINS[key],key+' explicit rootpin'
   receipts.append({'key':key,'path':str(p.relative_to(ROOT)),'bytes':len(b),'SHA256':digest,'stat_before':before,'stat_after':st(p),'actualmode':oct(p.stat().st_mode&0o777)})
   blobs[key]=base64.b64encode(b).decode()
 capture={'blobs_base64':blobs,'receipts':receipts,'actual_raw_artifact_read_bytes':raw_total,'actual_decoded_artifact_bytes':decoded_total,'raw_cap':RAW_CAP,'decoded_cap':DEC_CAP,'IMG_read_bytes':0,'reviewedcode_execution':False}
 (OUT/'small-input-capture.json.gz').write_bytes(gzip.compress((json.dumps(capture,separators=(',',':'))+'\n').encode(),mtime=0))
 (OUT/'small-input-read-receipts.json').write_text(json.dumps({k:v for k,v in capture.items() if k!='blobs_base64'},indent=2)+'\n')
 for key in ['cow/proof.json','cow/appends.json','upper/proof.json','upper/result-summary.json']:
  print(key,base64.b64decode(blobs[key]).decode())
 for key,terms in [('cow/prepare_lane_cow_appends.py',['emit_group','group_report','emitted','new_first','level == 6','level==6','clone','new_integer','records','append_group','new_count']),
                   ('upper/measure_upper_bound.py',['target_first','STOCK','multiplicity','new_index','newindex','target_keys','target_count','zip(','ordinal','range(',"'stock'",'append(','.pack(','.write('])]:
  lines=base64.b64decode(blobs[key]).decode().splitlines();selected=set()
  for i,line in enumerate(lines):
   if any(term in line for term in terms):selected.update(range(max(0,i-2),min(len(lines),i+5)))
  print('SOURCE EXCERPTS '+key)
  for i in sorted(selected):print(f'{i+1}: {lines[i]}')
 print(json.dumps({'actual_raw_artifact_read_bytes':raw_total,'actual_decoded_artifact_bytes':decoded_total,'IMGreads':0,'producerexec':False}))
except BaseException as e:
 (OUT/'actual-small-capture-failure.json').write_text(json.dumps({'error':str(e),'raw_read_bytes':raw_total,'decoded_bytes':decoded_total,'receipts':receipts},indent=2)+'\n');raise
