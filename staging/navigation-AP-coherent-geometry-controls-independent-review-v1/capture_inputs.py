#!/usr/bin/env python3
"""Read small normal artifacts only, once each. Never opens IMG or executes reviewed sources."""
import base64,gzip,hashlib,json
from pathlib import Path
ROOT=Path('/root/garmin');OUT=Path(__file__).resolve().parent
NEW=ROOT/'staging/navigation-AP-coherent-geometry-virtual-controls-v2'
OLD=ROOT/'staging/navigation-AP-header-geometry-arithmetic-review-v1'
LIMIT=262144;receipts=[];blobs={};total=0
expected={
 'new/proof.json':'dace2db29b3a7d36dc74e775b78501bbe0d9673da77e8f524a05fe7b662e7683',
 'new/prepared-control-plan.json':'dc636ce504acb7ef3a8b0980d4f91b796f05fc6f07dcbb52aed9d73c6740f655',
 'new/sealed-files.json':'b3365a9aa57c0181adcbebf80ce3ac3c58463706b9e773280db3433e9eba67da',
 'new/actual-root-tool-receipt.json':'d66fd45754238a5c1cfc74307eb83ebcb13cd3528e139cc6e491a83143fc0794',
 'old/proof.json':'61c836cbee7e7faabfdf76d391a8ca0531e831ed9cf8b380700195b25081614b'}
def st(p):
 s=p.stat();return [s.st_dev,s.st_ino,s.st_size,s.st_mtime_ns,s.st_ctime_ns]
def read(tag,base,name):
 global total
 p=base/name;before=st(p);assert before[2]<=65536 and total+before[2]<=LIMIT
 assert p.suffix not in ['.img','.pbf'];b=p.read_bytes();total+=len(b)
 key=tag+'/'+name;digest=hashlib.sha256(b).hexdigest();assert st(p)==before and len(b)==before[2]
 if key in expected:assert digest==expected[key],key+' authoritative digest'
 receipts.append({'key':key,'path':str(p.relative_to(ROOT)),'bytes':len(b),'SHA256':digest,'before':before,'after':st(p),'mode':oct(p.stat().st_mode&0o777)})
 blobs[key]=base64.b64encode(b).decode();return b
try:
 assert not (OUT/'input-capture.json.gz').exists(),'Unique bounded capture'
 for tag,base in [('new',NEW),('old',OLD)]:
  names=['proof.json','sealed-files.json','actual-root-tool-receipt.json']
  if tag=='new':names+=['prepared-control-plan.json','producer-source.py','header-decoder-source.py',
   'eightK_end_mirror-header.bin','expanded_fourK_geometry-header.bin','eightK_end_mirror-actual-stream-receipt.json','expanded_fourK_geometry-actual-stream-receipt.json']
  else:names+=['stock-header.bin','healthy_v2-header.bin','regressed_v3-header.bin','expanded_4K-header.bin','input-read-receipts.json','reference-ImgHeader.java']
  for name in names:read(tag,base,name)
 packed={'blobs_base64':blobs,'receipts':receipts,'actual_normal_input_bytes':total,'cap':LIMIT,'IMG_CPU_guest_audio_reads_or_exec':0}
 (OUT/'input-capture.json.gz').write_bytes(gzip.compress((json.dumps(packed,separators=(',',':'))+'\n').encode(),mtime=0))
 (OUT/'input-read-receipts.json').write_text(json.dumps({'receipts':receipts,'actual_normal_input_bytes':total,'cap':LIMIT},indent=2)+'\n')
 for key in ['new/proof.json','new/prepared-control-plan.json','new/sealed-files.json','new/actual-root-tool-receipt.json',
             'new/eightK_end_mirror-actual-stream-receipt.json','new/expanded_fourK_geometry-actual-stream-receipt.json','old/proof.json']:
  print(key,base64.b64decode(blobs[key]).decode())
 print('NEW PRODUCER SOURCE\n'+base64.b64decode(blobs['new/producer-source.py']).decode())
 print('HEADER DECODER SOURCE\n'+base64.b64decode(blobs['new/header-decoder-source.py']).decode())
 print(json.dumps({'actual_normal_input_bytes':total,'source_and_artifact_cap':LIMIT,'IMG_reads':0,'producer_execution':False,'guest':False}))
except BaseException as e:
 (OUT/'actual-capture-failure.json').write_text(json.dumps({'error':str(e),'actual_input_bytes':total,'receipts':receipts},indent=2)+'\n');raise
