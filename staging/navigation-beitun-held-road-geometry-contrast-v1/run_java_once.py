#!/usr/bin/env python3
"""One normal Java MapReader invocation, one selected tile, no native guest."""
import sys
sys.dont_write_bytecode=True
import hashlib,json,subprocess,time
from pathlib import Path
ROOT=Path('/root/garmin');HERE=Path(__file__).resolve().parent
def sha(b):return hashlib.sha256(b).hexdigest()
def stat(p):
 s=p.stat();return [s.st_dev,s.st_ino,s.st_size,s.st_mtime_ns,s.st_ctime_ns]
def main():
 assert not (HERE/'reader-process.json').exists()
 prep=json.loads((HERE/'prepared-inputs.json').read_text())
 selected=json.loads((HERE/'tile-selection.json').read_text())
 groups=json.loads((HERE/'candidate-groups.json').read_text())['groups']
 assert prep['ordinary_parser_allowed'] and selected['selected_tiles']==['70530020']
 assert [r['literal'] for r in groups if r['eligible_for_readonly_road_contrast']]==['景賢六街']
 assert prep['unique_target_labels']==['景賢六街','景賢六路','景賢北街']
 tile=ROOT/prep['selected_tile'];jar=ROOT/'sources/maps/mkgmap-r4924/mkgmap.jar'
 libs=sorted((jar.parent/'lib').glob('*.jar'))
 pins=prep['inherited_selected_tile_and_java_dependencies_sha256']
 receipts=[]
 for p in [tile,jar,*libs,HERE/'ReadRoadGeometryV2.java']:
  before=stat(p);raw=p.read_bytes();assert stat(p)==before
  relative=str(p.relative_to(ROOT));digest=sha(raw)
  if p!=HERE/'ReadRoadGeometryV2.java':assert digest==pins[relative]
  receipts.append(dict(path=relative,byte_range=[0,len(raw)],bytes=len(raw),sha256=digest,stat=before,
    purpose='selected-tile or dependency immutable hash verification; host read separate from Java parser'))
 argv=['/usr/bin/strace','-f','-qq','-yy','-s','0','-P',str(tile),'-e',
  'trace=openat,read,pread64,lseek,mmap,close','-o',str(HERE/'java-tile-IO.trace'),
  '/usr/bin/java','-Xmx384m','--class-path',str(jar)+':'+str(jar.parent/'lib')+'/*',
  str(HERE/'ReadRoadGeometryV2.java'),str(tile)]
 started=time.time_ns();mono=time.monotonic()
 with (HERE/'road-geometry.json').open('wb') as out,(HERE/'java-stderr.txt').open('wb') as err:
  process=subprocess.run(argv,stdout=out,stderr=err,timeout=60,check=False)
 receipt=dict(schema='one-ordinary-Java-selected-tile-process/v1',argv=argv,start_unix_ns=started,
  finish_unix_ns=time.time_ns(),elapsed_seconds=time.monotonic()-mono,exit_code=process.returncode,
  input_hash_read_receipts=receipts,parser_kind='mkgmap ordinary Java NET/RGN/LBL MapReader; no original ARM guest',
  maximum_tiles=1,actual_invocations=1,whole_Search_IMG_hash_or_read=False,full_source_or_PBF_read=False,
  geometry_ineligible_Rongxing_road_targets_excluded=True,original_reader_only_filter_changed=True,
  parser_result_or_IO_hooks=False,handles_closed=True)
 for r in receipts:assert stat(ROOT/r['path'])==r['stat']
 (HERE/'reader-process.json').write_text(json.dumps(receipt,ensure_ascii=False,indent=2)+'\n')
 assert process.returncode==0
 rows=json.loads((HERE/'road-geometry.json').read_text())
 assert all(r['file']==str(tile) for r in rows)
 assert all(set(r['labels'])&set(prep['unique_target_labels']) for r in rows)
 print(json.dumps(dict(exit_code=process.returncode,ordinary_Java_invocations=1,
  target_NET_rows=len(rows),labels=sorted({l for r in rows for l in r['labels']}),
  RGN_polylines=sum(len(r['segments']) for r in rows),tile=tile.name,
  native_CPU_cases=0,device_IO=False,all_handles_closed=True),ensure_ascii=False))
if __name__=='__main__':main()
