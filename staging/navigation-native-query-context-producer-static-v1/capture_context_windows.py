#!/usr/bin/env python3
"""Capture only explicitly selected MAIN pages; no IMG or guest execution."""
import hashlib,json,sys
from datetime import datetime,timezone
from pathlib import Path
ROOT=Path('/root/garmin');HERE=Path(__file__).resolve().parent
def sha(x):return hashlib.sha256(x).hexdigest()
def stat(p):
 s=p.stat();return [s.st_dev,s.st_ino,s.st_size,s.st_mtime_ns,s.st_ctime_ns]
def need(x,m):
 if not x:raise ValueError(m)
def main():
 pages=[int(x,0)for x in sys.argv[1:]];need(pages and len(pages)==len(set(pages)),'Explicit unique pages')
 meta_path=ROOT/'evidence/firmware-analysis/native-sections.json';meta_raw=meta_path.read_bytes()
 need(sha(meta_raw)=='07e37b4eef51a0844b8e8207fdfc1dd91161bdefe1870d038577f0df6aa98d9b','Startup mapping pin')
 meta=json.loads(meta_raw);path=ROOT/'evidence/firmware-analysis/main_02bd.bin';before=stat(path)
 need(before==[45826,524501,46962176,1790961981702588961,1791193582221334548],'MAIN immutable source stat')
 existing=list(HERE.glob('MAIN-page-*.bin'));need((len(existing)+len(pages))*4096<=24576,'New source cap24KiB')
 log=[]
 with path.open('rb',buffering=0)as f:
  for a in pages:
   need(a%4096==0,'Page alignment');p=HERE/('MAIN-page-%08x.bin'%a);need(not p.exists(),'No duplicate capture')
   hits=[c for c in meta['copies']if c['runtime_start']<=a and a+4096<=c['runtime_end']]
   load=hits[0]['load_start']+a-hits[0]['runtime_start']if len(hits)==1 else a
   need(len(hits)<=1,'Unique mapped region');need(0x50000<=load and load+4096<=0x50000+before[2],'Original source bounds')
   f.seek(load-0x50000);raw=f.read(4096);need(len(raw)==4096,'Exact read')
   with p.open('xb')as out:out.write(raw)
   log.append(dict(runtime=a,load=load,file_offset=load-0x50000,bytes=len(raw),sha256=sha(raw),path=str(p.relative_to(ROOT))))
 need(stat(path)==before,'Original MAIN unchanged')
 receipt=dict(schema='garmin-native-query-context-producer-static-capture/v1',created_utc=datetime.now(timezone.utc).isoformat(),source_path=str(path.relative_to(ROOT)),source_stat_before=before,source_stat_after=stat(path),source_whole_sha256_inherited=meta['stock_sha256'],whole_source_rehashed=False,new_source_reads=log,new_source_bytes=sum(x['bytes']for x in log),all_source_handles_closed=True,IMG_bytes_read=0,guest_cases_executed=0,all_assigned_checks_passed=True)
 out=HERE/('capture-%08x-receipt.json'%pages[0])
 with out.open('x')as f:json.dump(receipt,f,indent=2);f.write('\n')
 print(json.dumps({'receipt':str(out.relative_to(ROOT)),'new_MAIN_bytes':receipt['new_source_bytes'],'IMG_bytes':0,'all_assigned_checks_passed':True}))
if __name__=='__main__':main()
