#!/usr/bin/env python3
"""Single authorized targeted osmium getid, exact21 IDs, bounded private output."""
import sys
sys.dont_write_bytecode=True
import gzip,hashlib,json,os,re,signal,subprocess,threading,time
from pathlib import Path
import xml.etree.ElementTree as ET
ROOT=Path('/root/garmin');HERE=Path(__file__).resolve().parent
CAP=ROOT/'staging/navigation-beitun-source-capture-corrected-v1'
PBF=ROOT/'sources/maps/taiwan-latest.osm.pbf';READS=[]
MAX_OUTPUT=65536;MAX_SOURCE=327206226
def sha(b):return hashlib.sha256(b).hexdigest()
def stat(p):
 s=p.stat();return [s.st_dev,s.st_ino,s.st_size,s.st_mtime_ns,s.st_ctime_ns]
def read(p,pin=None):
 before=stat(p);b=p.read_bytes();assert stat(p)==before
 if pin:assert (len(b),sha(b))==pin
 READS.append(dict(path=str(p.relative_to(ROOT)),byte_range=[0,len(b)],bytes=len(b),sha256=sha(b),stat=before))
 return b
def save(n,d):
 assert not(HERE/n).exists()
 (HERE/n).write_text(json.dumps(d,ensure_ascii=False,indent=2)+'\n')
def parse_trace(lines):
 positions={};ranges=[];maps=[];opens=closes=0;ignored_signals=0
 for line in lines:
  if '--- SIG' in line:ignored_signals+=1;continue
  if str(PBF) not in line:continue
  if 'openat(' in line:
   m=re.search(r'= (\d+)<',line);assert m,line
   positions[int(m[1])]=0;opens+=1
  elif 'lseek(' in line:
   m=re.search(r'lseek\((\d+)<[^>]+>, (-?\d+), (SEEK_\w+)\) = (-?\d+)',line);assert m,line
   assert int(m[4])>=0;positions[int(m[1])]=int(m[4])
  elif 'pread64(' in line:
   m=re.search(r'pread64\((\d+)<[^>]+>, .*?, (\d+), (\d+)\) = (\d+)',line);assert m,line
   ranges.append(dict(offset=int(m[3]),bytes=int(m[4]),syscall='pread64'))
  elif re.search(r'\bread\(',line):
   m=re.search(r'read\((\d+)<[^>]+>, .*?, (\d+)\) = (\d+)',line);assert m,line
   fd=int(m[1]);amount=int(m[3]);assert fd in positions
   ranges.append(dict(offset=positions[fd],bytes=amount,syscall='read'));positions[fd]+=amount
  elif 'mmap(' in line:maps.append(line)
  elif 'close(' in line:
   m=re.search(r'close\((\d+)<[^>]+>\) = 0',line);assert m,line
   del positions[int(m[1])];closes+=1
  else:raise ValueError('Unknown selected-source syscall form')
 assert not positions and opens==closes==1 and not maps
 assert ranges and all(0<=r['offset']<=r['offset']+r['bytes']<=MAX_SOURCE for r in ranges)
 amount=sum(r['bytes']for r in ranges);assert amount<=MAX_SOURCE
 union=[]
 for a,b in sorted((r['offset'],r['offset']+r['bytes'])for r in ranges if r['bytes']):
  if union and a<=union[-1][1]:union[-1][1]=max(union[-1][1],b)
  else:union.append([a,b])
 return dict(reads=ranges,actual_read_syscalls=len(ranges),actual_syscall_read_bytes=amount,
  unique_ranges=union,unique_bytes=sum(b-a for a,b in union),file_opens=opens,file_closes=closes,
  mmap_count=0,signal_lines_observed=ignored_signals,source_upper_bound_bytes=MAX_SOURCE,
  source_eof_not_required_by_getid=True,physical_disk_page_IO_not_measured=True)
def main():
 assert not(HERE/'attempt-started.json').exists(),'No second extraction attempt authorized'
 assert HERE.stat().st_mode&0o777==0o700
 seal=json.loads(read(CAP/'SEAL.json'));cp=read(CAP/'proof.json')
 assert sha(cp)==seal['files']['proof.json']['SHA256']
 proof=json.loads(cp);z=read(CAP/'missing-source-groups.jsonl.gz',(18867,'937cfd4cd38ee374e99bdbb08d0a2546b6d9a40e6ea71bdd47408d309dfdc221'))
 plain=gzip.decompress(z);assert (len(plain),sha(plain))==(383921,'784bca17b70321b36a084b7a987849207a66fe34733b7b9ae28fcfb9ad24d031')
 lines=plain.splitlines(keepends=True);assert len(lines)==102
 found=[(i,line,json.loads(line))for i,line in enumerate(lines,1)if json.loads(line)['original_prepared_group']['group_id']==172188]
 assert len(found)==1;line_number,line,captured=found[0];group=captured['original_prepared_group']
 ids=group['source_ids'];assert len(ids)==len(set(ids))==group['source_node_count']==21
 assert group['separate_floor_unit_nodes']==20 and group['different_coordinate_nodes']==0
 assert group['coordinate_selection_ready'] and not group['needs_coordinate_review']
 assert ids[0]==captured['original_first_node_ID']==8535190177
 (HERE/'original-captured-group.json').write_text(json.dumps(captured,ensure_ascii=False,indent=2)+'\n')
 (HERE/'original-capture-line.jsonl').write_bytes(line)
 (HERE/'node-ids.txt').write_text(''.join('n'+str(v)+'\n'for v in ids))
 manifest_path=ROOT/'staging/maps/Taiwan_OSM_20261001_UTF8/manifest.json'
 meta=json.loads(read(manifest_path));inherited=proof['source_origin_inherited']
 assert inherited['path']==str(PBF.relative_to(ROOT)) and inherited['bytes']==MAX_SOURCE
 digest=inherited['sha256_inherited_not_rehashed']
 assert meta['source']['sha256']==digest=='f57631c6c5cdcee9b2e38c460494bf224c80d03301e6a45fd3bfaec0b52e5912'
 assert meta['source']['bytes']==MAX_SOURCE and meta['osm_data_timestamp']==inherited['snapshot_utc']=='2026-10-01T20:22:06Z'
 # Only small current-tool metadata probes. No PBF open/hash here.
 help_result=subprocess.run(['/usr/bin/osmium','getid','--help'],capture_output=True,check=True)
 version_result=subprocess.run(['/usr/bin/osmium','--version'],capture_output=True,check=True)
 (HERE/'osmium-getid-help.txt').write_bytes(help_result.stdout+help_result.stderr)
 (HERE/'osmium-version.txt').write_bytes(version_result.stdout+version_result.stderr)
 assert b'--id-file' in help_result.stdout and b'--verbose-ids' in help_result.stdout and b'--output-format' in help_result.stdout
 before=stat(PBF);assert before[2]==MAX_SOURCE
 sourcepin=dict(path=str(PBF.relative_to(ROOT)),bytes=MAX_SOURCE,existing_snapshot_utc=inherited['snapshot_utc'],
  inherited_SHA256_not_rehashed=digest,existing_metadata_sources=[str((CAP/'proof.json').relative_to(ROOT)),str(manifest_path.relative_to(ROOT))],
  existing_SHA_and_size_and_snapshot_pins_agree=True,new_before_stat=before,
  no_earlier_inode_stat_pin_claimed=True,full_PBF_hash_verified_this_scope=False)
 save('prepared-inputs.json',dict(input_read_receipts=READS,source_pin=sourcepin,
  capture_line=line_number,capture_plain_bytes=len(plain),capture_plain_sha256=sha(plain),capture_rows=102,capture_EOF_and_CRC=True,
  original_full_group_retained=True,exact_ID_count=21,max_getid_invocations=1,max_raw_output_bytes=MAX_OUTPUT,
  private_directory_mode='0700',raw_extract_must_remain_private=True))
 argv=['/usr/bin/strace','-f','-qq','-yy','-s','0','-P',str(PBF),'-e','trace=openat,read,pread64,lseek,mmap,close',
  '-o',str(HERE/'targeted-PBF-IO.trace'),'/usr/bin/osmium','getid','--no-progress','--verbose-ids',
  '-f','osm','-i',str(HERE/'node-ids.txt'),str(PBF)]
 save('attempt-started.json',dict(argv=argv,started_unix_ns=time.time_ns(),single_extraction_authorization=True,
  source_stat_before=before,expected_ID_count=21,source_budget_bytes=MAX_SOURCE,output_budget_bytes=MAX_OUTPUT))
 mono=time.monotonic();overflow=False;timeout=False;output_size=0
 with (HERE/'osmium.stderr.txt').open('wb')as err,(HERE/'rawextract.osm').open('xb')as out:
  os.chmod(HERE/'rawextract.osm',0o600)
  process=subprocess.Popen(argv,stdout=subprocess.PIPE,stderr=err,start_new_session=True)
  def stop_timeout():
   nonlocal timeout
   timeout=True
   try:os.killpg(process.pid,signal.SIGTERM)
   except ProcessLookupError:pass
  timer=threading.Timer(50,stop_timeout);timer.start()
  try:
   while True:
    b=process.stdout.read(4096)
    if not b:break
    if output_size+len(b)>MAX_OUTPUT:
     overflow=True;os.killpg(process.pid,signal.SIGTERM);break
    out.write(b);output_size+=len(b)
  finally:
   process.stdout.close();code=process.wait(timeout=5);timer.cancel()
 os.chmod(HERE/'rawextract.osm',0o400)
 after=stat(PBF);assert after==before
 save('extraction-process.json',dict(argv=argv,actual_getid_invocations=1,exit_code=code,
  elapsed_seconds=time.monotonic()-mono,raw_output_bytes=output_size,output_overflow=overflow,timed_out=timeout,
  source_stat_before=before,source_stat_after=after,source_stat_unchanged=True,
  source_full_hash_recomputed=False,raw_output_private_mode='0400',all_source_handles_closed=True))
 io=parse_trace((HERE/'targeted-PBF-IO.trace').read_text().splitlines())
 save('PBF-read-receipt.json',io)
 if code!=0 or overflow or timeout:
  save('extraction-gap.json',dict(reason='single extraction failed or output limit/time guard',retry_authorized=False));return
 raw=read(HERE/'rawextract.osm');xml=ET.fromstring(raw)
 elements=xml.findall('node');actual=[int(e.attrib['id'])for e in elements]
 missing=sorted(set(ids)-set(actual));extra=sorted(set(actual)-set(ids))
 save('extraction-membership.json',dict(requested_IDs=ids,actual_IDs=actual,missing_IDs=missing,extra_IDs=extra,
  actual_nodes=len(actual),duplicate_IDs=len(actual)!=len(set(actual)),other_objects=len(xml.findall('way'))+len(xml.findall('relation')),
  raw_extract_bytes=len(raw),raw_extract_sha256=sha(raw),raw_private_mode='0400',all_nodes_exact_requested=len(actual)==21 and not missing and not extra))
 if missing or extra or len(actual)!=21 or len(actual)!=len(set(actual)):
  save('extraction-gap.json',dict(reason='single extraction missing/extra/duplicate nodes',retry_authorized=False));return
 print(json.dumps(dict(result='single21-node extraction complete',actual_node_count=len(actual),
  actual_PBF_read_bytes=io['actual_syscall_read_bytes'],raw_extract_bytes=len(raw),raw_tags_not_printed=True,
  no_full_PBF_hash=True,handles_closed=True)))
if __name__=='__main__':main()
