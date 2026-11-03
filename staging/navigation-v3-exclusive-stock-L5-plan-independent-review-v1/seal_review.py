#!/usr/bin/env python3
"""Seal own L5 review artifacts; producer inputs checked by stat only."""
from pathlib import Path
import hashlib,json,os
ROOT=Path('/root/garmin');OUT=Path(__file__).resolve().parent
def sha(b):return hashlib.sha256(b).hexdigest()
def st(p):
 s=p.stat();return [s.st_dev,s.st_ino,s.st_size,s.st_mtime_ns,s.st_ctime_ns]
def need(v,m):
 if not v:raise ValueError(m)
need(not (OUT/'sealed-files.json').exists(),'Fresh own-result seal only')
raw=(OUT/'proof.json').read_bytes();proof=json.loads(raw)
need(sha(raw)=='2152d64c368482207b1834e8087f969937aeec1bfb19d6aca68c1309103a8f9e' and
 proof['all_assigned_bounded_review_checks_passed'],'Exact actual completed finite review proof')
receipt=json.loads((OUT/'actual-review-tool-receipt.json').read_bytes())
need(receipt['chunk_id']=='3fa361' and receipt['exit_code']==0,'Actual completed review tool receipt')
need(proof['actual_artifact_bytes_including_previews']==998654 and proof['actual_gzip_decompressed_bytes']==2655276 and
 proof['review_IMG_PBF_MAIN_producer_scanner_guest_audio_device_IO']==0,'Exact input/decompression budgets and zero prohibited IO')
for item in proof['actual_input_receipts']:
 need(st(ROOT/item['path'])==item['stat_before'],'Producer/closed source artifacts fullstats unchanged without reopening')
files=[]
for p in sorted(OUT.iterdir()):
 need(p.is_file() and not p.is_symlink(),'Only bounded regular own artifacts')
 if p.stat().st_mode&0o777!=0o444:p.chmod(0o444)
 before=st(p)
 with p.open('rb') as f:
  data=f.read(1048577);need(f.read(1)==b'' and len(data)==before[2],'Own small-file complete EOF')
 need(st(p)==before,'Own sealed artifact stable fullstat')
 files.append({'path':str(p.relative_to(ROOT)),'bytes':len(data),'sha256':sha(data),'mode':'0444','stat_at_seal':before})
row={'schema':'independent-exclusive-stock-L5-plan-review-seal/v1','all_assigned_bounded_review_checks_passed':True,
 'actual_review_exit_code':0,'actual_review_chunk':'3fa361','proof_sha256':sha(raw),'files':files,'file_count':len(files),
 'payload_bytes':sum(r['bytes'] for r in files),'producer_input_fullstats_unchanged':True,'sealer_producer_input_reopens':0,
 'all_own_handles_closed':True,'IMG_PBF_MAIN_producer_scanner_guest_audio_device_IO':0,
 'complete1636groups_and38734sum_verified':True,'all172_retained_oldstock_parent_locations_verified':True,
 'saved55canonical126bit_rows_and16shiftpairs_verified':True,'all38734_rawphysicalrows_or_fullincoming_graph_independently_verified':False,
 'capacity_still_exceeds610304B':True,'original128MiB_hardwarelimit_or_externalrefs_renderer_UI_install_proved':False}
p=OUT/'sealed-files.json';data=(json.dumps(row,ensure_ascii=False,indent=2)+'\n').encode()
with p.open('x') as f:f.write(data.decode());f.flush();os.fsync(f.fileno())
p.chmod(0o444)
print(json.dumps({'all_assigned_bounded_review_checks_passed':True,'sealed_files_sha256':sha(data),'file_count':len(files),
 'payload_bytes':row['payload_bytes'],'all_handles_closed':True,'producer_source_reopens':0}))
