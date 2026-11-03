#!/usr/bin/env python3
"""Seal own finite artifact-review result, without reopening producer inputs."""
from pathlib import Path
import hashlib,json,os

ROOT=Path('/root/garmin');OUT=Path(__file__).resolve().parent
def sha(b):return hashlib.sha256(b).hexdigest()
def stat(p):
 s=p.stat();return [s.st_dev,s.st_ino,s.st_size,s.st_mtime_ns,s.st_ctime_ns]
def need(v,m):
 if not v:raise ValueError(m)
need(not (OUT/'sealed-files.json').exists(),'Fresh own-result sealing only')
raw=(OUT/'proof.json').read_bytes();proof=json.loads(raw)
need(sha(raw)=='a1123cc1eed0cade119061eb33f94c94dda92463e50980a090552d4d627d2bb4' and
 proof['all_assigned_bounded_review_checks_passed'],'Exact actual completed independent review proof')
receipt=json.loads((OUT/'actual-review-tool-receipt.json').read_bytes())
need(receipt['chunk_id']=='c69350' and receipt['exit_code']==0,'Actual completed review tool receipt')
need(proof['actual_total_artifact_bytes_including_previews']==736057 and
 proof['actual_total_gzip_decompressed_bytes']==637988 and proof['review_IMG_PBF_MAIN_producer_scanner_guest_audio_device_IO']==0,
 'Actual unchanged finite budgets and no prohibited source execution')
for item in proof['actual_inputs']:
 need(stat(ROOT/item['path'])==item['stat_before'],'All producer/closed source fullstats still unchanged; no file reopen')
files=[]
for p in sorted(OUT.iterdir()):
 need(p.is_file() and not p.is_symlink(),'Only finite regular own artifacts')
 if p.stat().st_mode&0o777!=0o444:p.chmod(0o444)
 before=stat(p)
 with p.open('rb') as f:
  data=f.read(1048577);need(f.read(1)==b'' and len(data)==before[2],'Complete own small-file EOF')
 need(stat(p)==before,'Own artifact stat stable')
 files.append({'path':str(p.relative_to(ROOT)),'bytes':len(data),'sha256':sha(data),'mode':'0444','stat_at_seal':before})
row={'schema':'independent-exclusive-stock-L4-plan-review-seal/v1','all_assigned_bounded_review_checks_passed':True,
 'actual_review_exit_code':0,'actual_review_chunk':'c69350','proof_sha256':sha(raw),'files':files,'file_count':len(files),
 'payload_bytes':sum(r['bytes'] for r in files),'producer_inputs_fullstats_unchanged':True,
 'all_own_handles_closed':True,'sealer_producer_source_reopens':0,'IMG_PBF_MAIN_producer_scanner_guest_audio_device_IO':0,
 'full1251plan_rows_checked':True,'only65_saved128bit_rows_independently_decoded':True,
 'all108235_rawrows_or_allL3occupancy_independently_verified':False,'capacity_still_notfit':True,
 'external_reference_renderer_rootcause_UI_or_install_proved':False}
p=OUT/'sealed-files.json';data=(json.dumps(row,ensure_ascii=False,indent=2)+'\n').encode()
with p.open('x') as f:f.write(data.decode());f.flush();os.fsync(f.fileno())
p.chmod(0o444)
print(json.dumps({'all_assigned_bounded_review_checks_passed':True,'sealed_files_sha256':sha(data),
 'file_count':len(files),'payload_bytes':row['payload_bytes'],'all_handles_closed':True,'no_producer_source_reopened':True}))
