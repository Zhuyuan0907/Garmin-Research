#!/usr/bin/env python3
"""Normal artifact sealing only; no IMG content or reviewed mapper execution."""
import hashlib,json,os
from pathlib import Path
BASE=Path(__file__).resolve().parent;ROOT=Path('/root/garmin')
def need(x,m):
 if not x:raise ValueError(m)
def st(p):
 s=p.stat();return [s.st_dev,s.st_ino,s.st_size,s.st_mtime_ns,s.st_ctime_ns]
def sha(b):return hashlib.sha256(b).hexdigest()
proof=json.loads((BASE/'proof.json').read_bytes());receipt=json.loads((BASE/'actual-exec-terminal-receipt.json').read_bytes())
need(receipt['exit_code']==0 and receipt['terminal_chunk']=='28762d' and proof['all_assigned_pureDATA_checks_completed'],'Actual successful ordinary DATA terminal')
for tag,path in [('v2','staging/navigation-country-native-candidate-v2/gmapprom1.img'),('v3','staging/navigation-country-native-lane-candidate-v3/gmapprom1.img')]:
 need(st(ROOT/path)==proof['source_stats_before'][tag]==proof['source_stats_after'][tag],'Source actual stats unchanged without reopening content')
for r in proof['normal_input_pins']:
 need(st(ROOT/r['path'])==r['stat_after'],'Normal closed input source stats unchanged')
need(not (BASE/'sealed-files.json').exists(),'Fresh seal only')
files=sorted(p for p in BASE.rglob('*') if p.is_file() and p.name not in ['sealed-files.json','actual-sealer-terminal-receipt.json'])
rows=[];total=0
for p in files:
 b=p.read_bytes();before=st(p);need(len(b)==before[2] and len(b)<=2*1024*1024,'Whole small artifact')
 os.chmod(p,0o444);after=st(p);need(before[:4]==after[:4],'Only new artifact mode closure')
 need(p.read_bytes()==b and st(p)==after,'Actual full small artifact readback')
 rows.append({'path':str(p.relative_to(ROOT)),'bytes':len(b),'sha256':sha(b),'stat_at_seal':after,'mode':oct(p.stat().st_mode&0o777)})
 total+=len(b)
need(total<=4*1024*1024,'Small new namespace<=4MiB')
manifest={'schema':'L5-exclusive-stock-reuse-ordinary-data-seal/v1','files':rows,'payload_bytes':total,
 'actual_terminal':'28762d EXIT0','actual_IMG_read_bytes':141550252,'all_sources_oldseals_untouched':True,
 'original_IMG_and_closed_input_stats_verified':True,'seal_IMG_content_reads':0,
 'method':'Whole small output readback before/after newmode0444, exact SHA/size/dev/inode/mtime/ctime.',
 'L6_proposal_is_arithmetic_only_unexecuted':True,'excluded_post_seal_files':['sealed-files.json','actual-sealer-terminal-receipt.json'],
 'IMG_device_native_install_render_acceptance':False}
b=(json.dumps(manifest,ensure_ascii=False,indent=2)+'\n').encode();p=BASE/'sealed-files.json';p.write_bytes(b);os.chmod(p,0o444);need(p.read_bytes()==b,'Seal byte readback')
print(json.dumps({'closed_DATA_result_sealed':True,'seal_SHA256':sha(b),'seal_bytes':len(b),'listed_files':len(rows),'payload_bytes':total,
 'proof_SHA256':sha((BASE/'proof.json').read_bytes()),'summary_SHA256':sha((BASE/'scope-summary.json').read_bytes()),
 'L6proposal_SHA256':sha((BASE/'L6-next-scope-proposal.json').read_bytes()),'seal_IMG_reads':0}),flush=True)
