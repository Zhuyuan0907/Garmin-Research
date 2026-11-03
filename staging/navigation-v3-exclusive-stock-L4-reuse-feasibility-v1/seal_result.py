#!/usr/bin/env python3
"""Seal only new ordinary DATA outputs, checking existing source stats without content reads."""
import hashlib,json,os
from pathlib import Path
BASE=Path(__file__).resolve().parent;ROOT=Path('/root/garmin')
def need(x,m):
 if not x:raise ValueError(m)
def st(p):
 s=p.stat();return [s.st_dev,s.st_ino,s.st_size,s.st_mtime_ns,s.st_ctime_ns]
def digest(b):return hashlib.sha256(b).hexdigest()
proof=json.loads((BASE/'proof.json').read_bytes())
receipt=json.loads((BASE/'actual-exec-terminal-receipt.json').read_bytes())
need(receipt['terminal_exit_code']==0 and receipt['terminal_chunk']=='d1a040','Actual terminal identity')
need(proof['all_assigned_actual_DATA_checks_completed'],'Actual assigned DATA checks completed')
for p in ['staging/navigation-country-native-candidate-v2/gmapprom1.img',
          'staging/navigation-country-native-lane-candidate-v3/gmapprom1.img']:
 tag='v2' if '/navigation-country-native-candidate-v2/' in '/'+p else 'v3'
 need(st(ROOT/p)==proof['source_stats_before'][tag]==proof['source_stats_after'][tag],'Original source stat pin still unchanged')
files=sorted(p for p in BASE.rglob('*') if p.is_file() and p.name not in ['sealed-files.json','actual-sealer-terminal-receipt.json'])
need(not (BASE/'sealed-files.json').exists(),'Fresh seal only')
rows=[];total=0
for p in files:
 b=p.read_bytes();before=st(p);need(len(b)==before[2],'Whole small artifact readback')
 need(len(b)<=600000,'Small artifact only')
 os.chmod(p,0o444);after=st(p)
 need(before[:4]==after[:4],'Mode closure preserves content source times')
 again=p.read_bytes();need(again==b and st(p)==after,'Actual artifact full readback SHA/stat')
 rows.append({'path':str(p.relative_to(ROOT)),'bytes':len(b),'sha256':digest(b),'mode':oct(p.stat().st_mode&0o777),'stat_at_seal':after})
 total+=len(b)
need(total<=1048576,'Small namespace output <=1MiB')
seal={'schema':'exclusive-stock-L4-reuse-data-feasibility-seal/v1','files':rows,'payload_bytes':total,
 'actual_data_terminal':'d1a040 EXIT0','initial_failed_terminal':'db2114 EXIT1/IMG0',
 'actual_IMG_reads_during_sealer':0,'artifact_readback_method':'Whole small artifact byte read before and after mode0444; SHA/stat verified.',
 'original_sources_and_old_seals_untouched':True,'excluded_post_seal_files':['sealed-files.json','actual-sealer-terminal-receipt.json'],
 'no_image_compactor_or_patch_written':True}
b=(json.dumps(seal,ensure_ascii=False,indent=2)+'\n').encode();p=BASE/'sealed-files.json';p.write_bytes(b);os.chmod(p,0o444)
need(p.read_bytes()==b,'Seal actual readback')
print(json.dumps({'actual_DATA_result_sealed':True,'seal_SHA256':digest(b),'seal_bytes':len(b),'listed_files':len(rows),
 'payload_bytes':total,'proof_SHA256':digest((BASE/'proof.json').read_bytes()),
 'summary_SHA256':digest((BASE/'scope-summary.json').read_bytes()),'sealer_IMG_reads':0,'source_stats_unchanged':True}),flush=True)
