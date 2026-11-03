#!/usr/bin/env python3
"""Counted one-pass small-artifact seal; no original content reopen or reviewed-code execution."""
import base64,gzip,hashlib,json,os
from pathlib import Path
BASE=Path(__file__).resolve().parent;ROOT=Path('/root/garmin');CAP=262144;READ_BEFORE=156400
def need(x,m):
 if not x:raise ValueError(m)
def st(p):
 s=p.stat();return [s.st_dev,s.st_ino,s.st_size,s.st_mtime_ns,s.st_ctime_ns]
def sha(b):return hashlib.sha256(b).hexdigest()
need(not (BASE/'sealed-files.json').exists(),'Fresh finite seal')
files=sorted(p for p in BASE.rglob('*') if p.is_file() and p.name not in ['sealed-files.json','actual-sealer-terminal-receipt.json'])
payload=sum(p.stat().st_size for p in files);need(READ_BEFORE+payload+9000<=CAP,'Preflight complete final artifactread budget')
cache={};rows=[];actual=READ_BEFORE
for p in files:
 before=st(p);b=p.read_bytes();actual+=len(b);need(before==st(p) and len(b)==before[2],'Actual complete immutable small read')
 cache[str(p.relative_to(BASE))]=b;os.chmod(p,0o444);after=st(p);need(before[:4]==after[:4],'Only newfilemode changed')
 rows.append({'path':str(p.relative_to(ROOT)),'bytes':len(b),'sha256':sha(b),'mode':'0o444','stat_at_seal':after})
proof=json.loads(cache['proof.json']);receipt=json.loads(cache['actual-readonly-terminal-receipt.json'])
need(proof['all_assigned_finite_readonly_checks_completed'] and receipt['chunk']=='a7bad0' and receipt['exit_code']==0,'Actual independent review passed')
for name in ['input-capture.json.gz','initial-failure-input-capture.json.gz']:
 snapshot=json.loads(gzip.decompress(cache[name]))
 for r in snapshot['receipts']:need(st(ROOT/r['path'])==r['after'],'Closed original input metadata unchanged; content not reread')
manifest={'schema':'independent-AP-geometry-finite-readonly-seal/v1','files':rows,'payload_bytes':payload,
 'actual_readonly_terminal':'a7bad0 EXIT0','initial_review_failure':'c12201 EXIT1/IMG0 preserved',
 'explicit_artifact_read_bytes_before_seal':READ_BEFORE,'seal_artifact_read_bytes':payload,'explicit_artifact_bytes_before_seal_readback':actual,
 'aggregate_artifact_read_cap':CAP,'sealer_IMG_PBF_MAIN_reads':0,'all_closed_inputs_stat_unchanged':True,
 'original_producer_or_guest_execution':False,'independent_whole_virtual_hash_recomputed':False,
 'mode_closure_method':'One whole smallartifactread SHA/stat; only newfiles chmod0444, no second contentread. Seal readback counted separately.',
 'excluded_postseal_files':['sealed-files.json','actual-sealer-terminal-receipt.json']}
b=(json.dumps(manifest,separators=(',',':'))+'\n').encode();need(actual+len(b)<=CAP,'Final exact finite budget')
p=BASE/'sealed-files.json';p.write_bytes(b);os.chmod(p,0o444);again=p.read_bytes();actual+=len(again);need(again==b,'Actualsealbyte readback')
print(json.dumps({'sealed':True,'seal_SHA256':sha(b),'seal_bytes':len(b),'payload_bytes':payload,'listed_files':len(rows),
 'actual_aggregate_artifact_read_bytes':actual,'cap':CAP,'actual_review_IMG_bytes':0,'proof_SHA256':sha(cache['proof.json']),
 'summary_SHA256':sha(cache['scope-summary.json']),'L6proposal_SHA256':sha(cache['L6-next-preflight-proposal.json'])}),flush=True)
