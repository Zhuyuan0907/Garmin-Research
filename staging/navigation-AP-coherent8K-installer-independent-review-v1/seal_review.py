import hashlib,json,os
from pathlib import Path
P=Path(__file__).resolve().parent
assert not (P/'sealed-files.json').exists()
cache={};fresh_reads=0
def get(name):
 global fresh_reads
 if name in cache:return cache[name]
 q=P/name;s=q.stat();assert s.st_size<=16384
 with q.open('rb') as h:b=h.read(16385)
 assert h.closed and len(b)==s.st_size
 assert [s.st_dev,s.st_ino,s.st_size,s.st_mtime_ns,s.st_ctime_ns]==pin5(q)
 fresh_reads+=len(b);cache[name]=b;return b
def pin5(q):
 s=q.stat();return [s.st_dev,s.st_ino,s.st_size,s.st_mtime_ns,s.st_ctime_ns]
inspection=json.loads(get('actual-cached-source-inspection-receipts.json'))
inherited={Path(r['path']).name:r for r in inspection['actual_owned_cache_and_small_validation_reads'][:2]}
assert set(inherited)=={'actual-input-read-receipts.json','small-input-source-capture.json.gz'}
review=json.loads(get('review.json'))
assert review['own_read_failures_and_budgets']['actual_total_raw_input_before_seal']==482303
assert review['finite_source_review_complete'] and review['actual_virtual_stock_roles']['old_binding_not_relabelled_actual_coherent']
rows=[]
for q in sorted(P.iterdir()):
 if not q.is_file():continue
 before=pin5(q)
 if q.name in inherited:
  r=inherited[q.name];assert before==r['stat_before_after'] and before[2]==r['bytes']
  sha=r['SHA256'];method='actual previous full owned read de3a74 + exact unchanged stat, no new content read'
 else:
  raw=get(q.name);sha=hashlib.sha256(raw).hexdigest();method='fresh bounded owned-file read by sealer'
 assert before==pin5(q)
 os.chmod(q,0o444);after=pin5(q);assert before[:4]==after[:4]
 rows.append({'path':str(q.relative_to(Path.cwd())),'bytes':before[2],'SHA256':sha,'mode':'0444',
              'stat_before_freeze':before,'stat_after_freeze':after,'hash_provenance':method})
x={'scope':P.name,'files':rows,'finite_readonly_source_review_complete':True,
   'producer_installer_adapter_import_or_execution':False,'true_IMG_ZIP_recipe_open_or_stat':False,
   'producer_source_or_gate_or_seal_modified':False,'source_full_passes':2,
   'own_first_capture_failure_preserved':'31bb86 EXIT1 after196827B source reads; no first hash journal',
   'inherited_owned_full_read_pins':'de3a74; own cache and actual-input receipt content not reread at seal',
   'before_sealer_raw_input':482303,'actual_fresh_sealer_owned_reads':fresh_reads,
   'before_seal_readback_raw_input':482303+fresh_reads,'seal_readback_bytes':0,
   'final_raw_input_bytes':0,'input_raw_cap':524288,
   'output_payload_bytes':0,'output_cap':131072,
   'excluded_self_references':['sealed-files.json','actual-sealer-terminal-receipt.json'],
   'production_bundle_load_atomic_device_v2_recovery_UI_installability_pending':True,
   'scope_stopped':True}
payload=sum(r['bytes'] for r in rows)
for _ in range(10):
 raw=(json.dumps(x,indent=2)+'\n').encode();n=len(raw)
 vals=(n,482303+fresh_reads+n,payload+n);keys=('seal_readback_bytes','final_raw_input_bytes','output_payload_bytes')
 if vals==tuple(x[k] for k in keys):break
 for k,v in zip(keys,vals):x[k]=v
else:raise AssertionError('fixedpoint')
assert x['final_raw_input_bytes']<=524288 and x['output_payload_bytes']<=131072
q=P/'sealed-files.json';q.write_bytes(raw);os.chmod(q,0o444)
with q.open('rb') as h:b=h.read()
assert h.closed and b==raw
print(json.dumps({'readonly_review_sealed':True,
 'seal':{'path':str(q.relative_to(Path.cwd())),'bytes':len(raw),'SHA256':hashlib.sha256(raw).hexdigest()},
 'report_pins':[r for r in rows if Path(r['path']).name in ('review.json','scope-summary.json','HANDOFF.md','actual-readonly-tool-receipts.json')],
 'final_raw_input_bytes':x['final_raw_input_bytes'],'output_payload_bytes':x['output_payload_bytes'],
 'new_IMG_ZIP_recipe_source_reads_or_stat':0,'producer_or_installer_execution':False}))
