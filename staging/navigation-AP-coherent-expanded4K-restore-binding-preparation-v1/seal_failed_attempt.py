import hashlib,json,os
from pathlib import Path
P=Path(__file__).resolve().parent
assert not (P/'sealed-files.json').exists()
rows=[];raws={}
for q in sorted(P.iterdir()):
 if not q.is_file():continue
 st=q.stat();assert st.st_size<=131072
 with q.open('rb') as h:b=h.read(131073)
 assert h.closed and len(b)==st.st_size and q.stat()==st
 raws[q.name]=b;os.chmod(q,0o444);s=q.stat();assert (st.st_dev,st.st_ino,st.st_size,st.st_mtime_ns)==(s.st_dev,s.st_ino,s.st_size,s.st_mtime_ns)
 rows.append({'path':str(q.relative_to(Path.cwd())),'bytes':len(b),'SHA256':hashlib.sha256(b).hexdigest(),'mode':'0444','stat_after_freeze':[s.st_dev,s.st_ino,s.st_size,s.st_mtime_ns,s.st_ctime_ns]})
budget=json.loads(raws['preseal-budget.json']);delta=sum(len(v) for v in raws.values())
source=Path('staging/navigation-v3-expanded4k-offline-isolation-v1/v3-content-expanded4k-experiment.img.disabled');s=source.stat();assert [s.st_dev,s.st_ino,s.st_size,s.st_mtime_ns,s.st_ctime_ns]==[45826,538397,153337856,1791347653105259871,1791347659645611251]
x={'scope':P.name,'files':rows,'preserved_actual_failure':'0f1046 EXIT1, own host offset bug','no_IMG_read_by_failure_sealer':True,'original_IMG_stat_unchanged':True,'raw_before_seal_readback':budget['raw']+delta,'decoded_before_seal_readback':budget['decoded']+delta,'seal_readback_bytes':0,'final_raw_artifact_bytes':0,'final_decoded_artifact_bytes':0,'raw_cap':3145728,'decoded_cap':4194304,'IMGbytes':90884,'IMGcap':1048576,'excluded_self_references':['sealed-files.json','actual-sealer-terminal-receipt.json'],'scope_stopped':True}
for _ in range(10):
 b=(json.dumps(x,indent=2)+'\n').encode();n=len(b);vals=(n,x['raw_before_seal_readback']+n,x['decoded_before_seal_readback']+n)
 if vals==tuple(x[k] for k in ('seal_readback_bytes','final_raw_artifact_bytes','final_decoded_artifact_bytes')):break
 for k,v in zip(('seal_readback_bytes','final_raw_artifact_bytes','final_decoded_artifact_bytes'),vals):x[k]=v
else:raise AssertionError('fixedpoint')
assert x['final_raw_artifact_bytes']<=3145728 and x['final_decoded_artifact_bytes']<=4194304
assert delta+len(b)<=262144
q=P/'sealed-files.json';q.write_bytes(b);os.chmod(q,0o444)
with q.open('rb') as h:actual=h.read()
assert h.closed and actual==b
print(json.dumps({'failed_scope_sealed':True,'seal':{'path':str(q.relative_to(Path.cwd())),'bytes':len(b),'SHA256':hashlib.sha256(b).hexdigest()},'small_pins':[r for r in rows if Path(r['path']).name in ('failure-proof.json','scope-summary.json','metadata-actual.bin','MDRheader-actual.bin','failed-metadata-capture-v1.py')],'final_raw_artifact_bytes':x['final_raw_artifact_bytes'],'final_decoded_artifact_bytes':x['final_decoded_artifact_bytes'],'IMGbytes':90884,'payload_bytes':delta+len(b)}))
