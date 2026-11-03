import hashlib,json,os
from pathlib import Path
P=Path(__file__).resolve().parent
assert not (P/'sealed-files.json').exists()
rows=[];cache={};read_bytes=0
for q in sorted(P.iterdir()):
 if not q.is_file():continue
 s=q.stat();assert s.st_size<=65536
 with q.open('rb') as h:raw=h.read(65537)
 assert h.closed and len(raw)==s.st_size and q.stat()==s
 read_bytes+=len(raw);cache[q.name]=raw
 os.chmod(q,0o444);a=q.stat()
 assert (s.st_dev,s.st_ino,s.st_size,s.st_mtime_ns)==(a.st_dev,a.st_ino,a.st_size,a.st_mtime_ns)
 rows.append({'path':str(q.relative_to(Path.cwd())),'bytes':len(raw),'SHA256':hashlib.sha256(raw).hexdigest(),
              'mode':'0444','stat_before_freeze':[s.st_dev,s.st_ino,s.st_size,s.st_mtime_ns,s.st_ctime_ns],
              'stat_after_freeze':[a.st_dev,a.st_ino,a.st_size,a.st_mtime_ns,a.st_ctime_ns],
              'actual_hash_read_handle_closed':h.closed})
budget=json.loads(cache['preseal-budget-final.json']);summary=json.loads(cache['final-scope-summary.json'])
assert hashlib.sha256(cache['expanded_4k_stock_restore.py']).hexdigest()==summary['final_API']['SHA256']
assert hashlib.sha256(cache['expanded4K-stock-restore-binding.json']).hexdigest()==summary['binding']['SHA256']
assert hashlib.sha256(cache['executed-preparation-API-source.py.txt']).hexdigest()=='29f5f11c3f6eb1b0cc2de84840e78c7bd93dd73badac787aaeeede2e294b65bb'
old=Path('staging/navigation-native-8k-layout-restore-api-v1/native_8k_stock_restore.py');s=old.stat()
with old.open('rb') as h:oldraw=h.read(26504)
assert h.closed and len(oldraw)==26503 and old.stat()==s
assert hashlib.sha256(oldraw).hexdigest()=='43e041518baa72bfbdbc26c627d435749c4bf85adf7882e47ffcfb655c46fe5f'
read_bytes+=len(oldraw)
old_read={'path':str(old),'bytes':len(oldraw),'SHA256':hashlib.sha256(oldraw).hexdigest(),
          'stat_before_after':[s.st_dev,s.st_ino,s.st_size,s.st_mtime_ns,s.st_ctime_ns],
          'mode':oct(s.st_mode&0o777),'handle_closed':h.closed,'not_imported_or_mutated':True}
old_stats=[]
pins={
 'staging/navigation-v3-expanded4k-offline-isolation-v1/v3-content-expanded4k-experiment.img.disabled':
 [45826,538397,153337856,1791347653105259871,1791347659645611251],
 'staging/navigation-country-layout-restore-v2/restore-layout.json.gz':
 [45826,537899,879499,1791315658150755943,1791315658181971477],
 'staging/navigation-country-native-lane-restore-v3/actual-stock-restore-binding.json':
 [45826,538049,292144,1791317443079083775,1791317504736963562],
}
for name,pin in pins.items():
 q=Path(name);s=q.stat();actual=[s.st_dev,s.st_ino,s.st_size,s.st_mtime_ns,s.st_ctime_ns]
 assert actual==pin
 old_stats.append({'path':name,'stat_before_after':actual,'mode':oct(s.st_mode&0o777),'stat_only_no_content_read':True})
x={'scope':P.name,'files':rows,'all_finite_preparation_and_final_helper_controls_passed':True,
   'actual_bounded_preparation':'2b2f22 EXIT0','actual_final_guard_controls':'95aa48 EXIT0',
   'final_source_positive_production_rebind_or_whole_restore_run':False,
   'old_live_helper_final_actual_read':old_read,'original_source_stat_checks':old_stats,
   'final_source_and_executed_preparation_source_distinguished':True,
   'raw_before_seal_readback':budget['raw']+read_bytes,
   'decoded_before_seal_readback':budget['decoded']+read_bytes,
   'seal_readback_bytes':0,'final_raw_artifact_bytes':0,'final_decoded_artifact_bytes':0,
   'raw_cap':3145728,'decoded_cap':4194304,'new_IMGbytes':120,'prior_failed_v1_IMGbytes':90884,
   'cumulative_v1_v2_IMGbytes':91004,'IMGcap':1048576,'additional_IMGread_at_seal':0,
   'output_payload_cap':262144,'output_payload_bytes':0,
   'excluded_self_references':['sealed-files.json','actual-sealer-terminal-receipt.json'],
   'scope_stopped':True,'no_device_native_audio_firmware_install_package_claim':True}
payload=sum(r['bytes'] for r in rows)
for _ in range(10):
 raw=(json.dumps(x,indent=2)+'\n').encode();n=len(raw)
 vals=(n,x['raw_before_seal_readback']+n,x['decoded_before_seal_readback']+n,payload+n)
 keys=('seal_readback_bytes','final_raw_artifact_bytes','final_decoded_artifact_bytes','output_payload_bytes')
 if vals==tuple(x[k] for k in keys):break
 for k,v in zip(keys,vals):x[k]=v
else:raise AssertionError('manifest fixedpoint')
assert x['final_raw_artifact_bytes']<=3145728 and x['final_decoded_artifact_bytes']<=4194304
assert x['output_payload_bytes']<=262144
q=P/'sealed-files.json';q.write_bytes(raw);os.chmod(q,0o444)
with q.open('rb') as h:b=h.read()
assert h.closed and b==raw
print(json.dumps({'scope_sealed':True,'seal':{'path':str(q.relative_to(Path.cwd())),'bytes':len(raw),'SHA256':hashlib.sha256(raw).hexdigest()},
 'report_pins':[r for r in rows if Path(r['path']).name in ('expanded_4k_stock_restore.py','expanded4K-stock-restore-binding.json',
                    'final-scope-summary.json','proof.json','final-source-guard-review-and-controls.json','HANDOFF.md','API.md')],
 'final_raw_artifact_bytes':x['final_raw_artifact_bytes'],'final_decoded_artifact_bytes':x['final_decoded_artifact_bytes'],
 'new_IMGbytes':120,'cumulative_IMGbytes':91004,'payload_bytes':x['output_payload_bytes'],
 'old_helper_live_SHA_verified_unchanged':True,'production_reconstruction_run':False}))
