import pathlib,json,hashlib,gzip
S=pathlib.Path('staging/navigation-AP-coherent8K-installer-integration-preparation-v1')
P=pathlib.Path('staging/navigation-AP-coherent8K-installer-independent-review-v1')
names=['HANDOFF.md','actual-host-tool-receipts.json','actual-sealer-receipt-seal.json','actual-sealer-tool-receipt.json','coherent-control-restore-binding.json','coherent_header_overlay.py','device_support.py','host-control-proof.json','install_native_house_supplement.py','manifest.json','native_8k_stock_restore.py','native_coherent8k_rollback.py','prepare_integration.py','proof.json','seal_integration.py','sealed-files.json','source-preparation-proof.json','test_integration.py']
cache={};rows=[]
for name in names:
 q=S/name;st=q.stat();assert st.st_size<=65536
 with q.open('rb') as h:b=h.read(65537)
 after=q.stat();pin=[st.st_dev,st.st_ino,st.st_size,st.st_mtime_ns,st.st_ctime_ns]
 assert h.closed and pin==[after.st_dev,after.st_ino,after.st_size,after.st_mtime_ns,after.st_ctime_ns]
 cache[name]=b.decode();rows.append({'path':str(q),'bytes':len(b),'SHA256':hashlib.sha256(b).hexdigest(),
                                    'stat_before_after':pin,'mode':oct(after.st_mode&0o777),'handle_closed':True})
assert sum(r['bytes'] for r in rows)==196827
assert 196827+sum(r['bytes'] for r in rows)<=524288
plain=(json.dumps(cache,ensure_ascii=False,separators=(',',':'))+'\n').encode()
z=gzip.compress(plain,mtime=0)
assert len(z)<98304
(P/'small-input-source-capture.json.gz').write_bytes(z)
seal=json.loads(cache['sealed-files.json'])
pins=seal['files']
verified=[]
for row in rows:
 matching=[p for p in pins if p['path']==row['path']]
 if matching:
  assert len(matching)==1
  entry=matching[0]
  assert entry['bytes']==row['bytes'] and entry.get('SHA256',entry.get('sha256'))==row['SHA256']
  verified.append(row['path'])
proof={'scope':P.name,'first_capture_failure':{'actual_chunk':'31bb86','exit_code':1,
       'source_read_bytes':196827,'cause':'Own base64-gzip snapshot<=65536B guard failed after all source reads; no source/data rejection',
       'first_hash_receipts_missing_at_throw':True},
       'explicit_second_source_pass_bytes':196827,'actual_cumulative_source_input_bytes':393654,
       'actual_second_source_reads':rows,'actual_second_read_matches_sealed_file_entries':verified,
       'capture':{'bytes':len(z),'SHA256':hashlib.sha256(z).hexdigest(),'decoded_bytes':len(plain),
                  'decoded_SHA256':hashlib.sha256(plain).hexdigest(),'encoding':'UTF8 source strings, not base64'},
       'input_raw_cap':524288,'outputs_cap':131072,
       'true_IMG_ZIP_recipe_open_or_stat':False,'reviewed_installer_adapter_or_module_import_run':False}
(P/'actual-input-read-receipts.json').write_text(json.dumps(proof,indent=2)+'\n')
for name in ['native_coherent8k_rollback.py','install_native_house_supplement.py','manifest.json','HANDOFF.md','host-control-proof.json','actual-host-tool-receipts.json']:
 print(name);print(cache[name])
print(json.dumps({'captured':True,'second_pass':196827,'actual_cumulative_source_reads':393654,
                  'capture_bytes':len(z),'sealed_entry_matches':len(verified)}))
