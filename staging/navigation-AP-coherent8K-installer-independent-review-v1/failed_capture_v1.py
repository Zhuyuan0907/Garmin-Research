import pathlib,json,hashlib,gzip,base64
s=pathlib.Path('staging/navigation-AP-coherent8K-installer-integration-preparation-v1');d=pathlib.Path('staging/navigation-AP-coherent8K-installer-independent-review-v1')
names=['HANDOFF.md','actual-host-tool-receipts.json','actual-sealer-receipt-seal.json','actual-sealer-tool-receipt.json','coherent-control-restore-binding.json','coherent_header_overlay.py','device_support.py','host-control-proof.json','install_native_house_supplement.py','manifest.json','native_8k_stock_restore.py','native_coherent8k_rollback.py','prepare_integration.py','proof.json','seal_integration.py','sealed-files.json','source-preparation-proof.json','test_integration.py'];rows=[];cap={}
for n in names:
 q=s/n;st=q.stat();assert st.st_size<=65536 and q.suffix in ('.py','.md','.json')
 with q.open('rb') as h:b=h.read(65537)
 after=q.stat();before=[st.st_dev,st.st_ino,st.st_size,st.st_mtime_ns,st.st_ctime_ns];a=[after.st_dev,after.st_ino,after.st_size,after.st_mtime_ns,after.st_ctime_ns];assert h.closed and before==a and len(b)==st.st_size;cap[n]=base64.b64encode(b).decode();rows.append({'path':str(q),'bytes':len(b),'SHA256':hashlib.sha256(b).hexdigest(),'stat_before_after':a,'mode':oct(after.st_mode&0o777),'handle_closed':True})
assert sum(r['bytes'] for r in rows)<=524288
plain=(json.dumps(cap,sort_keys=True,separators=(',',':'))+'\n').encode();z=gzip.compress(plain,mtime=0);assert len(z)<=65536;(d/'small-input-source-capture.json.gz').write_bytes(z)
rec={'scope':d.name,'actual_reads':rows,'actual_input_raw_bytes':sum(r['bytes'] for r in rows),'input_raw_cap':524288,'capture_bytes':len(z),'capture_SHA256':hashlib.sha256(z).hexdigest(),'capture_decoded_bytes':len(plain),'capture_decoded_SHA256':hashlib.sha256(plain).hexdigest(),'true_IMG_ZIP_recipe_open_or_stat':False,'producer_installer_or_import_executed':False}
(d/'actual-input-read-receipts.json').write_text(json.dumps(rec,indent=2)+'\n')
for n in ['native_coherent8k_rollback.py','manifest.json','HANDOFF.md','host-control-proof.json','actual-host-tool-receipts.json']:
 print(n);print(base64.b64decode(cap[n]).decode())
print('INPUTREAD',sum(r['bytes'] for r in rows),'CAPTURE',len(z))
