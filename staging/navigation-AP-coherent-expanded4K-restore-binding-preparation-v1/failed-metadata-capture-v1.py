import pathlib,json,hashlib,ast,struct
p=pathlib.Path('staging/navigation-AP-coherent-expanded4K-restore-binding-preparation-v1'); receipts=[]
q=p/'source-and-recipe-read-receipts.json'; raw=q.read_bytes();budget=json.loads(raw);receipts.append({'path':str(q),'bytes':len(raw),'SHA256':hashlib.sha256(raw).hexdigest()})
q=p/'old-8K-helper-source-snapshot.py';raw=q.read_bytes();receipts.append({'path':str(q),'bytes':len(raw),'SHA256':hashlib.sha256(raw).hexdigest()});src=raw.decode();tree=ast.parse(src)
for n in tree.body:
 if isinstance(n,ast.FunctionDef) and n.name in ('_layouts_and_header','load_restore_binding'):
  print(ast.get_source_segment(src,n))
path=pathlib.Path('staging/navigation-v3-expanded4k-offline-isolation-v1/v3-content-expanded4k-experiment.img.disabled');s=path.stat();pin=[s.st_dev,s.st_ino,s.st_size,s.st_mtime_ns,s.st_ctime_ns];assert pin==[45826,538397,153337856,1791347653105259871,1791347659645611251];imgs=[]
with path.open('rb') as h:
 for label,at,n in [('metadata',0,90112),('MDRheader',23*4096,772)]:
  h.seek(at);b=h.read(n);assert len(b)==n;imgs.append({'label':label,'physical_offset':at,'bytes':n,'SHA256':hashlib.sha256(b).hexdigest()});(p/(label+'-actual.bin')).write_bytes(b)
  if label=='MDRheader': head=b
 directory=struct.unpack_from('<I',head,0x2b2)[0];print('DIRECTORYOFFSET',directory);assert directory==149220236
 at=23*4096+directory;h.seek(at);b=h.read(120);assert len(b)==120;imgs.append({'label':'MDRdirectory','physical_offset':at,'logical_offset':directory,'bytes':120,'SHA256':hashlib.sha256(b).hexdigest()});(p/'MDRdirectory-actual.bin').write_bytes(b);print('DIRhex',b.hex())
assert h.closed and path.stat()==s
x={'artifact_reads':receipts,'artifact_raw':budget['raw']+sum(r['bytes'] for r in receipts),'artifact_decoded':budget['decoded']+sum(r['bytes'] for r in receipts),'artifact_raw_cap':3145728,'artifact_decoded_cap':4194304,'IMG_reads':imgs,'IMG_bytes':sum(r['bytes'] for r in imgs),'IMG_cap':1048576,'IMG_before_after_stat':pin,'IMG_mode':oct(s.st_mode&0o777),'IMG_handle_closed':h.closed,'actual_full_IMG_hash_repeated':False,'IMG_component_hashes_repeated':False}
(p/'bounded-metadata-read-receipts.json').write_text(json.dumps(x,indent=2)+'\n');print('COUNTERS',json.dumps({k:v for k,v in x.items() if not isinstance(v,list)}))
