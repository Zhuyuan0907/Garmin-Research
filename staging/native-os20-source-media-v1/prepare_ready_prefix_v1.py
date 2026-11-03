#!/usr/bin/env python3
"""Pure FILE reconstruction of sealed READY endpoint; no guest or VM import."""
import sys
sys.dont_write_bytecode=True
import gzip,json,struct,hashlib
from pathlib import Path
BASE=Path(__file__).resolve().parent;ROOT=BASE.parents[1];OUT=BASE/'prefix'
READY=ROOT/'staging/native-os20-source-ready-v1/guest-v3/ready-proof.json.gz'
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def rel(p):return str(p.relative_to(ROOT))
def segments(path):
 b=path.read_bytes();h=struct.unpack_from('<16sHHIIIIIHHHHHH',b)
 for i in range(h[10]):
  k,o,a,_,fs,ms,fl,_=struct.unpack_from('<8I',b,h[5]+i*h[9])
  if k==1 and ms:yield a,fs,ms,fl,b[o:o+fs]
def main():
 assert not OUT.exists();OUT.mkdir()
 source=json.load(gzip.open(READY,'rt'));small=json.loads((READY.parent/'guest-proof.json').read_text())
 assert source['all_passed']and sha(READY)==small['proof_SHA256']
 file=ROOT/'staging/native-os20-source-ready-v1/file-v1/FILE-proof.json'
 assert json.loads(file.read_text())['all_passed']
 parent=ROOT/source['prefix'];assert sha(parent)==source['prefix_SHA256']
 old=json.load(gzip.open(parent,'rt'));replay={int(a):bytearray.fromhex(b)for a,b in old['whole_final'].items()}
 build=json.loads((ROOT/'staging/native-os20-source-ready-v1/build/manifest.json').read_text())
 for a,fs,ms,fl,data in segments(ROOT/build['ELF']):
  start=a&~4095;end=(a+ms+4095)&~4095;b=bytearray(b'\xa5'*(end-start));b[a-start:a-start+ms]=bytes(ms);b[a-start:a-start+fs]=data;replay[start]=b
 sys.path.insert(0,str(ROOT/'scripts'))
 from analyze_native_sections import NativeImage
 flash=source['source_backed_flash_page'];replay[flash['start']]=bytearray(NativeImage().read(flash['start'],flash['size']))
 assert hashlib.sha256(replay[flash['start']]).hexdigest()==flash['SHA256']
 for z in source['regions']:assert hashlib.sha256(replay[z['start']]).hexdigest()==z['before_SHA256']
 for row in source['CPU_store_journal']:
  z=next(z for z in source['regions']if z['start']<=row['address']and row['address']+row['size']<=z['start']+z['size'])
  b=replay[z['start']];off=row['address']-z['start'];n=row['size'];assert b[off:off+n].hex()==row['before_hex'];b[off:off+n]=row['value'].to_bytes(n,'little')
 for z in source['regions']:assert hashlib.sha256(replay[z['start']]).hexdigest()==z['after_SHA256']
 p=dict(all_passed=True,source_ready_proof=rel(READY),source_ready_proof_SHA256=sha(READY),
  source_ready_FILE_proof=rel(file),source_ready_FILE_proof_SHA256=sha(file),regions=source['regions'],
  whole_ready={str(a):b.hex()for a,b in replay.items()},boundary=source['boundary'],worker_TCB=source['worker_TCB'],
  workspace=source['workspace'],workspace_bytes=source['workspace_bytes'],adapter=source['adapter'],
  inherited_guest_patches=source['inherited_guest_patches'],source_sha256=source['source_sha256'],
  CPU_store_preimages_replayed=len(source['CPU_store_journal']),guest_or_old_37_objects_or_TTS_loader_reexecuted=False,
  VM_import_or_creation=False,device_IO=False)
 path=OUT/'ready-endpoint.json.gz'
 with path.open('xb')as f:
  with gzip.GzipFile(fileobj=f,mode='wb',mtime=0,compresslevel=6)as z:z.write(json.dumps(p,separators=(',',':')).encode())
 proof=dict(all_passed=True,prefix=rel(path),prefix_SHA256=sha(path),CPU_store_preimages_replayed=11440,
  source_sha256={rel(Path(__file__)):sha(Path(__file__)),rel(READY):sha(READY),rel(parent):sha(parent),rel(file):sha(file)},
  original_or_compiled_instructions_rerun=False,VM_import_or_creation=False,device_IO=False)
 (OUT/'FILE-prefix-proof.json').write_text(json.dumps(proof,indent=2)+'\n');print(json.dumps(proof),flush=True)
if __name__=='__main__':main()
