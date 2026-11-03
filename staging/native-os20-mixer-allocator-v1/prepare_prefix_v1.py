#!/usr/bin/env python3
"""FILE-only reconstruct already-executed Source boundary before mixer init.
No whole MAIN/whole-prefix byte file is duplicated in this new namespace.
"""
import sys
sys.dont_write_bytecode=True
import gzip,json,struct,hashlib
from pathlib import Path
BASE=Path(__file__).resolve().parent;ROOT=BASE.parents[1];OUT=BASE/'prefix'
OLD=ROOT/'staging/native-os20-source-media-v1'
READY=OLD/'prefix/ready-endpoint.json.gz';FAIL=OLD/'guest-v2/terminal-failure.json.gz'
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def rel(p):return str(p.relative_to(ROOT))
def segments(path):
 b=path.read_bytes();h=struct.unpack_from('<16sHHIIIIIHHHHHH',b)
 for i in range(h[10]):
  k,o,a,_,fs,ms,fl,_=struct.unpack_from('<8I',b,h[5]+i*h[9])
  if k==1 and ms:yield a,fs,ms,fl,b[o:o+fs]
def reconstruct():
 seal=json.loads((OLD/'SEAL-v1.json').read_text())
 for p in(READY,FAIL,OLD/'file-v1/FILE-proof.json',OLD/'build/manifest.json'):
  assert sha(p)==seal['files'][rel(p)]
 assert json.loads((OLD/'file-v1/FILE-proof.json').read_text())['all_passed']
 ready=json.load(gzip.open(READY,'rt'));fail=json.load(gzip.open(FAIL,'rt'));build=json.loads((OLD/'build/manifest.json').read_text())
 entry=next(e for e in fail['entries']if e['name']=='original_mixer_initializer');assert entry['ordinal']==78491
 state=entry['state'];assert state['GP16'][15]==0x3b9b66 and state['current_TCB']==0x183140a0
 replay={int(a):bytearray.fromhex(b)for a,b in ready['whole_ready'].items()}
 for a,fs,ms,fl,data in segments(ROOT/build['ELF']):
  start=a&~4095;end=(a+ms+4095)&~4095;b=bytearray(b'\xa5'*(end-start));b[a-start:a-start+ms]=bytes(ms);b[a-start:a-start+fs]=data;replay[start]=b
 regions=[dict(z)for z in fail['regions']];count=0
 for row in fail['CPU_store_journal']:
  if row['ordinal']>=entry['ordinal']:break
  a,n=row['address'],row['size'];z=next(z for z in regions if z['start']<=a and a+n<=z['start']+z['size'])
  b=replay[z['start']];off=a-z['start'];assert b[off:off+n].hex()==row['before_hex'];b[off:off+n]=row['value'].to_bytes(n,'little');count+=1
 for z in regions:z['after_SHA256']=hashlib.sha256(replay[z['start']]).hexdigest()
 p=dict(all_passed=True,regions=regions,whole_ready={str(a):b.hex()for a,b in replay.items()},boundary=dict(state=state),
  worker_TCB=ready['worker_TCB'],inherited_guest_patches=ready['inherited_guest_patches'],inherited_FIFO_publication=fail['publications'][0],
  source_ready_original_prefix_not_rerun=True,Source_packet_decode_registration_closed_not_rerun=True,
  entry_ordinal=entry['ordinal'],CPU_store_preimages_reconstructed=count)
 return p
def main():
 assert not OUT.exists();OUT.mkdir();p=reconstruct()
 meta=dict(all_passed=True,base_READY=rel(READY),base_READY_SHA256=sha(READY),partial_failure=rel(FAIL),partial_failure_SHA256=sha(FAIL),
  boundary=p['boundary'],entry_ordinal=p['entry_ordinal'],CPU_store_preimages_reconstructed=p['CPU_store_preimages_reconstructed'],
  regions=p['regions'],new_whole_MAIN_or_prefix_data_file_saved=False,VM_import_or_creation=False,device_IO=False,
  source_sha256={rel(p):sha(p)for p in(Path(__file__),READY,FAIL,OLD/'SEAL-v1.json',OLD/'file-v1/FILE-proof.json',OLD/'build/manifest.json',
   ROOT/json.loads((OLD/'build/manifest.json').read_text())['ELF'])})
 with(OUT/'FILE-prefix-proof.json').open('x')as f:json.dump(meta,f,indent=2);f.write('\n')
 print(json.dumps(dict(all_passed=True,boundary_PC='0x3B9B66',actual_Source_TCB='0x183140A0',CPU_store_preimages_reconstructed=p['CPU_store_preimages_reconstructed'],closed_prefix_not_rerun=True,new_whole_prefix_saved=False)),flush=True)
if __name__=='__main__':main()
