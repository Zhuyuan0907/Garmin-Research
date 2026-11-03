#!/usr/bin/env python3
"""Inspect all four actual READY publications in the compact CPU journal.
No VM: replay only exact typed slot metadata and four PCM pages.
"""
import gzip,hashlib,json,struct
from pathlib import Path
BASE=Path(__file__).resolve().parent;ROOT=BASE.parents[1]
G=BASE/'guest-v3';OUT=BASE/'file-publications-v1'
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def main():
 assert not OUT.exists();OUT.mkdir()
 small=json.loads((G/'guest-proof.json').read_text())
 assert sha(G/'tail-proof.json.gz')==small['proof_SHA256']
 p=json.load(gzip.open(G/'tail-proof.json.gz','rt'))
 build=json.loads((BASE/'build-v3/manifest.json').read_text())
 slots=build['symbols']['memory_output_slots']['address'];metadata=bytearray(96)
 pcm=bytearray(16384);reference=(ROOT/'staging/native-os20-resident-music-v2/reference-two-streams.pcm').read_bytes()
 publications=[]
 for row in p['protocol_CPU_stores']:
  address,size=row['address'],row['size'];payload=row['value'].to_bytes(size,'little')
  if 0x09140000<=address and address+size<=0x09144000:
   off=address-0x09140000;assert pcm[off:off+size].hex()==row['before_hex'];pcm[off:off+size]=payload
  if slots<=address and address+size<=slots+96:
   off=address-slots;assert metadata[off:off+size].hex()==row['before_hex'];metadata[off:off+size]=payload
   if off%24==4 and size==4 and row['value']==2:
    index=off//24;ticket,state,count,instance,reads,inflight=struct.unpack_from('<6I',metadata,index*24)
    order=len(publications);assert order<4 and row['actor']==p['worker_TCB']
    assert (ticket,state,count,instance,reads,inflight)==((order+1)*4,2,256,0xffffffff,0,0)
    published=bytes(pcm[index*4096:index*4096+count]);assert published==reference[order*256:(order+1)*256]
    publications.append(dict(ticket=ticket,slot=index,bytes=count,PC=row['PC'],ordinal=row['ordinal'],
     actor=row['actor'],PCM_SHA256=hashlib.sha256(published).hexdigest(),READY_CPU_store_from_COPYING=row['before_hex']=='01000000'))
 assert [r['ticket']for r in publications]==[4,8,12,16]
 assert all(r['READY_CPU_store_from_COPYING']for r in publications)
 assert bytes(pcm[:256])==reference[768:1024]
 assert bytes(pcm[256:])==bytes(16384-256)
 result=dict(all_passed=True,source_sha256={str(Path(__file__).relative_to(ROOT)):sha(Path(__file__))},
  guest_proof_SHA256=sha(G/'tail-proof.json.gz'),actual_READY_publications=publications,
  published_PCM_bytes_matching_closed_libsbc_reference=1024,pending_PCM_bytes_after_STOP=128,
  byte_comparison_boundary='four private typed FIFO READY publications; 896 bytes additionally read by controller',
  kernel_or_native_ownership_reinterpreted=False,VM_import_or_execution=False,device_IO=False)
 (OUT/'FILE-publications-proof.json').write_text(json.dumps(result,indent=2)+'\n')
 print(json.dumps(dict(all_passed=True,published_reference_PCM_bytes=1024,READY_tickets=[4,8,12,16],
  pending_bytes_after_STOP=128,VM_import_or_execution=False)),flush=True)
if __name__=='__main__':main()
